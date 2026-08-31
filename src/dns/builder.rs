//! DNS resolver builder and registry.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{
    DnsConfig, ExpandedDnsGroup, ExpandedDnsPolicyAction, ExpandedDnsPolicyRule, ExpandedDnsSpec,
};
use crate::dns::composite_resolver::CompositeResolver;
use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::dns::parsed::{ParsedDnsServer, ParsedDnsServerEntry, ParsedDnsUrl};
use crate::dns::policy::{PolicyAction, PolicyResolver, PolicyRuleSpec, PolicyStateRegistry};
use crate::dns::query_cache::{DnsQueryCache, SharedNativeResolver};
use crate::option_util::NoneOrSome;
use crate::resolver::{
    LateBoundResolver, NativeResolver, RefreshPolicy, RefreshingResolver, Resolver,
    ResolverFactory, TimeoutResolver,
};
use crate::tcp::chain_builder::{
    build_client_chain_group_with_selection, build_direct_chain_group,
};

const SYSTEM_DNS_CONFIG_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Registry of resolved DNS groups with lazy default resolver.
pub struct DnsRegistry {
    groups: FxHashMap<String, Arc<dyn Resolver>>,
    /// Default resolver, created lazily only if needed.
    default_resolver: Option<Arc<dyn Resolver>>,
    query_cache: Arc<DnsQueryCache>,
}

impl DnsRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self::with_query_cache(Arc::new(DnsQueryCache::default()))
    }

    fn with_query_cache(query_cache: Arc<DnsQueryCache>) -> Self {
        Self {
            groups: FxHashMap::default(),
            default_resolver: None,
            query_cache,
        }
    }

    /// Create an empty registry bound to the current DNS-client generation.
    /// Engine integrations use this after a full Box rotation so default
    /// resolution cannot keep the retiring generation's cache Arc alive.
    pub fn with_policy_state(policy_state: &PolicyStateRegistry) -> Self {
        Self::with_query_cache(policy_state.query_cache())
    }

    fn query_cache(&self) -> Arc<DnsQueryCache> {
        self.query_cache.clone()
    }

    /// Register a DNS group.
    pub fn register(&mut self, name: String, resolver: Arc<dyn Resolver>) {
        self.groups.insert(name, resolver);
    }

    /// Get a resolver by group name, returns None if not found.
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.groups.get(name).cloned()
    }

    /// Get or create the implicit native resolver used when a server has no
    /// `dns` field configured. Unlike an explicit `system` DNS entry, this
    /// synchronous fallback cannot expose wire TTLs and therefore only reads
    /// already-warm shared question-cache entries.
    pub fn get_or_create_default(&mut self) -> Arc<dyn Resolver> {
        if self.default_resolver.is_none() {
            self.default_resolver = Some(Arc::new(SharedNativeResolver::new(
                self.query_cache.clone(),
                crate::dns::IpStrategy::Ipv4AndIpv6,
                "system",
            )));
        }
        self.default_resolver.clone().unwrap()
    }

    /// Get resolver for a server config's dns field.
    /// After validation, dns.servers should be a single group name or None.
    pub fn get_for_server(&mut self, dns: Option<&DnsConfig>) -> Arc<dyn Resolver> {
        match dns.and_then(|c| c.resolved_group()) {
            Some(group_name) => self
                .groups
                .get(group_name)
                .cloned()
                .expect("dns group should exist (validated)"),
            None => self.get_or_create_default(),
        }
    }
}

impl Default for DnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a resolver with optional timeout and return as Arc<dyn Resolver>.
/// Wraps in TimeoutResolver before Arc to avoid double indirection.
fn wrap_resolver<T: Resolver + 'static>(resolver: T, timeout_secs: u32) -> Arc<dyn Resolver> {
    if timeout_secs > 0 {
        Arc::new(TimeoutResolver::with_timeout(
            resolver,
            Duration::from_secs(timeout_secs as u64),
        ))
    } else {
        Arc::new(resolver)
    }
}

/// Cloneable build plan that can reconstruct a fresh hickory resolver.
/// Used as the factory for RefreshingResolver so that refresh discards
/// the old hickory connection pool entirely.
#[derive(Clone)]
struct HickoryResolverPlan {
    parsed_url: ParsedDnsUrl,
    chain_group: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap_resolver: Arc<dyn Resolver>,
    chain_key: String,
    bootstrap_key: Option<String>,
    options: HickoryResolverOptions,
    description: String,
    system_state: Option<Arc<SystemResolverState>>,
}

type SystemConfigurationLoader = Arc<
    dyn Fn() -> std::io::Result<crate::dns::system_config::SystemConfigurationSnapshot>
        + Send
        + Sync,
>;

struct SystemResolverState {
    memo: Mutex<SystemResolverMemo>,
    check_lock: AsyncMutex<()>,
    loader: SystemConfigurationLoader,
    refresh_interval: Duration,
}

#[derive(Default)]
struct SystemResolverMemo {
    checked_at: Option<Instant>,
    fingerprint: Option<String>,
    resolver: Option<Arc<dyn Resolver>>,
    last_error: Option<CachedSystemResolverError>,
    systemd_resolved: bool,
}

#[derive(Clone, Debug)]
struct CachedSystemResolverError {
    kind: std::io::ErrorKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemResolverFailureDisposition {
    FailClosed,
    RetainedLastGood,
}

#[derive(Debug)]
struct FailClosedSystemResolver {
    error: CachedSystemResolverError,
}

impl Resolver for FailClosedSystemResolver {
    fn resolve_location(
        &self,
        _location: &crate::address::NetLocation,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send>,
    > {
        let error = self.error.clone();
        Box::pin(async move {
            Err(std::io::Error::new(
                error.kind,
                format!(
                    "advanced systemd-resolved DNS is fail-closed after refresh failure: {}",
                    error.message
                ),
            ))
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        None
    }
}

impl SystemResolverState {
    fn new() -> Self {
        Self {
            memo: Mutex::new(SystemResolverMemo::default()),
            check_lock: AsyncMutex::new(()),
            loader: Arc::new(crate::dns::system_config::read_system_configuration_snapshot),
            refresh_interval: SYSTEM_DNS_CONFIG_REFRESH_INTERVAL,
        }
    }

    fn recent_result(&self) -> Option<std::io::Result<Arc<dyn Resolver>>> {
        let memo = self.memo.lock();
        if memo
            .checked_at
            .is_none_or(|checked_at| checked_at.elapsed() >= self.refresh_interval)
        {
            return None;
        }
        if let Some(resolver) = &memo.resolver {
            return Some(Ok(resolver.clone()));
        }
        memo.last_error.as_ref().map(|error| {
            Err(std::io::Error::new(
                error.kind,
                format!(
                    "recent advanced system DNS configuration check failed: {}",
                    error.message
                ),
            ))
        })
    }

    fn remember_failure(
        &self,
        error: &std::io::Error,
        recognized_systemd_resolved: bool,
    ) -> (Option<Arc<dyn Resolver>>, SystemResolverFailureDisposition) {
        let mut memo = self.memo.lock();
        let cached_error = CachedSystemResolverError {
            kind: error.kind(),
            message: error.to_string(),
        };
        memo.checked_at = Some(Instant::now());
        memo.last_error = Some(cached_error.clone());
        if memo.systemd_resolved || recognized_systemd_resolved {
            // Do not keep an opportunistic resolver alive when the platform may
            // have switched to strict DNSOverTLS=yes. Publishing a resolver
            // which always errors makes RefreshingResolver replace its active
            // transport while retaining the five-second recovery cadence. On
            // the first build there is no active resolver to replace, so keep
            // the memo empty and return the discovery/build error explicitly.
            let had_active_resolver = memo.resolver.is_some();
            memo.fingerprint = None;
            memo.systemd_resolved = true;
            if !had_active_resolver {
                memo.resolver = None;
                return (None, SystemResolverFailureDisposition::FailClosed);
            }
            let resolver: Arc<dyn Resolver> = Arc::new(FailClosedSystemResolver {
                error: cached_error,
            });
            memo.resolver = Some(resolver.clone());
            (Some(resolver), SystemResolverFailureDisposition::FailClosed)
        } else {
            (
                memo.resolver.clone(),
                SystemResolverFailureDisposition::RetainedLastGood,
            )
        }
    }
}

impl HickoryResolverPlan {
    fn is_system_profile(&self) -> bool {
        matches!(self.parsed_url, ParsedDnsUrl::System)
    }

    fn is_pool_compatible_with(&self, other: &Self) -> bool {
        !self.is_system_profile()
            && !other.is_system_profile()
            && self.chain_key == other.chain_key
            && self.bootstrap_key == other.bootstrap_key
            && self.options.is_pool_compatible_with(&other.options)
    }

    async fn resolved_name_server_pairs(
        &self,
    ) -> std::io::Result<Vec<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)>> {
        let resolved_ips = match self.parsed_url.hostname() {
            Some(hostname) => {
                let location = crate::address::NetLocation::new(
                    crate::address::Address::Hostname(hostname.to_string()),
                    0,
                );
                let addrs = self
                    .bootstrap_resolver
                    .resolve_location(&location)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to resolve DNS server hostname '{}': {}",
                            hostname, e
                        ))
                    })?;
                if addrs.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "bootstrap lookup returned no addresses for '{}'",
                        hostname
                    )));
                }

                let mut ips = Vec::with_capacity(addrs.len());
                for ip in addrs.into_iter().map(|addr| addr.ip()) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }

                log::debug!(
                    "HickoryResolverPlan ({}): resolved {} to {:?}",
                    self.description,
                    hostname,
                    ips
                );
                ips
            }
            None => vec![],
        };

        if resolved_ips.is_empty() {
            let server = self
                .parsed_url
                .to_parsed_server(None)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return server_to_ns_config(&server)
                .map(|pair| vec![pair])
                .ok_or_else(|| {
                    std::io::Error::other(format!(
                        "resolver plan '{}' did not produce a nameserver config",
                        self.description
                    ))
                });
        }

        let mut ns_pairs = Vec::with_capacity(resolved_ips.len());
        for ip in resolved_ips {
            let server = self
                .parsed_url
                .to_parsed_server(Some(ip))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let pair = server_to_ns_config(&server).ok_or_else(|| {
                std::io::Error::other(format!(
                    "resolver plan '{}' did not produce a nameserver config",
                    self.description
                ))
            })?;
            ns_pairs.push(pair);
        }

        Ok(ns_pairs)
    }

    /// Build a fresh resolver, re-resolving hostname upstreams if needed.
    /// When a hostname resolves to multiple IPs, all are expanded into
    /// nameserver configs inside a single pooled hickory resolver.
    async fn build(&self) -> std::io::Result<Arc<dyn Resolver>> {
        if self.is_system_profile() {
            let state = self
                .system_state
                .as_ref()
                .expect("system resolver plans always have refresh state");
            if let Some(recent) = state.recent_result() {
                return recent;
            }

            // Coalesce concurrent expiry/error checks. Platform discovery can
            // invoke resolvectl on Linux, so keep all of it off Tokio workers.
            let _check_guard = state.check_lock.lock().await;
            if let Some(recent) = state.recent_result() {
                return recent;
            }
            let loader = state.loader.clone();
            let snapshot = match tokio::task::spawn_blocking(move || loader()).await {
                Ok(result) => result,
                Err(error) => Err(std::io::Error::other(format!(
                    "advanced system DNS configuration task failed: {error}"
                ))),
            };
            let snapshot = match snapshot {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let recognized_systemd_resolved =
                        crate::dns::system_config::error_recognized_systemd_resolved(&error);
                    let (replacement, disposition) =
                        state.remember_failure(&error, recognized_systemd_resolved);
                    if let Some(replacement) = replacement {
                        match disposition {
                            SystemResolverFailureDisposition::FailClosed => log::error!(
                                "HickoryResolverPlan ({}): systemd-resolved configuration check failed after a confirmed resolved generation; disabling the previous direct resolver until discovery recovers: {}",
                                self.description,
                                error
                            ),
                            SystemResolverFailureDisposition::RetainedLastGood => log::warn!(
                                "HickoryResolverPlan ({}): ordinary system DNS configuration check failed; retaining last-good resolver: {}",
                                self.description,
                                error
                            ),
                        }
                        return Ok(replacement);
                    }
                    if recognized_systemd_resolved {
                        log::error!(
                            "HickoryResolverPlan ({}): initial systemd-resolved discovery failed; refusing to publish a native fallback: {}",
                            self.description,
                            error
                        );
                    }
                    return Err(error);
                }
            };

            let snapshot_is_systemd_resolved = matches!(
                &snapshot.configuration,
                crate::dns::system_config::SystemConfiguration::SystemdResolved(_)
            );

            {
                let mut memo = state.memo.lock();
                if memo.fingerprint.as_deref() == Some(snapshot.fingerprint.as_str())
                    && let Some(resolver) = memo.resolver.clone()
                {
                    memo.checked_at = Some(Instant::now());
                    memo.last_error = None;
                    return Ok(resolver);
                }
            }

            let resolver: Arc<dyn Resolver> =
                match crate::dns::system_resolver::build_system_resolver(
                    snapshot.configuration,
                    snapshot.options,
                    self.chain_group.clone(),
                    self.bootstrap_resolver.clone(),
                    self.options.clone(),
                ) {
                    Ok(resolver) => resolver,
                    Err(error) => {
                        let (replacement, disposition) =
                            state.remember_failure(&error, snapshot_is_systemd_resolved);
                        if let Some(replacement) = replacement {
                            match disposition {
                                SystemResolverFailureDisposition::FailClosed => log::error!(
                                    "HickoryResolverPlan ({}): systemd-resolved transport build failed; disabling the previous direct resolver until discovery recovers: {}",
                                    self.description,
                                    error
                                ),
                                SystemResolverFailureDisposition::RetainedLastGood => log::warn!(
                                    "HickoryResolverPlan ({}): ordinary system DNS configuration could not build; retaining last-good resolver: {}",
                                    self.description,
                                    error
                                ),
                            }
                            return Ok(replacement);
                        }
                        if snapshot_is_systemd_resolved {
                            log::error!(
                                "HickoryResolverPlan ({}): initial systemd-resolved transport build failed; refusing to publish a native fallback: {}",
                                self.description,
                                error
                            );
                        }
                        return Err(error);
                    }
                };
            *state.memo.lock() = SystemResolverMemo {
                checked_at: Some(Instant::now()),
                fingerprint: Some(snapshot.fingerprint),
                resolver: Some(resolver.clone()),
                last_error: None,
                systemd_resolved: snapshot_is_systemd_resolved,
            };
            return Ok(resolver);
        }

        let ns_pairs = self.resolved_name_server_pairs().await?;

        if ns_pairs.len() > 1 {
            let resolver = HickoryResolver::build_pooled(
                ns_pairs,
                self.chain_group.clone(),
                self.bootstrap_resolver.clone(),
                self.options.clone(),
                self.description.clone(),
            )?;
            return Ok(Arc::new(resolver));
        }

        // Single IP or IP-literal upstream: build normally.
        let resolved_ip = ns_pairs.first().map(|(ip, _)| *ip);
        let server = self
            .parsed_url
            .to_parsed_server(resolved_ip)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        build_hickory_from_server(
            server,
            self.chain_group.clone(),
            self.bootstrap_resolver.clone(),
            self.options.clone(),
        )
    }
}

async fn try_build_hickory_pool_from_plans(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if plans.len() < 2 || plans.iter().any(HickoryResolverPlan::is_system_profile) {
        return Ok(None);
    }

    let first = &plans[0];
    if plans
        .iter()
        .skip(1)
        .any(|plan| !plan.is_pool_compatible_with(first))
    {
        return Ok(None);
    }

    let mut ns_pairs = Vec::new();
    for plan in plans {
        ns_pairs.extend(plan.resolved_name_server_pairs().await?);
    }

    if ns_pairs.len() < 2 {
        return Ok(None);
    }

    let descriptions: Vec<String> = plans.iter().map(|plan| plan.description.clone()).collect();
    let description = format!("pool[{}]", descriptions.join(", "));
    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.chain_group.clone(),
        first.bootstrap_resolver.clone(),
        first.options.clone(),
        description,
    )?;
    Ok(Some(Arc::new(resolver)))
}

/// Ordered refresh plan for groups that mix rebuildable Hickory transports
/// with a native system fallback on targets without raw platform DNS discovery.
#[derive(Clone)]
enum ResolverRefreshPlan {
    Hickory(Box<HickoryResolverPlan>),
    NativeSystem {
        timeout_secs: u32,
        ip_strategy: crate::dns::IpStrategy,
        query_cache: Arc<DnsQueryCache>,
        transport_tag: Arc<str>,
    },
}

fn build_shared_native_resolver(
    timeout_secs: u32,
    ip_strategy: crate::dns::IpStrategy,
    query_cache: Arc<DnsQueryCache>,
    transport_tag: Arc<str>,
) -> Arc<dyn Resolver> {
    wrap_resolver(
        SharedNativeResolver::new(query_cache, ip_strategy, transport_tag),
        timeout_secs,
    )
}

async fn build_refresh_plan_group(
    plans: &[ResolverRefreshPlan],
) -> std::io::Result<Arc<dyn Resolver>> {
    if plans
        .iter()
        .all(|plan| matches!(plan, ResolverRefreshPlan::Hickory(_)))
    {
        let hickory_plans = plans
            .iter()
            .map(|plan| match plan {
                ResolverRefreshPlan::Hickory(plan) => plan.as_ref().clone(),
                ResolverRefreshPlan::NativeSystem { .. } => unreachable!(),
            })
            .collect::<Vec<_>>();
        return build_hickory_resolver_group(&hickory_plans).await;
    }

    let mut resolvers = Vec::with_capacity(plans.len());
    for plan in plans {
        let resolver = match plan {
            ResolverRefreshPlan::Hickory(plan) => plan.build().await?,
            ResolverRefreshPlan::NativeSystem {
                timeout_secs,
                ip_strategy,
                query_cache,
                transport_tag,
            } => build_shared_native_resolver(
                *timeout_secs,
                *ip_strategy,
                query_cache.clone(),
                transport_tag.clone(),
            ),
        };
        resolvers.push(resolver);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Build mixed groups containing a wire-aware system profile as independently
/// refreshing entries. A group-wide five-second refresh would recreate every
/// unrelated Hickory resolver and discard its cache even when the OS DNS
/// fingerprint is unchanged.
async fn build_system_aware_refresh_group(
    plans: &[ResolverRefreshPlan],
) -> std::io::Result<Arc<dyn Resolver>> {
    let mut resolvers = Vec::with_capacity(plans.len());
    for plan in plans {
        let resolver: Arc<dyn Resolver> = match plan {
            ResolverRefreshPlan::Hickory(plan) => {
                let is_system_profile = plan.is_system_profile();
                let description = plan.description.clone();
                let plan = plan.clone();
                let factory: ResolverFactory = Arc::new(move || {
                    let plan = plan.clone();
                    Box::pin(async move { plan.build().await })
                });
                let policy = RefreshPolicy {
                    max_idle: Duration::from_secs(60),
                    max_age: is_system_profile.then_some(SYSTEM_DNS_CONFIG_REFRESH_INTERVAL),
                    retry_once_after_refresh: true,
                };
                Arc::new(RefreshingResolver::new(factory, policy, description).await?)
            }
            ResolverRefreshPlan::NativeSystem {
                timeout_secs,
                ip_strategy,
                query_cache,
                transport_tag,
            } => build_shared_native_resolver(
                *timeout_secs,
                *ip_strategy,
                query_cache.clone(),
                transport_tag.clone(),
            ),
        };
        resolvers.push(resolver);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

async fn build_hickory_resolver_group(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Arc<dyn Resolver>> {
    if plans.is_empty() {
        return Err(std::io::Error::other(
            "no hickory resolver plans configured",
        ));
    }

    if let Some(pooled) = try_build_hickory_pool_from_plans(plans).await? {
        return Ok(pooled);
    }

    let mut resolvers = Vec::with_capacity(plans.len());
    for plan in plans {
        resolvers.push(plan.build().await?);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Construct a single HickoryResolver from a ParsedDnsServer.
fn build_hickory_from_server(
    server: ParsedDnsServer,
    chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    options: HickoryResolverOptions,
) -> std::io::Result<Arc<dyn Resolver>> {
    Ok(match server {
        ParsedDnsServer::System => {
            unreachable!("system resolver should not use hickory build path")
        }
        ParsedDnsServer::Udp { addr } => {
            Arc::new(HickoryResolver::udp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tcp { addr } => {
            Arc::new(HickoryResolver::tcp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tls { addr, server_name } => Arc::new(HickoryResolver::tls(
            addr,
            server_name,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::Quic { addr, server_name } => Arc::new(HickoryResolver::quic(
            addr,
            server_name,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::https(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::h3(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
    })
}

/// Convert a ParsedDnsServer to (IpAddr, ConnectionConfig) for pooling.
/// Returns None for System resolvers (cannot be pooled).
fn server_to_ns_config(
    server: &ParsedDnsServer,
) -> Option<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)> {
    use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};

    match server {
        ParsedDnsServer::System => None,
        ParsedDnsServer::Udp { addr } => {
            let mut cc = ConnectionConfig::udp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tcp { addr } => {
            let mut cc = ConnectionConfig::tcp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tls { addr, server_name } => {
            let mut cc = ConnectionConfig::tls(server_name.clone());
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Quic { addr, server_name } => {
            let mut cc = ConnectionConfig::quic(server_name.clone());
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => {
            let mut cc = ConnectionConfig::https(server_name.clone(), Some(path.clone()));
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => {
            let protocol = ProtocolConfig::H3 {
                server_name: server_name.clone(),
                path: path.clone(),
                disable_grease: true,
            };
            let mut cc = ConnectionConfig::new(protocol);
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
    }
}

/// Build a resolver from parsed DNS server entries.
/// When all entries are hickory-backed with compatible settings, pools them
/// into a single hickory resolver instead of using CompositeResolver.
pub fn build_resolver(entries: Vec<ParsedDnsServerEntry>) -> std::io::Result<Arc<dyn Resolver>> {
    build_resolver_with_system_configuration(
        entries,
        crate::dns::system_config::read_system_configuration_snapshot,
    )
}

fn build_resolver_with_system_configuration(
    entries: Vec<ParsedDnsServerEntry>,
    load_system_configuration: impl Fn() -> std::io::Result<
        crate::dns::system_config::SystemConfigurationSnapshot,
    >,
) -> std::io::Result<Arc<dyn Resolver>> {
    if entries.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    // Try to pool all hickory-backed entries into one resolver.
    if let Some(pooled) = try_build_hickory_pool(&entries)? {
        return Ok(pooled);
    }

    // Fallback: build individual resolvers and composite them.
    let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let timeout_secs = entry.timeout_secs;

        let mut options = HickoryResolverOptions {
            ip_strategy: entry.ip_strategy,
            use_native_roots: entry.use_native_roots,
            request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
            connect_timeout: Duration::from_secs(entry.connect_timeout_secs as u64),
            attempts: entry.attempts,
            disable_cache: entry.disable_cache,
            rewrite_ttl: entry.rewrite_ttl,
            client_subnet: entry.client_subnet,
            shared_cache: entry.shared_cache.clone(),
            transport_tag: entry.transport_tag.clone(),
            trust_ad: false,
        };
        if matches!(&entry.server, ParsedDnsServer::System)
            && crate::dns::system_config::wire_system_resolver_supported()
            && options.shared_cache.is_none()
        {
            // Public callers which bypass DnsRegistry still get a real
            // question cache for wire-aware system answers.
            options.shared_cache = Some(Arc::new(DnsQueryCache::default()));
        }

        let resolver: Arc<dyn Resolver> = match entry.server {
            ParsedDnsServer::System
                if crate::dns::system_config::wire_system_resolver_supported() =>
            {
                let snapshot = load_system_configuration()?;
                crate::dns::system_resolver::build_system_resolver(
                    snapshot.configuration,
                    snapshot.options,
                    entry.client_chain,
                    entry.bootstrap_resolver,
                    options,
                )?
            }
            ParsedDnsServer::System => build_shared_native_resolver(
                timeout_secs,
                entry.ip_strategy,
                entry
                    .shared_cache
                    .clone()
                    .unwrap_or_else(|| Arc::new(DnsQueryCache::default())),
                entry.transport_tag.clone(),
            ),
            server => build_hickory_from_server(
                server,
                entry.client_chain,
                entry.bootstrap_resolver,
                options,
            )?,
        };

        resolvers.push(resolver);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Attempt to build a single pooled hickory resolver from all entries.
/// Returns None if entries contain system resolvers, or if entries have
/// heterogeneous settings (different chains, bootstraps, timeouts, etc.).
/// Pooling is only safe when all entries share the same runtime config,
/// since a single hickory resolver applies one set of options to all its
/// nameservers.
fn try_build_hickory_pool(
    entries: &[ParsedDnsServerEntry],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if entries.is_empty() || entries.len() < 2 {
        return Ok(None);
    }

    let first = &entries[0];

    // All entries must be hickory-backed (no system resolvers) and share
    // the same chain group, bootstrap, and tuning options.
    let mut ns_pairs = Vec::with_capacity(entries.len());
    for entry in entries {
        match server_to_ns_config(&entry.server) {
            Some(pair) => ns_pairs.push(pair),
            None => return Ok(None),
        }

        if !Arc::ptr_eq(&entry.client_chain, &first.client_chain) {
            return Ok(None);
        }
        if !Arc::ptr_eq(&entry.bootstrap_resolver, &first.bootstrap_resolver) {
            return Ok(None);
        }
        if entry.timeout_secs != first.timeout_secs
            || entry.connect_timeout_secs != first.connect_timeout_secs
            || entry.attempts != first.attempts
            || entry.ip_strategy != first.ip_strategy
            || entry.use_native_roots != first.use_native_roots
            || entry.disable_cache != first.disable_cache
            || entry.rewrite_ttl != first.rewrite_ttl
            || entry.client_subnet != first.client_subnet
            || entry.transport_tag != first.transport_tag
            || match (&entry.shared_cache, &first.shared_cache) {
                (Some(left), Some(right)) => !Arc::ptr_eq(left, right),
                (None, None) => false,
                _ => true,
            }
        {
            return Ok(None);
        }
    }

    let timeout_secs = first.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: first.ip_strategy,
        use_native_roots: first.use_native_roots,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(first.connect_timeout_secs as u64),
        attempts: first.attempts,
        disable_cache: first.disable_cache,
        rewrite_ttl: first.rewrite_ttl,
        client_subnet: first.client_subnet,
        shared_cache: first.shared_cache.clone(),
        transport_tag: first.transport_tag.clone(),
        trust_ad: false,
    };

    let descriptions: Vec<String> = entries.iter().map(|e| format!("{:?}", e.server)).collect();
    let description = format!("pool[{}]", descriptions.join(", "));

    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.client_chain.clone(),
        first.bootstrap_resolver.clone(),
        options,
        description,
    )?;

    Ok(Some(Arc::new(resolver)))
}

/// Build DnsRegistry from expanded DNS groups.
///
/// Groups must be in topological order (bootstrap dependencies first).
/// This function:
/// - Builds client chain groups from expanded client chains
/// - Resolves hostnames in DNS URLs using bootstrap resolvers
/// - Creates HickoryResolver instances
pub async fn build_dns_registry(groups: Vec<ExpandedDnsGroup>) -> std::io::Result<DnsRegistry> {
    let policy_state = PolicyStateRegistry::default();
    build_dns_registry_with_policy_state(groups, &policy_state).await
}

/// Build a DNS registry while adopting compiler-identified mutable rule state
/// from a longer-lived owner. Callers which do not need state to survive a
/// resolver graph rebuild should continue using [`build_dns_registry`].
pub async fn build_dns_registry_with_policy_state(
    groups: Vec<ExpandedDnsGroup>,
    policy_state: &PolicyStateRegistry,
) -> std::io::Result<DnsRegistry> {
    let mut registry = DnsRegistry::with_policy_state(policy_state);

    for group in groups {
        let resolver = if group.final_server.is_some()
            || !group.rules.is_empty()
            || group.specs.iter().any(|spec| spec.tag.is_some())
        {
            build_policy_resolver(&group, &registry, policy_state).await?
        } else {
            build_resolver_from_specs(&group.specs, &registry, &group.name).await?
        };
        registry.register(group.name, resolver);
    }

    Ok(registry)
}

async fn build_policy_resolver(
    group: &ExpandedDnsGroup,
    registry: &DnsRegistry,
    policy_state: &PolicyStateRegistry,
) -> std::io::Result<Arc<dyn Resolver>> {
    // A DNS upstream can use a proxy detour whose own server lookup names one
    // of this policy's upstream tags. The policy does not exist until all of
    // its upstream transports have been built, so give those chains a weak
    // late-bound handle and connect it after constructing the policy.
    let chain_resolver = Arc::new(LateBoundResolver::new());
    let mut upstreams: FxHashMap<String, Arc<dyn Resolver>> = FxHashMap::default();
    for spec in &group.specs {
        let tag = spec.tag.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "DNS policy group '{}' contains an untagged upstream",
                    group.name
                ),
            )
        })?;
        let description = format!("{}/{}", group.name, tag);
        let resolver = build_resolver_from_specs_with_chain_resolver(
            std::slice::from_ref(spec),
            registry,
            &description,
            Some(chain_resolver.clone()),
        )
        .await?;
        if upstreams.insert(tag.to_string(), resolver).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "DNS policy group '{}' has duplicate upstream tag {tag:?}",
                    group.name
                ),
            ));
        }
    }

    let final_tag = group.final_server.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("DNS policy group '{}' has no final upstream", group.name),
        )
    })?;
    let final_resolver = upstreams.get(final_tag).cloned().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "DNS policy group '{}' final references unknown upstream tag {final_tag:?}",
                group.name
            ),
        )
    })?;

    let rules = group
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| policy_rule_spec(group, &upstreams, index, rule))
        .collect::<std::io::Result<Vec<_>>>()?;
    let rule_state_keys = group
        .rules
        .iter()
        .map(|rule| rule.reject_flood_state_key.clone())
        .collect();
    let policy: Arc<dyn Resolver> =
        Arc::new(PolicyResolver::with_named_upstreams_and_state_registry(
            final_resolver,
            rules,
            upstreams,
            rule_state_keys,
            policy_state,
        )?);
    chain_resolver.bind(&policy)?;
    Ok(policy)
}

fn policy_rule_spec(
    group: &ExpandedDnsGroup,
    upstreams: &FxHashMap<String, Arc<dyn Resolver>>,
    index: usize,
    rule: &ExpandedDnsPolicyRule,
) -> std::io::Result<PolicyRuleSpec> {
    let action = match &rule.action {
        ExpandedDnsPolicyAction::Route(tag) => {
            let resolver = upstreams.get(tag).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "DNS policy group '{}' rules[{index}] references unknown upstream tag {tag:?}",
                        group.name
                    ),
                )
            })?;
            PolicyAction::Route(resolver)
        }
        ExpandedDnsPolicyAction::Reject(method) => PolicyAction::Reject(*method),
        ExpandedDnsPolicyAction::Predefined(response) => PolicyAction::Predefined(response.clone()),
    };
    Ok(PolicyRuleSpec {
        exact: rule.exact.clone(),
        suffix: rule.suffix.clone(),
        keyword: rule.keyword.clone(),
        regex: rule.regex.clone(),
        rule_set: rule.rule_set.clone(),
        no_drop: rule.no_drop,
        timeout: (rule.timeout_millis != 0)
            .then(|| std::time::Duration::from_millis(rule.timeout_millis)),
        action,
    })
}

/// Build a resolver from expanded DNS specs, wrapping hickory-backed groups
/// in RefreshingResolver for stale connection mitigation.
async fn build_resolver_from_specs(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
    group_name: &str,
) -> std::io::Result<Arc<dyn Resolver>> {
    build_resolver_from_specs_with_chain_resolver(specs, registry, group_name, None).await
}

async fn build_resolver_from_specs_with_chain_resolver(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
    group_name: &str,
    chain_resolver: Option<Arc<dyn Resolver>>,
) -> std::io::Result<Arc<dyn Resolver>> {
    if specs.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut entries: Vec<ParsedDnsServerEntry> = Vec::with_capacity(specs.len());
    let mut refresh_plans: Vec<ResolverRefreshPlan> = Vec::with_capacity(specs.len());
    let mut has_rebuildable = false;
    let mut has_system_profile = false;

    for spec in specs {
        let (entry, plan) = build_entry_and_plan(spec, registry, chain_resolver.as_ref()).await?;
        match plan {
            Some(plan) => {
                has_rebuildable = true;
                has_system_profile |= plan.is_system_profile();
                refresh_plans.push(ResolverRefreshPlan::Hickory(Box::new(plan)));
            }
            None if matches!(entry.server, ParsedDnsServer::System) => {
                refresh_plans.push(ResolverRefreshPlan::NativeSystem {
                    timeout_secs: entry.timeout_secs,
                    ip_strategy: entry.ip_strategy,
                    query_cache: entry
                        .shared_cache
                        .clone()
                        .unwrap_or_else(|| registry.query_cache()),
                    transport_tag: entry.transport_tag.clone(),
                });
            }
            None => {
                return Err(std::io::Error::other(
                    "non-system DNS entry did not produce a rebuild plan",
                ));
            }
        }
        entries.push(entry);
    }

    // Any wire-aware entry gets a rebuildable resolver. On supported targets,
    // every explicit `system` entry follows this path so DHCP/VPN nameserver
    // changes are observed and cold answers retain their wire TTL in the
    // shared question cache.
    if has_system_profile {
        build_system_aware_refresh_group(&refresh_plans).await
    } else if has_rebuildable {
        let description = group_name.to_string();
        let refresh_plans = refresh_plans.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let refresh_plans = refresh_plans.clone();
            Box::pin(async move { build_refresh_plan_group(&refresh_plans).await })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: None,
            retry_once_after_refresh: true,
        };

        let refreshing = RefreshingResolver::new(factory, policy, description).await?;
        Ok(Arc::new(refreshing))
    } else {
        build_resolver(entries)
    }
}

/// Build a ParsedDnsServerEntry and optionally a HickoryResolverPlan from an expanded spec.
/// The plan is returned for non-system resolvers and every supported
/// wire-aware system profile so it can be rebuilt on platform DNS changes.
async fn build_entry_and_plan(
    spec: &ExpandedDnsSpec,
    registry: &DnsRegistry,
    chain_resolver: Option<&Arc<dyn Resolver>>,
) -> std::io::Result<(ParsedDnsServerEntry, Option<HickoryResolverPlan>)> {
    // Parse URL
    let parsed_url = ParsedDnsUrl::parse_with_server_name(&spec.url, spec.server_name.as_deref())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Build client chain group
    let chain_resolver: Arc<dyn Resolver> = chain_resolver
        .cloned()
        .unwrap_or_else(|| Arc::new(NativeResolver::new()));
    let chain_group = if spec.client_chains.is_empty()
        && matches!(
            &spec.client_chain_selection,
            crate::config::ClientChainSelectionConfig::RoundRobin
        ) {
        Arc::new(build_direct_chain_group(chain_resolver))
    } else {
        let chains = if spec.client_chains.len() == 1 {
            NoneOrSome::One(spec.client_chains[0].clone())
        } else {
            NoneOrSome::Some(spec.client_chains.clone())
        };
        Arc::new(build_client_chain_group_with_selection(
            chains,
            spec.client_chain_selection.clone(),
            chain_resolver,
        ))
    };

    // Build or get bootstrap resolver
    let bootstrap_resolver: Arc<dyn Resolver> = match &spec.bootstrap_url {
        Some(bootstrap_url) => {
            // Try to get from registry first (group reference)
            if let Some(resolver) = registry.get_by_name(bootstrap_url) {
                resolver
            } else {
                // Parse as URL and build a simple resolver
                let bootstrap_parsed = ParsedDnsUrl::parse(bootstrap_url).map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid bootstrap_url '{}': {}",
                        bootstrap_url, e
                    ))
                })?;

                let bootstrap_server = bootstrap_parsed
                    .to_parsed_server(None)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;

                let native = Arc::new(NativeResolver::new());
                let direct_chain = Arc::new(build_direct_chain_group(native.clone()));
                // Bootstrap resolvers use default timeout (10s) and 2 attempts
                let bootstrap_entry = ParsedDnsServerEntry::new(
                    bootstrap_server,
                    direct_chain,
                    native,
                    super::IpStrategy::default(),
                    10, // Default timeout for bootstrap
                    5,  // Default connect timeout for bootstrap
                    2,  // Default attempts for bootstrap
                )
                .with_shared_cache(registry.query_cache(), bootstrap_url.clone());
                build_resolver(vec![bootstrap_entry])?
            }
        }
        None => Arc::new(NativeResolver::new()),
    };

    let timeout_secs = spec.timeout_secs;
    let effective_use_native_roots = spec.use_native_roots && parsed_url.uses_tls();
    let options = HickoryResolverOptions {
        ip_strategy: spec.ip_strategy,
        use_native_roots: effective_use_native_roots,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(spec.connect_timeout_secs as u64),
        attempts: spec.attempts,
        disable_cache: spec.disable_cache,
        rewrite_ttl: spec.rewrite_ttl,
        client_subnet: spec.client_subnet,
        shared_cache: Some(registry.query_cache()),
        transport_tag: Arc::from(
            spec.source_tag
                .as_deref()
                .or(spec.tag.as_deref())
                .unwrap_or(spec.url.as_str()),
        ),
        trust_ad: false,
    };

    let advanced_system_profile = matches!(parsed_url, ParsedDnsUrl::System)
        && (spec.disable_cache || spec.rewrite_ttl.is_some() || spec.client_subnet.is_some());
    let wire_system_profile = matches!(parsed_url, ParsedDnsUrl::System)
        && crate::dns::system_config::wire_system_resolver_supported();
    if advanced_system_profile && !wire_system_profile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "system DNS query controls require wire-aware platform DNS discovery on this target",
        ));
    }

    // Keeping system transports as plans makes platform discovery part of
    // every rebuild instead of freezing the process-start nameserver list.
    let plan = if !matches!(parsed_url, ParsedDnsUrl::System) || wire_system_profile {
        Some(HickoryResolverPlan {
            parsed_url: parsed_url.clone(),
            chain_group: chain_group.clone(),
            bootstrap_resolver: bootstrap_resolver.clone(),
            chain_key: serde_yaml::to_string(&(&spec.client_chains, &spec.client_chain_selection))
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "failed to serialize client_chains selection: {e}"
                    ))
                })?,
            bootstrap_key: spec.bootstrap_url.clone(),
            options,
            description: spec.url.clone(),
            system_state: wire_system_profile.then(|| Arc::new(SystemResolverState::new())),
        })
    } else {
        None
    };

    // Resolve hostname if URL contains one
    let resolved_ip = match parsed_url.hostname() {
        Some(hostname) => {
            let location = crate::address::NetLocation::new(
                crate::address::Address::Hostname(hostname.to_string()),
                0,
            );

            let addrs = bootstrap_resolver
                .resolve_location(&location)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "failed to resolve DNS server hostname '{}': {}",
                        hostname, e
                    ))
                })?;
            let address = addrs.first().ok_or_else(|| {
                std::io::Error::other(format!(
                    "bootstrap lookup returned no addresses for '{}'",
                    hostname
                ))
            })?;
            Some(address.ip())
        }
        None => None,
    };

    // Convert to ParsedDnsServer with resolved IP
    let server = parsed_url
        .to_parsed_server(resolved_ip)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let entry = ParsedDnsServerEntry::new(
        server,
        chain_group,
        bootstrap_resolver,
        spec.ip_strategy,
        spec.timeout_secs,
        spec.connect_timeout_secs,
        spec.attempts,
    )
    .with_native_roots(effective_use_native_roots)
    .with_query_profile(spec.disable_cache, spec.rewrite_ttl, spec.client_subnet)
    .with_shared_cache(
        registry.query_cache(),
        spec.source_tag
            .as_deref()
            .or(spec.tag.as_deref())
            .unwrap_or(spec.url.as_str()),
    );

    Ok((entry, plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::address::{Address, NetLocation};
    use crate::config::{
        DnsServerSpec, ExpandedDnsGroup, ExpandedDnsPolicyAction, ExpandedDnsPolicyRule,
        ExpandedDnsSpec,
    };
    use crate::dns::parsed::{IpStrategy, ParsedDnsServer};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;

    /// Helper to build a shared chain group and bootstrap resolver for tests.
    fn shared_test_deps() -> (
        Arc<crate::client_proxy_chain::ClientChainGroup>,
        Arc<dyn Resolver>,
    ) {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(build_direct_chain_group(resolver.clone()));
        (chain, resolver)
    }

    fn make_entry(
        server: ParsedDnsServer,
        chain: &Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: &Arc<dyn Resolver>,
    ) -> ParsedDnsServerEntry {
        ParsedDnsServerEntry::new(
            server,
            chain.clone(),
            bootstrap.clone(),
            IpStrategy::default(),
            5,
            5,
            1,
        )
    }

    fn make_spec(url: &str) -> ExpandedDnsSpec {
        ExpandedDnsSpec {
            tag: None,
            source_tag: None,
            url: url.to_string(),
            server_name: None,
            use_native_roots: false,
            client_chains: vec![],
            client_chain_selection: crate::config::ClientChainSelectionConfig::RoundRobin,
            bootstrap_url: None,
            ip_strategy: IpStrategy::default(),
            disable_cache: false,
            rewrite_ttl: None,
            client_subnet: None,
            timeout_secs: 5,
            connect_timeout_secs: 5,
            attempts: 1,
        }
    }

    fn test_system_snapshot(
        fingerprint: impl Into<String>,
    ) -> crate::dns::system_config::SystemConfigurationSnapshot {
        crate::dns::system_config::SystemConfigurationSnapshot {
            configuration: crate::dns::system_config::SystemConfiguration::Resolver(
                crate::dns::system_config::OrdinarySystemConfiguration::new(
                    hickory_resolver::config::ResolverConfig::from_parts(
                        None,
                        Vec::new(),
                        vec![hickory_resolver::config::NameServerConfig::udp_and_tcp(
                            "192.0.2.53".parse().unwrap(),
                        )],
                    ),
                ),
            ),
            options: hickory_resolver::config::ResolverOpts::default(),
            fingerprint: fingerprint.into(),
        }
    }

    fn build_resolver_with_test_system_configuration(
        entries: Vec<ParsedDnsServerEntry>,
    ) -> std::io::Result<Arc<dyn Resolver>> {
        build_resolver_with_system_configuration(entries, || {
            Ok(test_system_snapshot("test-system"))
        })
    }

    fn use_test_system_configuration(
        plan: &mut HickoryResolverPlan,
        fingerprint: impl Into<String>,
    ) {
        let fingerprint = fingerprint.into();
        let loader: SystemConfigurationLoader =
            Arc::new(move || Ok(test_system_snapshot(fingerprint.clone())));
        let state = plan
            .system_state
            .as_mut()
            .expect("wire-aware system plan must have refresh state");
        Arc::get_mut(state)
            .expect("newly built test plan must own its refresh state")
            .loader = loader;
    }

    fn test_systemd_snapshot(
        fingerprint: impl Into<String>,
        dns_over_tls: crate::dns::system_config::ResolvedDnsOverTlsMode,
    ) -> crate::dns::system_config::SystemConfigurationSnapshot {
        crate::dns::system_config::SystemConfigurationSnapshot {
            configuration: crate::dns::system_config::SystemConfiguration::SystemdResolved(
                crate::dns::system_config::SystemdResolvedConfiguration {
                    interface: "test-default-link".to_string(),
                    dns_over_tls,
                    servers: vec![crate::dns::system_config::ResolvedNameServer {
                        address: "192.0.2.53".parse().unwrap(),
                        port: None,
                        server_name: Some("dns.example".to_string()),
                    }],
                    base_config: hickory_resolver::config::ResolverConfig::default(),
                },
            ),
            options: hickory_resolver::config::ResolverOpts::default(),
            fingerprint: fingerprint.into(),
        }
    }

    fn test_broken_systemd_snapshot(
        fingerprint: impl Into<String>,
    ) -> crate::dns::system_config::SystemConfigurationSnapshot {
        let mut snapshot = test_systemd_snapshot(
            fingerprint,
            crate::dns::system_config::ResolvedDnsOverTlsMode::No,
        );
        let crate::dns::system_config::SystemConfiguration::SystemdResolved(configuration) =
            &mut snapshot.configuration
        else {
            unreachable!("test helper always creates a systemd-resolved snapshot");
        };
        configuration.servers.clear();
        snapshot
    }

    fn test_system_plan(
        loader: SystemConfigurationLoader,
        refresh_interval: Duration,
    ) -> HickoryResolverPlan {
        let (chain_group, bootstrap_resolver) = shared_test_deps();
        HickoryResolverPlan {
            parsed_url: ParsedDnsUrl::System,
            chain_group,
            bootstrap_resolver,
            chain_key: "direct".to_string(),
            bootstrap_key: None,
            options: HickoryResolverOptions {
                disable_cache: true,
                ..HickoryResolverOptions::default()
            },
            description: "test-system".to_string(),
            system_state: Some(Arc::new(SystemResolverState {
                memo: Mutex::new(SystemResolverMemo::default()),
                check_lock: AsyncMutex::new(()),
                loader,
                refresh_interval,
            })),
        }
    }

    #[test]
    fn advanced_system_profile_uses_ordered_hickory_system_configuration() {
        let (chain, bootstrap) = shared_test_deps();
        let entry = make_entry(ParsedDnsServer::System, &chain, &bootstrap).with_query_profile(
            true,
            Some(60),
            Some("192.0.2.7/24".parse().unwrap()),
        );
        let resolver = build_resolver_with_test_system_configuration(vec![entry]).unwrap();
        let debug = format!("{resolver:?}");
        assert!(debug.contains("OrderedSystemResolver"), "{debug}");
        assert_eq!(resolver.result_cache_ttl(), None);
    }

    #[tokio::test]
    #[cfg(any(unix, target_os = "windows"))]
    async fn every_supported_system_profile_gets_a_wire_refresh_plan() {
        let registry = DnsRegistry::new();
        let ordinary = make_spec("system");
        let (_, ordinary_plan) = build_entry_and_plan(&ordinary, &registry, None)
            .await
            .unwrap();
        let ordinary_plan = ordinary_plan.expect("plain system must be wire-aware on this target");
        assert!(ordinary_plan.is_system_profile());
        assert!(ordinary_plan.options.shared_cache.is_some());

        let mut advanced = make_spec("system");
        advanced.disable_cache = true;
        let (_, advanced_plan) = build_entry_and_plan(&advanced, &registry, None)
            .await
            .unwrap();
        let mut advanced_plan = advanced_plan.expect("advanced system profile must be rebuildable");
        assert!(advanced_plan.is_system_profile());
        use_test_system_configuration(&mut advanced_plan, "supported-system-profile");

        let first = advanced_plan.build().await.unwrap();
        let unchanged = advanced_plan.build().await.unwrap();
        assert!(
            Arc::ptr_eq(&first, &unchanged),
            "unchanged system configuration must preserve the Hickory cache"
        );

        let refresh_plans = [ResolverRefreshPlan::Hickory(Box::new(advanced_plan))];
        let resolver = build_system_aware_refresh_group(&refresh_plans)
            .await
            .unwrap();
        let debug = format!("{resolver:?}");
        assert!(debug.contains("RefreshingResolver"), "{debug}");
        assert!(debug.contains("max_age: Some(5s)"), "{debug}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn system_checks_are_blocking_safe_and_coalesced() {
        let runtime_thread = std::thread::current().id();
        let loader_thread = Arc::new(Mutex::new(None));
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_thread = loader_thread.clone();
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            observed_calls.fetch_add(1, Ordering::Relaxed);
            *observed_thread.lock() = Some(std::thread::current().id());
            Ok(test_system_snapshot("unchanged"))
        });
        let plan = test_system_plan(loader, Duration::from_secs(5));

        let results = futures::future::join_all((0..16).map(|_| plan.build())).await;
        let resolvers = results.into_iter().map(Result::unwrap).collect::<Vec<_>>();

        assert_eq!(loader_calls.load(Ordering::Relaxed), 1);
        assert_ne!(loader_thread.lock().as_ref(), Some(&runtime_thread));
        assert!(
            resolvers
                .iter()
                .skip(1)
                .all(|resolver| Arc::ptr_eq(&resolvers[0], resolver)),
            "concurrent checks must share one freshly built resolver"
        );
    }

    #[tokio::test]
    async fn failed_ordinary_system_check_is_rate_limited_and_retains_last_good() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            if observed_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(test_system_snapshot("last-good"))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "test platform read failure",
                ))
            }
        });
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);
        let first = plan.build().await.unwrap();
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let after_failure = plan.build().await.unwrap();
        let during_cooldown = plan.build().await.unwrap();

        assert!(Arc::ptr_eq(&first, &after_failure));
        assert!(Arc::ptr_eq(&first, &during_cooldown));
        assert_eq!(
            loader_calls.load(Ordering::Relaxed),
            2,
            "a failed platform read must still start the five-second cooldown"
        );
    }

    #[tokio::test]
    async fn first_recognized_resolved_discovery_failure_is_explicit_and_rate_limited() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            observed_calls.fetch_add(1, Ordering::Relaxed);
            Err(crate::dns::system_config::mark_systemd_resolved_error(
                std::io::Error::new(std::io::ErrorKind::NotFound, "resolvectl unavailable"),
            ))
        });
        let plan = test_system_plan(loader, Duration::from_secs(5));

        let error = plan.build().await.expect_err("initial build must fail");
        assert!(
            error.to_string().contains("resolvectl unavailable"),
            "{error}"
        );
        let during_cooldown = plan
            .build()
            .await
            .expect_err("cached initial failure must remain explicit");
        assert!(
            during_cooldown
                .to_string()
                .contains("recent advanced system DNS configuration check failed"),
            "{during_cooldown}"
        );
        assert_eq!(loader_calls.load(Ordering::Relaxed), 1);
        let memo = plan.system_state.as_ref().unwrap().memo.lock();
        assert!(memo.systemd_resolved);
        assert!(memo.resolver.is_none());
    }

    #[tokio::test]
    async fn recognized_resolved_failure_replaces_ordinary_last_good_with_fail_closed() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader =
            Arc::new(
                move || match observed_calls.fetch_add(1, Ordering::Relaxed) {
                    0 => Ok(test_system_snapshot("ordinary-last-good")),
                    1 => Err(crate::dns::system_config::mark_systemd_resolved_error(
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "resolvectl unavailable after resolved ownership was recognized",
                        ),
                    )),
                    _ => Ok(test_systemd_snapshot(
                        "resolved-recovered",
                        crate::dns::system_config::ResolvedDnsOverTlsMode::No,
                    )),
                },
            );
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);

        let ordinary = plan.build().await.unwrap();
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let fail_closed = plan.build().await.unwrap();
        assert!(!Arc::ptr_eq(&ordinary, &fail_closed));
        let debug = format!("{fail_closed:?}");
        assert!(debug.contains("FailClosedSystemResolver"), "{debug}");
        assert!(
            plan.system_state
                .as_ref()
                .unwrap()
                .memo
                .lock()
                .systemd_resolved
        );
        let error = fail_closed
            .resolve_location(&NetLocation::new(
                crate::address::Address::Hostname("privacy.example".to_string()),
                53,
            ))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fail-closed"), "{error}");
        assert_eq!(loader_calls.load(Ordering::Relaxed), 2);

        let during_cooldown = plan.build().await.unwrap();
        assert!(Arc::ptr_eq(&fail_closed, &during_cooldown));
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);
        let recovered = plan.build().await.unwrap();
        assert!(format!("{recovered:?}").contains("OrderedSystemResolver"));
        assert!(
            plan.system_state
                .as_ref()
                .unwrap()
                .memo
                .lock()
                .systemd_resolved
        );
        assert_eq!(loader_calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn first_resolved_transport_build_failure_is_explicit() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            observed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(test_broken_systemd_snapshot("broken-first-generation"))
        });
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);

        let error = plan.build().await.expect_err("initial build must fail");
        assert!(!error.to_string().is_empty());
        assert!(
            plan.system_state
                .as_ref()
                .unwrap()
                .memo
                .lock()
                .systemd_resolved
        );

        let during_cooldown = plan
            .build()
            .await
            .expect_err("cached initial failure must remain explicit");
        assert!(
            during_cooldown
                .to_string()
                .contains("recent advanced system DNS configuration check failed"),
            "{during_cooldown}"
        );
        assert_eq!(loader_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn confirmed_resolved_transport_build_failure_is_fail_closed() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            if observed_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(test_systemd_snapshot(
                    "published-resolved-generation",
                    crate::dns::system_config::ResolvedDnsOverTlsMode::No,
                ))
            } else {
                Ok(test_broken_systemd_snapshot("broken-replacement"))
            }
        });
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);

        let published = plan.build().await.unwrap();
        assert!(
            plan.system_state
                .as_ref()
                .unwrap()
                .memo
                .lock()
                .systemd_resolved
        );
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let fail_closed = plan.build().await.unwrap();
        assert!(!Arc::ptr_eq(&published, &fail_closed));
        assert!(format!("{fail_closed:?}").contains("FailClosedSystemResolver"));
        let error = fail_closed
            .resolve_location(&NetLocation::new(
                crate::address::Address::Hostname("privacy.example".to_string()),
                443,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("fail-closed"));
        assert_eq!(loader_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn failed_resolved_refresh_replaces_opportunistic_transport_until_strict_recovery() {
        use crate::dns::system_config::ResolvedDnsOverTlsMode;

        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader =
            Arc::new(
                move || match observed_calls.fetch_add(1, Ordering::Relaxed) {
                    0 => Ok(test_systemd_snapshot(
                        "opportunistic",
                        ResolvedDnsOverTlsMode::Opportunistic,
                    )),
                    1 => Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "resolvectl unavailable while DNSOverTLS may have changed",
                    )),
                    _ => Ok(test_systemd_snapshot("strict", ResolvedDnsOverTlsMode::Yes)),
                },
            );
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);

        let opportunistic = plan.build().await.unwrap();
        assert!(format!("{opportunistic:?}").contains("Opportunistic"));
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let fail_closed = plan.build().await.unwrap();
        assert!(!Arc::ptr_eq(&opportunistic, &fail_closed));
        assert!(format!("{fail_closed:?}").contains("FailClosedSystemResolver"));
        let error = fail_closed
            .resolve_location(&NetLocation::new(
                crate::address::Address::Hostname("privacy.example".to_string()),
                443,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("fail-closed"));

        let during_cooldown = plan.build().await.unwrap();
        assert!(Arc::ptr_eq(&fail_closed, &during_cooldown));
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let strict = plan.build().await.unwrap();
        assert!(!Arc::ptr_eq(&fail_closed, &strict));
        assert!(format!("{strict:?}").contains("Yes"));
        assert_eq!(loader_calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn changed_system_fingerprint_rebuilds_the_hickory_resolver() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = loader_calls.clone();
        let loader: SystemConfigurationLoader = Arc::new(move || {
            let generation = observed_calls.fetch_add(1, Ordering::Relaxed);
            Ok(test_system_snapshot(format!("generation-{generation}")))
        });
        let interval = Duration::from_secs(5);
        let plan = test_system_plan(loader, interval);
        let first = plan.build().await.unwrap();
        plan.system_state.as_ref().unwrap().memo.lock().checked_at =
            Some(Instant::now() - interval);

        let changed = plan.build().await.unwrap();

        assert!(!Arc::ptr_eq(&first, &changed));
        assert_eq!(loader_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn dns_builder_preserves_urltest_client_chain_selection() {
        let mut spec = make_spec("tcp://1.1.1.1");
        spec.client_chains = vec![
            crate::config::ClientChain::default(),
            crate::config::ClientChain::default(),
        ];
        spec.client_chain_selection = crate::config::ClientChainSelectionConfig::UrlTest {
            shared_id: None,
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 30_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };

        let (_, plan) = build_entry_and_plan(&spec, &DnsRegistry::new(), None)
            .await
            .unwrap();
        let plan = plan.unwrap();
        assert!(format!("{:?}", plan.chain_group).contains("UrlTest"));
        assert!(plan.chain_key.contains("urltest"));
    }

    #[tokio::test]
    async fn native_roots_are_normalized_for_dns_entries_and_refresh_plans() {
        for (url, expected) in [
            ("system", false),
            ("udp://1.1.1.1", false),
            ("tcp://1.1.1.1", false),
            ("tls://1.1.1.1", true),
            ("quic://1.1.1.1", true),
            ("https://1.1.1.1/dns-query", true),
            ("h3://1.1.1.1/dns-query", true),
        ] {
            let mut spec = make_spec(url);
            spec.use_native_roots = true;
            let (entry, plan) = build_entry_and_plan(&spec, &DnsRegistry::new(), None)
                .await
                .unwrap();
            assert_eq!(entry.use_native_roots, expected, "entry for {url}");
            if let Some(plan) = plan {
                assert_eq!(
                    plan.options.use_native_roots, expected,
                    "refresh plan for {url}"
                );
            }
        }
    }

    #[test]
    fn test_compatible_servers_are_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "compatible entries should be pooled into one HickoryResolver, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "compatible entries should NOT produce CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn registry_returns_policy_resolver_for_server_group() {
        let mut upstream = make_spec("udp://192.0.2.53");
        upstream.tag = Some("policy-final".to_string());
        let group = ExpandedDnsGroup {
            name: "policy-dns".to_string(),
            specs: vec![upstream],
            final_server: Some("policy-final".to_string()),
            rules: vec![
                ExpandedDnsPolicyRule {
                    reject_flood_state_key: None,
                    exact: vec!["static.example".to_string()],
                    suffix: Vec::new(),
                    keyword: Vec::new(),
                    regex: Vec::new(),
                    rule_set: Vec::new(),
                    action: ExpandedDnsPolicyAction::Predefined(
                        crate::dns::DnsPredefinedResponse::no_error(vec![
                            "192.0.2.7".parse().unwrap(),
                        ]),
                    ),
                    no_drop: false,
                    timeout_millis: 0,
                },
                ExpandedDnsPolicyRule {
                    reject_flood_state_key: None,
                    exact: vec!["empty.example".to_string()],
                    suffix: Vec::new(),
                    keyword: Vec::new(),
                    regex: Vec::new(),
                    rule_set: Vec::new(),
                    action: ExpandedDnsPolicyAction::Predefined(
                        crate::dns::DnsPredefinedResponse::no_error(Vec::new()),
                    ),
                    no_drop: false,
                    timeout_millis: 0,
                },
                ExpandedDnsPolicyRule {
                    reject_flood_state_key: None,
                    exact: Vec::new(),
                    suffix: vec!["blocked.example".to_string()],
                    keyword: Vec::new(),
                    regex: Vec::new(),
                    rule_set: Vec::new(),
                    action: ExpandedDnsPolicyAction::Reject(crate::dns::DnsRejectMethod::Default),
                    no_drop: false,
                    timeout_millis: 0,
                },
            ],
        };
        let mut registry = build_dns_registry(vec![group]).await.unwrap();
        let config = DnsConfig {
            servers: NoneOrSome::One(DnsServerSpec::Simple("policy-dns".to_string())),
            final_server: None,
            rules: Vec::new(),
        };
        let resolver = registry.get_for_server(Some(&config));

        let static_location =
            NetLocation::new(Address::Hostname("STATIC.EXAMPLE.".to_string()), 8443);
        assert_eq!(
            resolver.resolve_location(&static_location).await.unwrap(),
            ["192.0.2.7:8443".parse().unwrap()]
        );

        let empty_location = NetLocation::new(Address::Hostname("empty.example".to_string()), 53);
        assert!(
            resolver
                .resolve_location(&empty_location)
                .await
                .unwrap()
                .is_empty()
        );

        let blocked_location =
            NetLocation::new(Address::Hostname("ads.blocked.example".to_string()), 53);
        assert_eq!(
            resolver
                .resolve_location(&blocked_location)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn hostname_upstream_rejects_empty_predefined_bootstrap_result() {
        let mut bootstrap_upstream = make_spec("udp://192.0.2.53");
        bootstrap_upstream.tag = Some("fallback".to_string());
        let bootstrap_group = ExpandedDnsGroup {
            name: "bootstrap-dns".to_string(),
            specs: vec![bootstrap_upstream],
            final_server: Some("fallback".to_string()),
            rules: vec![ExpandedDnsPolicyRule {
                reject_flood_state_key: None,
                exact: vec!["resolver.example".to_string()],
                suffix: Vec::new(),
                keyword: Vec::new(),
                regex: Vec::new(),
                rule_set: Vec::new(),
                action: ExpandedDnsPolicyAction::Predefined(
                    crate::dns::DnsPredefinedResponse::no_error(Vec::new()),
                ),
                no_drop: false,
                timeout_millis: 0,
            }],
        };
        let mut target = make_spec("https://resolver.example/dns-query");
        target.bootstrap_url = Some("bootstrap-dns".to_string());
        let target_group = ExpandedDnsGroup {
            name: "target-dns".to_string(),
            specs: vec![target],
            final_server: None,
            rules: Vec::new(),
        };

        let error = build_dns_registry(vec![bootstrap_group, target_group])
            .await
            .err()
            .expect("an empty production bootstrap result must be rejected");
        assert!(
            error
                .to_string()
                .contains("bootstrap lookup returned no addresses for 'resolver.example'"),
            "{error}"
        );
    }

    #[test]
    fn test_incompatible_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.timeout_secs = 10;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible timeouts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_attempts_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.attempts = 1;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.attempts = 3;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible attempts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_ip_strategy_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.ip_strategy = IpStrategy::Ipv4Only;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.ip_strategy = IpStrategy::Ipv6Only;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible ip_strategy should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_chain_groups_prevent_pooling() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain_a = Arc::new(build_direct_chain_group(resolver.clone()));
        let chain_b = Arc::new(build_direct_chain_group(resolver.clone()));

        let entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain_a,
            &resolver,
        );
        let entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain_b,
            &resolver,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different chain groups should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_bootstrap_resolvers_prevent_pooling() {
        let (chain, _) = shared_test_deps();
        let bootstrap_a: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let bootstrap_b: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        let entry_a = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_a,
            IpStrategy::default(),
            5,
            5,
            1,
        );
        let entry_b = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_b,
            IpStrategy::default(),
            5,
            5,
            1,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different bootstrap resolvers should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_system_resolver_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(ParsedDnsServer::System, &chain, &bootstrap),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver_with_test_system_configuration(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            !debug.contains("pool["),
            "system resolver entry should prevent pooling, got: {}",
            debug
        );
    }

    #[test]
    fn test_single_entry_not_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        )];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        // Single entry should not go through pooling (no benefit).
        assert!(
            !debug.contains("pool["),
            "single entry should not be pooled, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "single entry should not be composited, got: {}",
            debug
        );
    }

    #[test]
    fn test_quic_server_builds_native_doq_with_custom_sni_and_port() {
        use hickory_resolver::config::ProtocolConfig;

        let server = ParsedDnsServer::Quic {
            addr: "94.140.14.14:8853".parse().unwrap(),
            server_name: Arc::from("dns.example.com"),
        };
        let (ip, connection) = server_to_ns_config(&server).unwrap();
        assert_eq!(ip, "94.140.14.14".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(connection.port, 8853);
        assert!(matches!(
            connection.protocol,
            ProtocolConfig::Quic { ref server_name } if &**server_name == "dns.example.com"
        ));

        let (chain, bootstrap) = shared_test_deps();
        let resolver = build_resolver(vec![make_entry(server, &chain, &bootstrap)]).unwrap();
        let debug = format!("{resolver:?}");
        assert!(
            debug.contains("quic://94.140.14.14:8853#dns.example.com"),
            "expected native DoQ resolver description, got: {debug}"
        );
    }

    #[test]
    fn test_three_compatible_servers_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Tcp {
                    addr: "1.1.1.1:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "three compatible entries should be pooled, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_connect_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.connect_timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.connect_timeout_secs = 2;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible connect_timeout should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_keeps_distinct_transport_identities_out_of_one_pool() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let spec_b = make_spec("udp://8.8.4.4");

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry, None)
            .await
            .unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry, None)
            .await
            .unwrap();
        let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "different original transports require distinct Go single-flight identities, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_falls_back_for_incompatible_specs() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let mut spec_b = make_spec("udp://8.8.4.4");
        spec_b.attempts = 3;

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry, None)
            .await
            .unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry, None)
            .await
            .unwrap();
        let plans = vec![plan_a.unwrap(), plan_b.unwrap()];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible specs should fall back to CompositeResolver, got: {}",
            debug
        );
    }
}
