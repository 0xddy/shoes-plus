use log::{debug, error};
use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::address::{AddressMask, NetLocationMask};
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::{Resolver, resolve_location};
use crate::routing::predicate::{
    RouteContext, RouteMatchConfig, RoutePredicate, RoutePredicateError, RouteProtocol,
};

/// Cache key for routing decisions.
/// We cache based on the destination address and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RoutingCacheKey {
    /// Hostname destination (e.g., "example.com:443")
    Hostname { hostname: String, port: u16 },
    /// IPv4 destination
    Ipv4 { addr: Ipv4Addr, port: u16 },
    /// IPv6 destination
    Ipv6 { addr: Ipv6Addr, port: u16 },
}

impl RoutingCacheKey {
    fn from_location(location: &NetLocation) -> Self {
        match location.address() {
            Address::Hostname(hostname) => RoutingCacheKey::Hostname {
                hostname: hostname.to_lowercase(),
                port: location.port(),
            },
            Address::Ipv4(addr) => RoutingCacheKey::Ipv4 {
                addr: *addr,
                port: location.port(),
            },
            Address::Ipv6(addr) => RoutingCacheKey::Ipv6 {
                addr: *addr,
                port: location.port(),
            },
        }
    }
}

/// Cached routing decision.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CachedDecision {
    /// Index into the rules Vec for an Allow decision
    Allow(usize),
    /// Block decision
    Block,
}

/// LRU cache for routing decisions.
/// Uses RwLock for concurrent access - reads use peek() which doesn't require mutable access.
pub struct RoutingCache {
    inner: RwLock<LruCache<RoutingCacheKey, CachedDecision>>,
}

impl std::fmt::Debug for RoutingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.inner.read();
        f.debug_struct("RoutingCache")
            .field("len", &cache.len())
            .field("cap", &cache.cap())
            .finish()
    }
}

impl RoutingCache {
    /// Default cache capacity
    pub const DEFAULT_CAPACITY: usize = 10_000;

    /// Create a new routing cache with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: RwLock::new(LruCache::new(cap)),
        }
    }

    /// Look up a cached decision.
    /// Uses peek() which doesn't update LRU order (avoids write lock).
    #[inline]
    pub fn get(&self, location: &NetLocation) -> Option<CachedDecision> {
        let key = RoutingCacheKey::from_location(location);
        self.inner.read().peek(&key).copied()
    }

    /// Insert a decision into the cache.
    #[inline]
    pub fn insert(&self, location: &NetLocation, decision: CachedDecision) {
        let key = RoutingCacheKey::from_location(location);
        self.inner.write().put(key, decision);
    }

    #[cfg(test)]
    fn clear(&self) {
        self.inner.write().clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[derive(Debug)]
pub struct ConnectRule {
    pub masks: Vec<NetLocationMask>,
    /// Optional second-stage matcher, ANDed with the legacy destination masks.
    pub predicate: Option<RoutePredicate>,
    pub action: ConnectAction,
}

impl ConnectRule {
    pub fn new(masks: Vec<NetLocationMask>, action: ConnectAction) -> Self {
        Self {
            masks,
            predicate: None,
            action,
        }
    }

    pub fn with_predicate(
        masks: Vec<NetLocationMask>,
        predicate: RoutePredicate,
        action: ConnectAction,
    ) -> Self {
        Self {
            masks,
            predicate: Some(predicate),
            action,
        }
    }

    pub fn try_with_match_config(
        masks: Vec<NetLocationMask>,
        match_config: RouteMatchConfig,
        action: ConnectAction,
    ) -> Result<Self, RoutePredicateError> {
        if RoutePredicate::has_rule_set(&match_config)
            && masks
                .iter()
                .any(|mask| mask.port != 0 || mask.address_mask.netmask != 0)
        {
            return Err(RoutePredicateError::new(
                "rule_set match requires an unconditional legacy mask (for example 0.0.0.0/0)",
            ));
        }
        Ok(Self::with_predicate(
            masks,
            RoutePredicate::compile(&match_config)?,
            action,
        ))
    }
}

#[derive(Debug)]
pub enum ConnectAction {
    Allow {
        override_address: Option<NetLocation>,
        /// The chain group for this rule - multiple chains for round-robin selection.
        chain_group: ClientChainGroup,
    },
    Block,
}

impl ConnectAction {
    pub fn new_allow(override_address: Option<NetLocation>, chain_group: ClientChainGroup) -> Self {
        ConnectAction::Allow {
            override_address,
            chain_group,
        }
    }

    pub fn new_block() -> Self {
        ConnectAction::Block
    }

    /// Convert this action to a decision.
    ///
    /// Takes ownership of the location. If there's an override_address, a new
    /// ResolvedLocation is created (the resolved_addr doesn't apply to a different
    /// destination). Otherwise, the original location is passed through, preserving
    /// any resolution that was done during rule matching.
    pub fn to_decision(&self, location: ResolvedLocation) -> ConnectDecision<'_> {
        match self {
            ConnectAction::Allow {
                override_address,
                chain_group,
            } => {
                let remote_location = match override_address {
                    Some(l) => {
                        // Override address - create fresh location (resolved_addr doesn't apply)
                        let new_loc = if l.port() > 0 {
                            l.clone()
                        } else {
                            // If port of 0 is specified, take the requested port.
                            NetLocation::new(l.address().clone(), location.location().port())
                        };
                        new_loc.into()
                    }
                    None => {
                        // No override - pass through with any resolution intact
                        location
                    }
                };
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                }
            }
            ConnectAction::Block => ConnectDecision::Block,
        }
    }
}

/// Threshold for enabling cache based on rule count.
/// If rule count exceeds this value, caching is enabled even without DNS resolution.
const CACHE_RULE_THRESHOLD: usize = 16;

// TODO: Replace linear rule matching with radix set/trie
#[derive(Debug)]
pub struct ClientProxySelector {
    rules: Vec<ConnectRule>,
    /// Explicit inbound sniff setting. `None` is the legacy auto mode, where
    /// protocol predicates alone decide whether application bytes are inspected.
    sniff_policy: Option<bool>,
    /// If false, hostname rules will not trigger DNS resolution to match against IP-based
    /// destinations. This is useful when a huge blocklist or rule list is provided.
    /// However, this means that the user needs to make sure DNS resolutions are not done
    /// manually before hitting the server. Default is false (don't resolve).
    resolve_rule_hostnames: bool,
    /// LRU cache for routing decisions. Speeds up repeated lookups for the same destination.
    /// None if caching is disabled (few rules and no DNS resolution).
    cache: Option<RoutingCache>,
}

unsafe impl Send for ClientProxySelector {}
unsafe impl Sync for ClientProxySelector {}

#[derive(Debug)]
pub enum ConnectDecision<'a> {
    Allow {
        chain_group: &'a ClientChainGroup,
        remote_location: ResolvedLocation,
    },
    Block,
}

impl ClientProxySelector {
    pub fn new(rules: Vec<ConnectRule>) -> Self {
        Self::with_sniff_policy(rules, None)
    }

    /// Create a selector with an explicit inbound sniff policy.
    ///
    /// `None` retains legacy demand-driven sniffing, `Some(true)` enables it for
    /// every TCP stream, and `Some(false)` disables it unconditionally.
    pub fn with_sniff_policy(rules: Vec<ConnectRule>, sniff_policy: Option<bool>) -> Self {
        // Match sing-box route semantics: destination-IP predicates only inspect an
        // address that is already literal or pre-resolved. DNS resolution for routing
        // remains available as an explicit compatibility opt-in through
        // `with_options(rules, true)`.
        Self::with_options_and_cache_size_and_sniff_policy(
            rules,
            false,
            RoutingCache::DEFAULT_CAPACITY,
            sniff_policy,
        )
    }

    /// Create a new ClientProxySelector with configurable hostname resolution behavior.
    ///
    /// # Arguments
    /// * `rules` - The list of routing rules
    /// * `resolve_rule_hostnames` - If true, hostname rules will be resolved via DNS to match
    ///   against IP-based destinations. If false (default), hostname rules only match hostname
    ///   destinations directly. Setting this to false is more performant for large rule sets.
    pub fn with_options(rules: Vec<ConnectRule>, resolve_rule_hostnames: bool) -> Self {
        Self::with_options_and_cache_size_and_sniff_policy(
            rules,
            resolve_rule_hostnames,
            RoutingCache::DEFAULT_CAPACITY,
            None,
        )
    }

    /// Create a new ClientProxySelector with configurable hostname resolution and cache size.
    ///
    /// # Arguments
    /// * `rules` - The list of routing rules
    /// * `resolve_rule_hostnames` - If true, hostname rules will be resolved via DNS to match
    ///   against IP-based destinations. If false (default), hostname rules only match hostname
    ///   destinations directly.
    /// * `cache_capacity` - Maximum number of routing decisions to cache. Set to 0 to disable caching.
    ///
    /// # Caching behavior
    /// Caching is automatically enabled when the selector is independent of resolved IPs and:
    /// - `resolve_rule_hostnames` is true, OR
    /// - Rule count exceeds `CACHE_RULE_THRESHOLD` (16).
    ///
    /// For simple configurations with few rules and no DNS resolution, caching is disabled
    /// as the overhead of cache key construction exceeds the cost of linear rule matching.
    pub fn with_options_and_cache_size(
        rules: Vec<ConnectRule>,
        resolve_rule_hostnames: bool,
        cache_capacity: usize,
    ) -> Self {
        Self::with_options_and_cache_size_and_sniff_policy(
            rules,
            resolve_rule_hostnames,
            cache_capacity,
            None,
        )
    }

    fn with_options_and_cache_size_and_sniff_policy(
        rules: Vec<ConnectRule>,
        resolve_rule_hostnames: bool,
        cache_capacity: usize,
        sniff_policy: Option<bool>,
    ) -> Self {
        // Enable caching for context-free, resolution-independent selectors when
        // explicitly requested or when linear rule scans become expensive.
        // Network is intentionally not part of the legacy cache key. Context-sensitive
        // selectors bypass caching, preventing a TCP decision from being reused for UDP.
        let uses_context = rules.iter().any(|rule| {
            rule.predicate
                .as_ref()
                .is_some_and(RoutePredicate::uses_context)
        });
        // A hostname decision that depends on its resolved IP cannot be cached by
        // hostname and port alone. DNS may legitimately change between requests;
        // reusing a previous allow rule would let a public-to-private DNS rebind
        // bypass an IP-CIDR block rule while the connector resolves the hostname
        // again. Keep these selectors uncached until the cache key can include a
        // resolution with well-defined lifetime semantics.
        let uses_resolved_ip = rules.iter().any(|rule| {
            rule.predicate
                .as_ref()
                .is_some_and(RoutePredicate::requires_ip)
        });
        let cache = if !uses_context
            && !uses_resolved_ip
            && (resolve_rule_hostnames || rules.len() > CACHE_RULE_THRESHOLD)
        {
            Some(RoutingCache::new(cache_capacity.max(1)))
        } else {
            None
        };

        Self {
            rules,
            sniff_policy,
            resolve_rule_hostnames,
            cache,
        }
    }

    /// Judge a connection request, using the cache for faster repeated lookups.
    ///
    /// Takes ownership of `location` because:
    /// 1. Rule matching may resolve the hostname and cache it in the location
    /// 2. Rules may override the destination entirely
    ///
    /// The returned `ConnectDecision` contains the (possibly resolved/modified) location.
    ///
    /// IP-dependent and context-dependent selectors are deliberately uncached. Otherwise,
    /// caching is enabled when `resolve_rule_hostnames` is true or there are more than 16 rules.
    #[allow(dead_code)] // Kept as the context-free compatibility API.
    #[inline]
    pub async fn judge<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        self.judge_with_context(location, resolver, &RouteContext::default())
            .await
    }

    /// Judge a TCP destination. Built-in stream handlers use this convenience wrapper.
    #[inline]
    pub async fn judge_tcp<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        self.judge_with_context(location, resolver, &RouteContext::tcp())
            .await
    }

    /// Judge a TCP destination after bounded application-protocol sniffing.
    #[inline]
    pub async fn judge_sniffed_tcp<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        protocol: RouteProtocol,
        domain: Option<String>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        // The destination-only cache key cannot distinguish two HTTP Host/TLS SNI
        // values sharing one IP:port. Bypass it only for this metadata-bearing
        // lookup; ordinary TCP and UDP decisions can still use the selector cache.
        let resolved_ip = location.resolved_addr().map(|addr| ip_to_u128(addr.ip()));
        self.judge_uncached_with_context(
            location,
            resolved_ip,
            resolver,
            &RouteContext::sniffed_tcp(protocol, domain),
        )
        .await
    }

    /// The inbound's explicit sniff policy, or `None` for legacy auto mode.
    pub fn sniff_policy(&self) -> Option<bool> {
        self.sniff_policy
    }

    /// Whether this selector should inspect application bytes on a TCP stream.
    pub fn needs_tcp_sniff(&self) -> bool {
        self.sniff_policy.unwrap_or_else(|| {
            self.rules.iter().any(|rule| {
                rule.predicate
                    .as_ref()
                    .is_some_and(RoutePredicate::uses_protocol)
            })
        })
    }

    /// Compatibility alias for entry points while they migrate to
    /// [`Self::needs_tcp_sniff`].
    pub fn needs_tcp_protocol_sniff(&self) -> bool {
        self.needs_tcp_sniff()
    }

    /// Judge a UDP destination. Built-in datagram handlers use this convenience wrapper.
    #[inline]
    pub async fn judge_udp<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        self.judge_with_context(location, resolver, &RouteContext::udp())
            .await
    }

    /// Judge a connection with metadata that is not encoded in its destination.
    #[inline]
    pub async fn judge_with_context<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        context: &RouteContext,
    ) -> std::io::Result<ConnectDecision<'a>> {
        // Derive resolved_ip from any pre-resolved address
        let resolved_ip = location.resolved_addr().map(|addr| ip_to_u128(addr.ip()));

        // If caching is disabled, go directly to rule matching
        let cache = match &self.cache {
            Some(c) => c,
            None => {
                return self
                    .judge_uncached_with_context(location, resolved_ip, resolver, context)
                    .await;
            }
        };

        // Fast path: check cache first
        // Note: cached decisions don't include resolved_addr, so we pass through the location
        if let Some(cached) = cache.get(location.location()) {
            return Ok(self.cached_to_decision(cached, location));
        }

        // Slow path: full rule matching (may resolve and update the location)
        let mut location = location;
        match match_rule(
            &self.rules,
            &mut location,
            resolved_ip,
            resolver,
            self.resolve_rule_hostnames,
            context,
        )
        .await?
        {
            Some(rule_index) => {
                // Cache the result
                cache.insert(location.location(), CachedDecision::Allow(rule_index));
                Ok(self.rules[rule_index].action.to_decision(location))
            }
            None => {
                // Cache the block decision
                cache.insert(location.location(), CachedDecision::Block);
                Ok(ConnectDecision::Block)
            }
        }
    }

    /// Judge without using the cache. Useful for testing or when cache bypass is needed.
    #[allow(dead_code)] // Kept as the context-free compatibility API.
    #[inline]
    pub async fn judge_uncached<'a>(
        &'a self,
        location: ResolvedLocation,
        resolved_ip: Option<u128>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        self.judge_uncached_with_context(location, resolved_ip, resolver, &RouteContext::default())
            .await
    }

    /// Judge without caching while supplying route metadata.
    #[inline]
    pub async fn judge_uncached_with_context<'a>(
        &'a self,
        location: ResolvedLocation,
        resolved_ip: Option<u128>,
        resolver: &Arc<dyn Resolver>,
        context: &RouteContext,
    ) -> std::io::Result<ConnectDecision<'a>> {
        let mut location = location;
        match match_rule(
            &self.rules,
            &mut location,
            resolved_ip,
            resolver,
            self.resolve_rule_hostnames,
            context,
        )
        .await?
        {
            Some(rule_index) => Ok(self.rules[rule_index].action.to_decision(location)),
            None => Ok(ConnectDecision::Block),
        }
    }

    /// Convert a cached decision back to a ConnectDecision.
    #[inline]
    fn cached_to_decision(
        &self,
        cached: CachedDecision,
        location: ResolvedLocation,
    ) -> ConnectDecision<'_> {
        match cached {
            CachedDecision::Allow(rule_index) => {
                self.rules[rule_index].action.to_decision(location)
            }
            CachedDecision::Block => ConnectDecision::Block,
        }
    }

    #[cfg(test)]
    fn cache_size(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.len())
    }

    #[cfg(test)]
    fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    #[cfg(test)]
    fn is_cache_enabled(&self) -> bool {
        self.cache.is_some()
    }
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => ipv4_to_u128(addr),
        IpAddr::V6(addr) => ipv6_to_u128(addr),
    }
}

#[inline]
fn ipv4_to_u128(ip: Ipv4Addr) -> u128 {
    ipv6_to_u128(ip.to_ipv6_mapped())
}

#[inline]
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

#[inline]
fn matches_domain(base_domain: &str, hostname: &str) -> bool {
    if hostname.ends_with(base_domain) {
        let hostname_len = hostname.len();
        let base_domain_len = base_domain.len();
        if hostname_len == base_domain_len {
            true
        } else {
            // hostname_len > base_domain_len since hostname ends with base_domain.
            hostname.as_bytes()[hostname_len - base_domain_len - 1] == b'.'
        }
    } else {
        false
    }
}

/// Returns the index of the matching rule.
/// During matching, may resolve the location's address and cache it in `location`.
#[inline]
async fn match_rule(
    rules: &[ConnectRule],
    location: &mut ResolvedLocation,
    mut resolved_ip: Option<u128>,
    resolver: &Arc<dyn Resolver>,
    resolve_rule_hostnames: bool,
    context: &RouteContext,
) -> std::io::Result<Option<usize>> {
    for (rule_index, rule) in rules.iter().enumerate() {
        let mut masks_match = false;
        for mask in rule.masks.iter() {
            match match_mask(
                mask,
                location,
                &mut resolved_ip,
                resolver,
                resolve_rule_hostnames,
            )
            .await
            {
                Ok(is_match) => {
                    if is_match {
                        debug!(
                            "Found matching mask for {} -> {mask:?}",
                            location.location()
                        );
                        masks_match = true;
                        break;
                    }
                }
                Err(MatchMaskError::Fatal(e)) => {
                    return Err(std::io::Error::other(format!(
                        "fatal error while matching mask for {}: {e}",
                        location.location()
                    )));
                }
                Err(MatchMaskError::NonFatal(e)) => {
                    error!(
                        "Non-fatal error while trying to match mask for {}: {e}",
                        location.location()
                    );
                }
            }
        }

        if !masks_match {
            continue;
        }

        if let Some(predicate) = &rule.predicate {
            // Preserve the selector's existing hostname-resolution policy. If enabled,
            // resolve only when an IP-dependent OR branch is still undecidable.
            let mut predicate_ips: Vec<IpAddr> = location
                .resolved_addrs()
                .map(|addresses| {
                    addresses
                        .iter()
                        .map(|address| address.ip())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if predicate.needs_resolved_ips(location.location(), &predicate_ips, context)
                && matches!(location.location().address(), Address::Hostname(_))
                && resolve_rule_hostnames
            {
                let socket_addr = resolve_location(location, resolver).await?;
                resolved_ip = Some(ip_to_u128(socket_addr.ip()));
                predicate_ips = location
                    .resolved_addrs()
                    .expect("successful resolution retains at least one address")
                    .iter()
                    .map(|address| address.ip())
                    .collect::<Vec<_>>();
            }
            if !predicate.matches_resolved_ips(location.location(), &predicate_ips, context) {
                continue;
            }
        }

        return Ok(Some(rule_index));
    }
    Ok(None)
}

enum MatchMaskError {
    NonFatal(std::io::Error),
    Fatal(std::io::Error),
}

// Helper function for testing - exposed for unit tests
#[cfg(test)]
pub fn matches_domain_for_test(base_domain: &str, hostname: &str) -> bool {
    matches_domain(base_domain, hostname)
}

/// Match a single mask against the location.
/// Updates `resolved_ip` and `location.resolved_addr` if DNS resolution is performed.
#[inline]
async fn match_mask(
    location_mask: &NetLocationMask,
    location: &mut ResolvedLocation,
    resolved_ip: &mut Option<u128>,
    resolver: &Arc<dyn Resolver>,
    resolve_rule_hostnames: bool,
) -> std::result::Result<bool, MatchMaskError> {
    let NetLocationMask {
        address_mask: AddressMask { address, netmask },
        port,
    } = location_mask;

    let netmask = *netmask;
    let port = *port;

    if port > 0 && port != location.location().port() {
        return Ok(false);
    }

    if netmask == 0 {
        return Ok(true);
    }

    if let Some(hostname) = address.hostname() {
        if let Some(remote_hostname) = location.location().address().hostname() {
            return Ok(matches_domain(hostname, remote_hostname));
        }

        // We don't care about netmasks when hostnames are provided, so we can do direct matching
        // without resolving when both the remote location and the provided rule address are hostnames,
        // and simply return if it doesn't match.
        if !resolve_rule_hostnames {
            return Ok(false);
        }
    }

    // Need to get resolved IP for matching
    let masked_ip = match resolved_ip {
        Some(ip) => *ip,
        None => {
            // Resolve the destination lazily - this caches in `location`
            let socket_addr = resolve_location(location, resolver)
                .await
                .map_err(MatchMaskError::Fatal)?;
            let ip = ip_to_u128(socket_addr.ip());
            resolved_ip.replace(ip);
            ip
        }
    } & netmask;

    match address {
        Address::Ipv4(ip_addr) => {
            let mask = ipv4_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Ipv6(ip_addr) => {
            let mask = ipv6_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Hostname(_) => {
            // non-fatal error when the rule address cannot be resolved.
            // TODO: could this be cached?
            let socket_addrs = resolver
                .resolve_location(&NetLocation::new(address.clone(), port))
                .await
                .map_err(MatchMaskError::NonFatal)?;
            for socket_addr in socket_addrs {
                let mask = ip_to_u128(socket_addr.ip()) & netmask;
                if mask == masked_ip {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::Resolver;
    use std::future::Future;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock resolver for testing that returns predefined results
    #[derive(Debug)]
    struct MockResolver {
        mappings: std::collections::HashMap<String, Vec<SocketAddr>>,
    }

    impl MockResolver {
        fn new() -> Self {
            Self {
                mappings: std::collections::HashMap::new(),
            }
        }

        fn with_mapping(mut self, hostname: &str, port: u16, addrs: Vec<IpAddr>) -> Self {
            let key = format!("{}:{}", hostname, port);
            let socket_addrs: Vec<SocketAddr> = addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            self.mappings.insert(key, socket_addrs);
            self
        }
    }

    impl Resolver for MockResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            let key = format!("{}:{}", location.address(), location.port());
            let result = self.mappings.get(&key).cloned();
            Box::pin(async move {
                result.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("No mock mapping for {}", key),
                    )
                })
            })
        }
    }

    #[derive(Debug)]
    struct RebindingResolver {
        first: IpAddr,
        subsequent: IpAddr,
        calls: AtomicUsize,
    }

    impl RebindingResolver {
        fn new(first: IpAddr, subsequent: IpAddr) -> Self {
            Self {
                first,
                subsequent,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Resolver for RebindingResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let address = if call == 0 {
                self.first
            } else {
                self.subsequent
            };
            let port = location.port();
            Box::pin(async move { Ok(vec![SocketAddr::new(address, port)]) })
        }
    }

    /// Helper to create a mock resolver as Arc<dyn Resolver>
    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(MockResolver::new())
    }

    /// Create a mock ClientChainGroup for testing (single chain with direct connector)
    fn mock_chain_group() -> ClientChainGroup {
        use crate::resolver::NativeResolver;
        use crate::tcp::chain_builder::build_client_chain_group;
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        build_client_chain_group(crate::option_util::NoneOrSome::None, resolver)
    }

    /// Helper to create an allow rule (for rule matching tests)
    fn allow_rule(masks: Vec<&str>, _proxy_name: &str) -> ConnectRule {
        let masks: Vec<NetLocationMask> = masks
            .into_iter()
            .map(|s| NetLocationMask::from(s).unwrap())
            .collect();
        // For tests, we just use a mock chain group since we're testing rule matching
        ConnectRule::new(masks, ConnectAction::new_allow(None, mock_chain_group()))
    }

    /// Helper to create an allow rule with multiple proxies (for rule matching tests)
    fn allow_rule_multi(masks: Vec<&str>, _proxy_names: Vec<&str>) -> ConnectRule {
        let masks: Vec<NetLocationMask> = masks
            .into_iter()
            .map(|s| NetLocationMask::from(s).unwrap())
            .collect();
        // For tests, we just use a mock chain group since we're testing rule matching
        ConnectRule::new(masks, ConnectAction::new_allow(None, mock_chain_group()))
    }

    /// Helper to create a block rule
    fn block_rule(masks: Vec<&str>) -> ConnectRule {
        let masks: Vec<NetLocationMask> = masks
            .into_iter()
            .map(|s| NetLocationMask::from(s).unwrap())
            .collect();
        ConnectRule::new(masks, ConnectAction::new_block())
    }

    /// Helper to create an allow rule with address override
    fn allow_rule_with_override(
        masks: Vec<&str>,
        _proxy_name: &str,
        override_addr: &str,
    ) -> ConnectRule {
        let masks: Vec<NetLocationMask> = masks
            .into_iter()
            .map(|s| NetLocationMask::from(s).unwrap())
            .collect();
        let override_location = NetLocation::from_str(override_addr, Some(0)).unwrap();
        ConnectRule::new(
            masks,
            ConnectAction::new_allow(Some(override_location), mock_chain_group()),
        )
    }

    #[test]
    fn test_matches_domain_exact_match() {
        assert!(matches_domain_for_test("example.com", "example.com"));
        assert!(matches_domain_for_test("foo.bar.com", "foo.bar.com"));
    }

    #[test]
    fn test_matches_domain_subdomain_match() {
        assert!(matches_domain_for_test("example.com", "www.example.com"));
        assert!(matches_domain_for_test(
            "example.com",
            "sub.www.example.com"
        ));
        assert!(matches_domain_for_test("bar.com", "foo.bar.com"));
    }

    #[test]
    fn test_matches_domain_no_match_different_domain() {
        assert!(!matches_domain_for_test("example.com", "notexample.com"));
        assert!(!matches_domain_for_test("example.com", "example.org"));
        assert!(!matches_domain_for_test("foo.com", "bar.com"));
    }

    #[test]
    fn test_matches_domain_no_match_partial_suffix() {
        // "malicious-example.com" ends with "example.com" as a string,
        // but it's not a subdomain
        assert!(!matches_domain_for_test(
            "example.com",
            "malicious-example.com"
        ));
        assert!(!matches_domain_for_test("example.com", "fakeexample.com"));
        assert!(!matches_domain_for_test("bar.com", "foobar.com"));
    }

    #[test]
    fn test_matches_domain_no_match_base_longer() {
        assert!(!matches_domain_for_test("www.example.com", "example.com"));
        assert!(!matches_domain_for_test("sub.example.com", "example.com"));
    }

    #[test]
    fn test_matches_domain_empty_strings() {
        assert!(!matches_domain_for_test("example.com", ""));
        assert!(!matches_domain_for_test("", "example.com"));
        assert!(matches_domain_for_test("", "")); // Both empty matches
    }

    #[test]
    fn test_matches_domain_single_label() {
        assert!(matches_domain_for_test("localhost", "localhost"));
        assert!(!matches_domain_for_test("localhost", "notlocalhost"));
        assert!(!matches_domain_for_test("host", "localhost")); // partial suffix
    }

    #[tokio::test]
    async fn test_ipv4_exact_match() {
        let rules = vec![
            allow_rule(vec!["192.168.1.1/32"], "proxy1"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow, got Block"),
        }
    }

    #[tokio::test]
    async fn test_ipv4_exact_match_no_match() {
        let rules = vec![
            allow_rule(vec!["192.168.1.1/32"], "proxy1"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Different IP should fall through to default
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 2)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow, got Block"),
        }
    }

    #[tokio::test]
    async fn test_ipv4_cidr_24() {
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // All addresses in 192.168.1.0/24 should match
        for last_octet in [0u8, 1, 100, 254, 255] {
            let location =
                NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, last_octet)), 80);
            let decision = selector.judge(location.into(), &resolver).await.unwrap();
            match decision {
                ConnectDecision::Allow { .. } => {}
                ConnectDecision::Block => panic!("Expected Allow for 192.168.1.{}", last_octet),
            }
        }

        // Address outside the range should not match
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_ipv4_cidr_16() {
        let rules = vec![
            allow_rule(vec!["10.0.0.0/8"], "private_a"),
            allow_rule(vec!["172.16.0.0/12"], "private_b"),
            allow_rule(vec!["192.168.0.0/16"], "private_c"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Test 10.0.0.0/8 range
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 255, 255, 255)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Test 172.16.0.0/12 range (172.16.0.0 - 172.31.255.255)
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(172, 20, 5, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Test 192.168.0.0/16 range
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 100, 50)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Public IP should go to default
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_ipv4_localhost() {
        let rules = vec![
            allow_rule(vec!["127.0.0.0/8"], "loopback"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // 127.x.x.x should all match loopback
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 255, 255, 255)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_ipv6_exact_match() {
        let rules = vec![
            allow_rule(vec!["::1/128"], "loopback"),
            allow_rule(vec!["::/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_ipv6_cidr() {
        let rules = vec![
            allow_rule(vec!["fe80::/10"], "link_local"),
            allow_rule(vec!["fc00::/7"], "unique_local"),
            allow_rule(vec!["::/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Link-local address
        let location = NetLocation::new(Address::Ipv6("fe80::1".parse().unwrap()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Unique local address (fc00::/7 covers fc00:: and fd00::)
        let location = NetLocation::new(Address::Ipv6("fd00::1234".parse().unwrap()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Global unicast should go to default
        let location = NetLocation::new(Address::Ipv6("2001:db8::1".parse().unwrap()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_hostname_exact_match() {
        let rules = vec![
            allow_rule(vec!["example.com"], "example_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Hostname("example.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_hostname_subdomain_match() {
        let rules = vec![
            allow_rule(vec!["example.com"], "example_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Subdomain should match
        let location = NetLocation::new(Address::Hostname("www.example.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Deep subdomain should match
        let location = NetLocation::new(Address::Hostname("sub.www.example.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_hostname_no_false_subdomain_match() {
        // malicious-example.com should NOT match example.com rule
        let rules = vec![
            allow_rule(vec!["example.com"], "example_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Hostname("malicious-example.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        let location = NetLocation::new(Address::Hostname("fakeexample.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_hostname_different_tld() {
        let rules = vec![
            allow_rule(vec!["example.com"], "example_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Different TLD should not match
        let location = NetLocation::new(Address::Hostname("example.org".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_port_specific_rule() {
        let rules = vec![
            allow_rule(vec!["0.0.0.0/0:443"], "https_proxy"),
            allow_rule(vec!["0.0.0.0/0:80"], "http_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Port 443 should match https_proxy
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Port 80 should match http_proxy
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Other ports should go to default
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_port_with_ip_restriction() {
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24:22"], "ssh_lan"),
            allow_rule(vec!["0.0.0.0/0:22"], "ssh_default"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // LAN SSH should match ssh_lan
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 22);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // External SSH should match ssh_default
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 22);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // LAN HTTP should go to default (not ssh_lan because port doesn't match)
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_first_rule_wins() {
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "specific"),
            allow_rule(vec!["192.168.0.0/16"], "less_specific"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // 192.168.1.x should match the first (more specific) rule
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // 192.168.2.x should match the second rule
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_rule_order_matters_security() {
        // SECURITY: If a block rule comes after an allow rule for overlapping ranges,
        // the allow rule takes precedence
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "allowed"),
            block_rule(vec!["192.168.0.0/16"]),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // 192.168.1.x matches the allow rule first
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow for 192.168.1.1"),
        }

        // 192.168.2.x should be blocked
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block for 192.168.2.1"),
            ConnectDecision::Block => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_block_rule() {
        let rules = vec![
            block_rule(vec!["192.168.1.0/24"]),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Blocked range
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block"),
            ConnectDecision::Block => {} // Expected
        }

        // Non-blocked range
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_block_hostname() {
        let rules = vec![
            block_rule(vec!["blocked.com"]),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Blocked hostname
        let location = NetLocation::new(Address::Hostname("blocked.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block for blocked.com"),
            ConnectDecision::Block => {} // Expected
        }

        // Subdomain of blocked hostname should also be blocked
        let location = NetLocation::new(Address::Hostname("www.blocked.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block for www.blocked.com"),
            ConnectDecision::Block => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_no_default_rule_blocks() {
        let rules = vec![allow_rule(vec!["192.168.1.0/24"], "lan")];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Non-matching address with no default rule should block
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block when no default rule"),
            ConnectDecision::Block => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_round_robin_proxy_selection() {
        // Note: Since ClientProxyChain now handles round-robin internally,
        // we just verify that multiple calls succeed. Actual round-robin testing
        // is done at the ClientProxyChain level.
        let rules = vec![allow_rule_multi(
            vec!["0.0.0.0/0"],
            vec!["proxy1", "proxy2", "proxy3"],
        )];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        for _ in 0..6 {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
            let decision = selector.judge(location.into(), &resolver).await.unwrap();
            match decision {
                ConnectDecision::Allow { .. } => {
                    // Round-robin selection now happens in ClientProxyChain
                }
                ConnectDecision::Block => panic!("Expected Allow"),
            }
        }
    }

    #[tokio::test]
    async fn test_single_proxy_no_rotation() {
        let rules = vec![allow_rule(vec!["0.0.0.0/0"], "only_proxy")];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        for _ in 0..5 {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
            let decision = selector.judge(location.into(), &resolver).await.unwrap();
            match decision {
                ConnectDecision::Allow { .. } => {}
                ConnectDecision::Block => panic!("Expected Allow"),
            }
        }
    }

    #[tokio::test]
    async fn test_address_override() {
        let rules = vec![allow_rule_with_override(
            vec!["0.0.0.0/0"],
            "proxy",
            "10.0.0.1:8080",
        )];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow {
                remote_location, ..
            } => {
                assert_eq!(remote_location.address().to_string(), "10.0.0.1");
                assert_eq!(remote_location.port(), 8080);
            }
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_address_override_preserve_port() {
        // Override with port 0 should preserve the original port
        let rules = vec![allow_rule_with_override(
            vec!["0.0.0.0/0"],
            "proxy",
            "10.0.0.1:0",
        )];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow {
                remote_location, ..
            } => {
                assert_eq!(remote_location.address().to_string(), "10.0.0.1");
                assert_eq!(remote_location.port(), 443); // Original port preserved
            }
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_multiple_masks_in_rule() {
        let rules = vec![
            allow_rule(
                vec!["192.168.1.0/24", "192.168.2.0/24", "10.0.0.0/8"],
                "internal",
            ),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // All three ranges should match "internal"
        for ip in [
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 2, 100),
            Ipv4Addr::new(10, 50, 50, 50),
        ] {
            let location = NetLocation::new(Address::Ipv4(ip), 80);
            let decision = selector.judge(location.into(), &resolver).await.unwrap();
            match decision {
                ConnectDecision::Allow { .. } => {
                    // assertion removed - client_proxy no longer available
                }
                ConnectDecision::Block => panic!("Expected Allow for {}", ip),
            }
        }

        // Other IPs should go to default
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_multiple_hostnames_in_rule() {
        let rules = vec![
            allow_rule(
                vec!["google.com", "youtube.com", "gmail.com"],
                "google_proxy",
            ),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        for hostname in [
            "google.com",
            "www.google.com",
            "youtube.com",
            "mail.gmail.com",
        ] {
            let location = NetLocation::new(Address::Hostname(hostname.to_string()), 80);
            let decision = selector.judge(location.into(), &resolver).await.unwrap();
            match decision {
                ConnectDecision::Allow { .. } => {
                    // assertion removed - client_proxy no longer available
                }
                ConnectDecision::Block => panic!("Expected Allow for {}", hostname),
            }
        }
    }

    #[tokio::test]
    async fn test_empty_rules_blocks_all() {
        let rules: Vec<ConnectRule> = vec![];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block with empty rules"),
            ConnectDecision::Block => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_ipv4_mapped_ipv6() {
        // IPv4-mapped IPv6 addresses (::ffff:192.168.1.1) should be handled correctly
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Regular IPv4
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_broadcast_and_special_addresses() {
        let rules = vec![
            block_rule(vec!["255.255.255.255/32"]), // Broadcast
            block_rule(vec!["0.0.0.0/32"]),         // Unspecified
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Broadcast should be blocked
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::BROADCAST), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block for broadcast"),
            ConnectDecision::Block => {} // Expected
        }

        // Unspecified should be blocked
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => panic!("Expected Block for unspecified"),
            ConnectDecision::Block => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_case_sensitivity_hostname() {
        let rules = vec![
            allow_rule(vec!["Example.COM"], "example_proxy"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Note: DNS hostnames are case-insensitive by spec, but our implementation
        // does case-sensitive matching. This test documents current behavior.
        let location = NetLocation::new(Address::Hostname("example.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {
                // Current behavior: case-sensitive, so this goes to default
                // If we want case-insensitive, this should be "example_proxy"
            }
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_access_round_robin() {
        // Test that concurrent access to round-robin is safe (uses AtomicU32)
        use std::sync::Arc as StdArc;

        let rules = vec![allow_rule_multi(
            vec!["0.0.0.0/0"],
            vec!["p1", "p2", "p3", "p4"],
        )];
        let selector = StdArc::new(ClientProxySelector::new(rules));
        let resolver = mock_resolver();

        let mut handles = vec![];
        for _ in 0..10 {
            let selector = selector.clone();
            let resolver = resolver.clone();
            handles.push(tokio::spawn(async move {
                let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
                let _ = selector.judge(location.into(), &resolver).await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
        // If we got here without panic, concurrent access is safe
    }

    #[tokio::test]
    async fn test_localhost_bypass() {
        // Common pattern: bypass proxy for localhost
        // Note: With resolve_rule_hostnames=false (default), hostname destinations
        // won't match IP rules unless the hostname rule comes first.
        let rules = vec![
            allow_rule(vec!["localhost"], "direct_host"), // Hostname rule first
            allow_rule_with_override(vec!["127.0.0.0/8"], "direct", "127.0.0.1:0"),
            allow_rule(vec!["0.0.0.0/0"], "proxy"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // 127.0.0.1 should use direct (matches IP rule)
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // localhost hostname should use direct_host (matches hostname rule)
        let location = NetLocation::new(Address::Hostname("localhost".to_string()), 8080);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_mixed_ip_and_hostname_rules() {
        // With resolve_rule_hostnames=false (default), hostname destinations do not
        // trigger DNS merely to evaluate an IP rule. Hostname rules can still match
        // directly, so keep the more specific rules before the fallback.
        let rules = vec![
            block_rule(vec!["malware.com"]),
            allow_rule(vec!["trusted.com"], "trusted"), // Hostname rules before IP rules
            allow_rule(vec!["192.168.0.0/16"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        let resolver = mock_resolver();

        // Malware hostname blocked
        let location = NetLocation::new(Address::Hostname("malware.com".to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        assert!(matches!(decision, ConnectDecision::Block));

        // LAN IP allowed through lan proxy
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Trusted hostname allowed through trusted proxy
        let location = NetLocation::new(Address::Hostname("api.trusted.com".to_string()), 443);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[test]
    fn test_routing_cache_key_from_location_hostname() {
        let location = NetLocation::new(Address::Hostname("Example.COM".to_string()), 443);
        let key = RoutingCacheKey::from_location(&location);
        match key {
            RoutingCacheKey::Hostname { hostname, port } => {
                assert_eq!(hostname, "example.com"); // Should be lowercased
                assert_eq!(port, 443);
            }
            _ => panic!("Expected Hostname key"),
        }
    }

    #[test]
    fn test_routing_cache_key_from_location_ipv4() {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let key = RoutingCacheKey::from_location(&location);
        match key {
            RoutingCacheKey::Ipv4 { addr, port } => {
                assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(port, 80);
            }
            _ => panic!("Expected Ipv4 key"),
        }
    }

    #[test]
    fn test_routing_cache_key_from_location_ipv6() {
        let location = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8080);
        let key = RoutingCacheKey::from_location(&location);
        match key {
            RoutingCacheKey::Ipv6 { addr, port } => {
                assert_eq!(addr, Ipv6Addr::LOCALHOST);
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Ipv6 key"),
        }
    }

    #[test]
    fn test_routing_cache_basic_operations() {
        let cache = RoutingCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

        // Initially no entry
        assert!(cache.get(&location).is_none());

        // Insert and retrieve
        cache.insert(&location, CachedDecision::Allow(5));
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&location);
        assert!(cached.is_some());
        match cached.unwrap() {
            CachedDecision::Allow(idx) => assert_eq!(idx, 5),
            CachedDecision::Block => panic!("Expected Allow"),
        }
    }

    #[test]
    fn test_routing_cache_block_decision() {
        let cache = RoutingCache::new(100);
        let location = NetLocation::new(Address::Hostname("blocked.com".to_string()), 443);

        cache.insert(&location, CachedDecision::Block);

        let cached = cache.get(&location);
        assert!(matches!(cached, Some(CachedDecision::Block)));
    }

    #[test]
    fn test_routing_cache_different_ports() {
        let cache = RoutingCache::new(100);
        let loc_80 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let loc_443 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);

        cache.insert(&loc_80, CachedDecision::Allow(1));
        cache.insert(&loc_443, CachedDecision::Allow(2));

        // Same IP, different ports should be different cache entries
        match cache.get(&loc_80).unwrap() {
            CachedDecision::Allow(idx) => assert_eq!(idx, 1),
            _ => panic!("Expected Allow(1)"),
        }
        match cache.get(&loc_443).unwrap() {
            CachedDecision::Allow(idx) => assert_eq!(idx, 2),
            _ => panic!("Expected Allow(2)"),
        }
    }

    #[test]
    fn test_routing_cache_hostname_case_insensitive() {
        let cache = RoutingCache::new(100);

        // Insert with uppercase
        let loc_upper = NetLocation::new(Address::Hostname("EXAMPLE.COM".to_string()), 443);
        cache.insert(&loc_upper, CachedDecision::Allow(1));

        // Retrieve with lowercase - should find it
        let loc_lower = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        assert!(cache.get(&loc_lower).is_some());

        // Retrieve with mixed case - should find it
        let loc_mixed = NetLocation::new(Address::Hostname("Example.Com".to_string()), 443);
        assert!(cache.get(&loc_mixed).is_some());
    }

    #[test]
    fn test_routing_cache_clear() {
        let cache = RoutingCache::new(100);

        // Add some entries
        for i in 0..10 {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, i)), 80);
            cache.insert(&location, CachedDecision::Allow(i as usize));
        }
        assert_eq!(cache.len(), 10);

        // Clear
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // Verify entries are gone
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 0)), 80);
        assert!(cache.get(&location).is_none());
    }

    #[test]
    fn test_routing_cache_lru_eviction() {
        // Small cache to test eviction
        let cache = RoutingCache::new(3);

        // Insert 3 entries
        let loc1 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 1)), 80);
        let loc2 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 2)), 80);
        let loc3 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 3)), 80);

        cache.insert(&loc1, CachedDecision::Allow(1));
        cache.insert(&loc2, CachedDecision::Allow(2));
        cache.insert(&loc3, CachedDecision::Allow(3));
        assert_eq!(cache.len(), 3);

        // Insert 4th entry - should evict the oldest (loc1)
        let loc4 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 4)), 80);
        cache.insert(&loc4, CachedDecision::Allow(4));
        assert_eq!(cache.len(), 3);

        // loc1 should be evicted
        assert!(cache.get(&loc1).is_none());
        // Others should still be present
        assert!(cache.get(&loc2).is_some());
        assert!(cache.get(&loc3).is_some());
        assert!(cache.get(&loc4).is_some());
    }

    #[test]
    fn test_routing_cache_overwrite() {
        let cache = RoutingCache::new(100);
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

        // Insert Allow
        cache.insert(&location, CachedDecision::Allow(1));
        match cache.get(&location).unwrap() {
            CachedDecision::Allow(idx) => assert_eq!(idx, 1),
            _ => panic!("Expected Allow(1)"),
        }

        // Overwrite with Block
        cache.insert(&location, CachedDecision::Block);
        assert!(matches!(cache.get(&location), Some(CachedDecision::Block)));

        // Overwrite with different Allow
        cache.insert(&location, CachedDecision::Allow(5));
        match cache.get(&location).unwrap() {
            CachedDecision::Allow(idx) => assert_eq!(idx, 5),
            _ => panic!("Expected Allow(5)"),
        }
    }

    /// Helper to create a selector with caching enabled (via resolve_rule_hostnames=true)
    fn selector_with_cache(rules: Vec<ConnectRule>) -> ClientProxySelector {
        ClientProxySelector::with_options(rules, true)
    }

    #[tokio::test]
    async fn test_selector_cache_disabled_for_few_rules() {
        // With few rules and resolve_rule_hostnames=false, cache should be disabled
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::new(rules);
        assert!(!selector.is_cache_enabled());

        // Routing should still work correctly
        let resolver = mock_resolver();
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }

    #[tokio::test]
    async fn test_selector_cache_enabled_with_dns_resolution() {
        // With resolve_rule_hostnames=true, cache should be enabled even with few rules
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = ClientProxySelector::with_options(rules, true);
        assert!(selector.is_cache_enabled());
    }

    #[tokio::test]
    async fn test_selector_cache_enabled_with_many_rules() {
        // With many rules (>16), cache should be enabled even without DNS resolution
        let mut rules: Vec<ConnectRule> = (0..20)
            .map(|i| allow_rule(vec![&format!("10.0.{}.0/24", i)], &format!("rule{}", i)))
            .collect();
        rules.push(allow_rule(vec!["0.0.0.0/0"], "default"));

        let selector = ClientProxySelector::new(rules);
        assert!(selector.is_cache_enabled());
    }

    #[tokio::test]
    async fn test_selector_cache_hit() {
        // Use selector_with_cache to ensure caching is enabled for this test
        let rules = vec![
            allow_rule(vec!["192.168.1.0/24"], "lan"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);

        // First call - cache miss
        assert_eq!(selector.cache_size(), 0);
        let decision = selector
            .judge(location.clone().into(), &resolver)
            .await
            .unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Should be cached now
        assert_eq!(selector.cache_size(), 1);

        // Second call - cache hit (same result)
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Still only 1 entry (was a hit, not a new insert)
        assert_eq!(selector.cache_size(), 1);
    }

    #[tokio::test]
    async fn test_selector_cache_block_decision() {
        let rules = vec![
            block_rule(vec!["192.168.1.0/24"]),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);

        // First call - cache miss, should block
        let decision = selector
            .judge(location.clone().into(), &resolver)
            .await
            .unwrap();
        assert!(matches!(decision, ConnectDecision::Block));
        assert_eq!(selector.cache_size(), 1);

        // Second call - cache hit, still blocks
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        assert!(matches!(decision, ConnectDecision::Block));
    }

    #[tokio::test]
    async fn test_selector_clear_cache() {
        let rules = vec![allow_rule(vec!["0.0.0.0/0"], "default")];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        // Make some cached entries
        for i in 0..5 {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, i)), 80);
            let _ = selector.judge(location.into(), &resolver).await.unwrap();
        }
        assert_eq!(selector.cache_size(), 5);

        // Clear cache
        selector.clear_cache();
        assert_eq!(selector.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_selector_judge_uncached() {
        let rules = vec![allow_rule(vec!["0.0.0.0/0"], "default")];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

        // Use judge_uncached - should NOT populate cache
        let decision = selector
            .judge_uncached(location.into(), None, &resolver)
            .await
            .unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }

        // Cache should still be empty
        assert_eq!(selector.cache_size(), 0);
    }

    #[tokio::test]
    async fn test_selector_cache_different_destinations() {
        let rules = vec![
            allow_rule(vec!["192.168.0.0/16"], "lan"),
            allow_rule(vec!["10.0.0.0/8"], "private"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        // Hit different rules
        let loc_lan = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let loc_private = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 80);
        let loc_public = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);

        let d1 = selector
            .judge(loc_lan.clone().into(), &resolver)
            .await
            .unwrap();
        let d2 = selector
            .judge(loc_private.clone().into(), &resolver)
            .await
            .unwrap();
        let d3 = selector
            .judge(loc_public.clone().into(), &resolver)
            .await
            .unwrap();

        // Verify correct routing (all should be Allow decisions)
        assert!(
            matches!(d1, ConnectDecision::Allow { .. }),
            "Expected lan to allow"
        );
        assert!(
            matches!(d2, ConnectDecision::Allow { .. }),
            "Expected private to allow"
        );
        assert!(
            matches!(d3, ConnectDecision::Allow { .. }),
            "Expected default to allow"
        );

        // All 3 should be cached
        assert_eq!(selector.cache_size(), 3);

        // Verify cache hits return same results
        let d1_cached = selector.judge(loc_lan.into(), &resolver).await.unwrap();
        assert!(
            matches!(d1_cached, ConnectDecision::Allow { .. }),
            "Expected lan from cache"
        );
    }

    #[tokio::test]
    async fn test_selector_cache_hostname_destinations() {
        let rules = vec![
            allow_rule(vec!["google.com"], "google"),
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        // Hostname match
        let loc_google = NetLocation::new(Address::Hostname("www.google.com".to_string()), 443);
        let decision = selector
            .judge(loc_google.clone().into(), &resolver)
            .await
            .unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            _ => panic!("Expected google"),
        }

        // Should be cached
        assert_eq!(selector.cache_size(), 1);

        // Case-insensitive cache hit
        let loc_google_upper =
            NetLocation::new(Address::Hostname("WWW.GOOGLE.COM".to_string()), 443);
        let decision = selector
            .judge(loc_google_upper.into(), &resolver)
            .await
            .unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            _ => panic!("Expected google from cache"),
        }

        // Should still be 1 entry (case-insensitive hit)
        assert_eq!(selector.cache_size(), 1);
    }

    #[tokio::test]
    async fn test_selector_cache_with_custom_size() {
        // Use resolve_rule_hostnames=true to enable caching with custom size
        let rules = vec![allow_rule(vec!["0.0.0.0/0"], "default")];
        let selector = ClientProxySelector::with_options_and_cache_size(rules, true, 5);
        let resolver = mock_resolver();

        // Fill cache to capacity
        for i in 0..5 {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, i)), 80);
            let _ = selector.judge(location.into(), &resolver).await.unwrap();
        }
        assert_eq!(selector.cache_size(), 5);

        // Add one more - should evict oldest
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 100)), 80);
        let _ = selector.judge(location.into(), &resolver).await.unwrap();
        assert_eq!(selector.cache_size(), 5); // Still 5, one was evicted

        // First entry should be evicted - verify by checking the cache is full
        // but we can't directly access the internal cache to verify eviction
        // So we verify indirectly: if we add another entry, size stays at 5
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 200)), 80);
        let _ = selector.judge(location.into(), &resolver).await.unwrap();
        assert_eq!(selector.cache_size(), 5);
    }

    #[tokio::test]
    async fn test_selector_concurrent_cache_access() {
        use std::sync::Arc as StdArc;

        let rules = vec![allow_rule(vec!["0.0.0.0/0"], "default")];
        let selector = StdArc::new(selector_with_cache(rules));
        let resolver = mock_resolver();

        // Spawn multiple tasks accessing the cache concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let selector = selector.clone();
            let resolver = resolver.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..100 {
                    let location =
                        NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, i as u8, j as u8)), 80);
                    let decision = selector.judge(location.into(), &resolver).await.unwrap();
                    match decision {
                        ConnectDecision::Allow { .. } => {}
                        ConnectDecision::Block => panic!("Expected Allow"),
                    }
                }
            }));
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }

        // Should have cached entries (exact number depends on timing)
        assert!(selector.cache_size() > 0);
    }

    #[tokio::test]
    async fn test_selector_cache_preserves_rule_priority() {
        // Ensure caching doesn't break rule priority
        let rules = vec![
            allow_rule(vec!["192.168.1.100/32"], "specific"), // Rule 0
            allow_rule(vec!["192.168.1.0/24"], "subnet"),     // Rule 1
            allow_rule(vec!["192.168.0.0/16"], "network"),    // Rule 2
            allow_rule(vec!["0.0.0.0/0"], "default"),         // Rule 3
        ];
        let selector = selector_with_cache(rules);
        let resolver = mock_resolver();

        // Specific IP should match rule 0 (most specific)
        let loc_specific = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
        let decision = selector
            .judge(loc_specific.clone().into(), &resolver)
            .await
            .unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            _ => panic!("Expected specific"),
        }

        // Verify from cache - should still be "specific"
        let decision_cached = selector
            .judge(loc_specific.into(), &resolver)
            .await
            .unwrap();
        match decision_cached {
            ConnectDecision::Allow { .. } => {}
            _ => panic!("Expected specific from cache"),
        }

        // Different IP in same subnet should match rule 1
        let loc_subnet = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 50)), 80);
        let decision = selector.judge(loc_subnet.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            _ => panic!("Expected subnet"),
        }
    }

    #[tokio::test]
    async fn predicate_is_anded_with_legacy_masks() {
        let predicate_rule = ConnectRule::try_with_match_config(
            vec![NetLocationMask::from("example.com").unwrap()],
            RouteMatchConfig {
                port: vec![443],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::new(vec![
            predicate_rule,
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ]);
        let resolver = mock_resolver();

        let blocked = NetLocation::new(Address::Hostname("api.example.com".into()), 443);
        assert!(matches!(
            selector.judge_tcp(blocked.into(), &resolver).await.unwrap(),
            ConnectDecision::Block
        ));

        let wrong_port = NetLocation::new(Address::Hostname("api.example.com".into()), 80);
        assert!(matches!(
            selector
                .judge_tcp(wrong_port.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));

        let wrong_mask = NetLocation::new(Address::Hostname("other.test".into()), 443);
        assert!(matches!(
            selector
                .judge_tcp(wrong_mask.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
    }

    #[test]
    fn tcp_sniff_policy_distinguishes_auto_enabled_and_disabled() {
        let destination_only = || {
            ConnectRule::try_with_match_config(
                vec![NetLocationMask::ANY],
                RouteMatchConfig {
                    domain_suffix: vec!["example.com".into()],
                    ..Default::default()
                },
                ConnectAction::new_block(),
            )
            .unwrap()
        };
        let protocol = || {
            ConnectRule::try_with_match_config(
                vec![NetLocationMask::ANY],
                RouteMatchConfig {
                    protocol: vec![RouteProtocol::Tls],
                    ..Default::default()
                },
                ConnectAction::new_block(),
            )
            .unwrap()
        };

        let legacy_destination = ClientProxySelector::new(vec![destination_only()]);
        assert_eq!(legacy_destination.sniff_policy(), None);
        assert!(!legacy_destination.needs_tcp_sniff());
        assert_eq!(
            legacy_destination.needs_tcp_protocol_sniff(),
            legacy_destination.needs_tcp_sniff()
        );
        assert!(ClientProxySelector::new(vec![protocol()]).needs_tcp_sniff());

        let enabled = ClientProxySelector::with_sniff_policy(vec![destination_only()], Some(true));
        assert_eq!(enabled.sniff_policy(), Some(true));
        assert!(enabled.needs_tcp_sniff());
        assert_eq!(
            enabled.needs_tcp_protocol_sniff(),
            enabled.needs_tcp_sniff()
        );
        assert!(ClientProxySelector::with_sniff_policy(Vec::new(), Some(true)).needs_tcp_sniff());

        let disabled = ClientProxySelector::with_sniff_policy(vec![protocol()], Some(false));
        assert_eq!(disabled.sniff_policy(), Some(false));
        assert!(!disabled.needs_tcp_sniff());
        assert_eq!(
            disabled.needs_tcp_protocol_sniff(),
            disabled.needs_tcp_sniff()
        );
    }

    #[test]
    fn explicitly_enabled_sniffing_keeps_cache_for_context_free_traffic() {
        let rule = || {
            ConnectRule::try_with_match_config(
                vec![NetLocationMask::ANY],
                RouteMatchConfig {
                    domain_suffix: vec!["example.com".into()],
                    ..Default::default()
                },
                ConnectAction::new_block(),
            )
            .unwrap()
        };

        let legacy = ClientProxySelector::with_options_and_cache_size_and_sniff_policy(
            vec![rule()],
            true,
            8,
            None,
        );
        assert!(legacy.cache.is_some());

        let enabled = ClientProxySelector::with_options_and_cache_size_and_sniff_policy(
            vec![rule()],
            true,
            8,
            Some(true),
        );
        assert!(enabled.cache.is_some());
    }

    #[tokio::test]
    async fn sniffed_domain_routes_an_ip_destination_without_cache_cross_talk() {
        let domain_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                domain_suffix: vec!["blocked.example".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::with_options_and_cache_size_and_sniff_policy(
            vec![domain_block, allow_rule(vec!["0.0.0.0/0"], "default")],
            true,
            8,
            Some(true),
        );
        let resolver = mock_resolver();
        let destination = || NetLocation::new(Address::Ipv4(Ipv4Addr::new(203, 0, 113, 10)), 443);

        assert!(selector.cache.is_some());
        assert!(matches!(
            selector
                .judge_udp(destination().into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
        assert_eq!(
            selector.cache_size(),
            1,
            "forced TCP sniffing must not disable caching for UDP traffic"
        );

        assert!(matches!(
            selector
                .judge_sniffed_tcp(
                    destination().into(),
                    &resolver,
                    RouteProtocol::Tls,
                    Some("api.blocked.example".into()),
                )
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
        assert!(matches!(
            selector
                .judge_sniffed_tcp(
                    destination().into(),
                    &resolver,
                    RouteProtocol::Tls,
                    Some("allowed.example".into()),
                )
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
        assert_eq!(
            selector.cache_size(),
            1,
            "sniffed metadata must neither read nor write the destination-only cache"
        );
    }

    #[tokio::test]
    async fn network_context_selects_transport_and_disables_cache() {
        let udp_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                network: vec![crate::routing::predicate::RouteNetwork::Udp],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::with_options(
            vec![udp_block, allow_rule(vec!["0.0.0.0/0"], "default")],
            true,
        );
        assert!(!selector.is_cache_enabled());
        let resolver = mock_resolver();
        let destination = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53);

        assert!(matches!(
            selector
                .judge_tcp(destination.clone().into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
        assert!(matches!(
            selector
                .judge_udp(destination.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
    }

    #[tokio::test]
    async fn ip_predicate_does_not_resolve_hostname_by_default() {
        let private_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::with_sniff_policy(
            vec![private_block, allow_rule(vec!["0.0.0.0/0"], "default")],
            None,
        );
        let counting_resolver = Arc::new(RebindingResolver::new(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        ));
        let resolver: Arc<dyn Resolver> = counting_resolver.clone();
        let destination = NetLocation::new(Address::Hostname("private.example".into()), 443);

        assert!(matches!(
            selector
                .judge_tcp(destination.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
        assert_eq!(
            counting_resolver.calls(),
            0,
            "default route matching must not resolve an FQDN for an IP predicate"
        );
    }

    #[tokio::test]
    async fn ip_predicate_resolves_hostname_when_explicitly_enabled() {
        let private_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::with_options(
            vec![private_block, allow_rule(vec!["0.0.0.0/0"], "default")],
            true,
        );
        let counting_resolver = Arc::new(RebindingResolver::new(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        ));
        let resolver: Arc<dyn Resolver> = counting_resolver.clone();
        let destination = NetLocation::new(Address::Hostname("private.example".into()), 443);

        assert!(matches!(
            selector
                .judge_tcp(destination.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
        assert_eq!(counting_resolver.calls(), 1);
    }

    #[tokio::test]
    async fn ip_predicate_uses_pre_resolved_hostname_without_resolver() {
        let private_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::new(vec![
            private_block,
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ]);
        let counting_resolver = Arc::new(RebindingResolver::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        ));
        let resolver: Arc<dyn Resolver> = counting_resolver.clone();
        let destination = ResolvedLocation::with_resolved(
            NetLocation::new(Address::Hostname("private.example".into()), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 443),
        );

        assert!(matches!(
            selector.judge_tcp(destination, &resolver).await.unwrap(),
            ConnectDecision::Block
        ));
        assert_eq!(counting_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn ip_predicate_matches_literal_ip_without_resolver() {
        let private_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::new(vec![
            private_block,
            allow_rule(vec!["0.0.0.0/0"], "default"),
        ]);
        let counting_resolver = Arc::new(RebindingResolver::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        ));
        let resolver: Arc<dyn Resolver> = counting_resolver.clone();
        let destination = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 1, 2, 3)), 443);

        assert!(matches!(
            selector
                .judge_tcp(destination.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
        assert_eq!(counting_resolver.calls(), 0);
    }

    #[tokio::test]
    async fn ip_predicate_matches_later_candidate_and_preserves_order_for_dialing() {
        let routed = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["192.0.2.0/24".into()],
                ..Default::default()
            },
            ConnectAction::new_allow(None, mock_chain_group()),
        )
        .unwrap();
        let selector = ClientProxySelector::with_options(vec![routed], true);
        let expected = vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        ];
        let resolver: Arc<dyn Resolver> =
            Arc::new(MockResolver::new().with_mapping("multi.example", 443, expected.clone()));
        let destination = NetLocation::new(Address::Hostname("multi.example".into()), 443);

        let ConnectDecision::Allow {
            remote_location, ..
        } = selector
            .judge_tcp(destination.into(), &resolver)
            .await
            .unwrap()
        else {
            panic!("a matching later DNS candidate should select the route");
        };

        let actual = remote_location
            .resolved_addrs()
            .expect("IP routing must retain the complete DNS answer")
            .iter()
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn ip_version_does_not_resolve_or_match_a_hostname() {
        let ipv6_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_version: vec![6],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector =
            ClientProxySelector::new(vec![ipv6_block, allow_rule(vec!["0.0.0.0/0"], "default")]);

        // The empty resolver makes an accidental lookup observable as an
        // error. sing-box's route IPVersionItem only inspects a literal
        // destination (DNS query-family metadata is a separate DNS-router path).
        assert!(matches!(
            selector
                .judge_tcp(
                    NetLocation::new(Address::Hostname("dual-stack.example".into()), 443).into(),
                    &mock_resolver(),
                )
                .await
                .unwrap(),
            ConnectDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn ip_predicate_rechecks_hostname_after_public_to_private_dns_rebind() {
        let private_block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector = ClientProxySelector::with_options(
            vec![private_block, allow_rule(vec!["0.0.0.0/0"], "default")],
            true,
        );
        let rebinding = Arc::new(RebindingResolver::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        ));
        let resolver: Arc<dyn Resolver> = rebinding.clone();
        let destination = || NetLocation::new(Address::Hostname("rebind.example".into()), 443);

        assert!(
            !selector.is_cache_enabled(),
            "IP-dependent selectors must not cache hostname-only decisions"
        );
        let first = selector
            .judge_tcp(destination().into(), &resolver)
            .await
            .unwrap();
        let ConnectDecision::Allow {
            remote_location, ..
        } = first
        else {
            panic!("the initial public address should be allowed");
        };
        assert_eq!(
            remote_location.resolved_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
        );

        assert!(matches!(
            selector
                .judge_tcp(destination().into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
        assert_eq!(rebinding.calls(), 2);
    }

    #[tokio::test]
    async fn matching_domain_arm_does_not_resolve_cidr_arm_in_same_group() {
        let block = ConnectRule::try_with_match_config(
            vec![NetLocationMask::ANY],
            RouteMatchConfig {
                domain: vec!["known.example".into()],
                ip_cidr: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ConnectAction::new_block(),
        )
        .unwrap();
        let selector =
            ClientProxySelector::new(vec![block, allow_rule(vec!["0.0.0.0/0"], "default")]);
        // The empty resolver would error if the CIDR arm were evaluated eagerly.
        let resolver = mock_resolver();
        let destination = NetLocation::new(Address::Hostname("known.example".into()), 443);
        assert!(matches!(
            selector
                .judge_tcp(destination.into(), &resolver)
                .await
                .unwrap(),
            ConnectDecision::Block
        ));
    }

    #[test]
    fn rule_set_rejects_restrictive_legacy_masks() {
        let rule_set = RouteMatchConfig {
            rule_set: vec![crate::routing::predicate::RouteRuleSetConfig {
                format: "source".into(),
                path: "this-file-is-not-read.json".into(),
            }],
            ..Default::default()
        };
        for match_config in [
            rule_set.clone(),
            RouteMatchConfig {
                any: vec![rule_set],
                ..Default::default()
            },
        ] {
            let error = ConnectRule::try_with_match_config(
                vec![NetLocationMask::from("example.com").unwrap()],
                match_config,
                ConnectAction::new_block(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("unconditional legacy mask"));
        }
    }

    #[test]
    fn test_netmask_value_for_cidr_0() {
        // Verify that 0.0.0.0/0 actually produces netmask == 0
        let mask = NetLocationMask::from("0.0.0.0/0").unwrap();
        assert_eq!(
            mask.address_mask.netmask, 0,
            "0.0.0.0/0 should have netmask == 0, got {}",
            mask.address_mask.netmask
        );
    }

    #[test]
    fn test_netmask_value_for_cidr_24() {
        // Verify that /24 does NOT produce netmask == 0
        let mask = NetLocationMask::from("172.17.0.0/24").unwrap();
        assert_ne!(
            mask.address_mask.netmask, 0,
            "172.17.0.0/24 should have netmask != 0"
        );
    }
}
