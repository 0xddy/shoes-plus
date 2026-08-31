//! Resolver implementation using hickory-dns.
//!
//! Uses ProxyRuntimeProvider for all connections, which handles both direct
//! and proxied connections through ClientChainGroup.

use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::{DnsRequest, Edns};
use hickory_resolver::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{ConnectionProvider, PoolContext, Resolver};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::parsed::IpStrategy;
use crate::dns::proxy_runtime::ProxyRuntimeProvider;
use crate::dns::{
    DnsCachePolicy, DnsClientSubnet, DnsExchangeResponse, DnsQueryCache, DnsQuestion,
    DnsQuestionType,
};
use crate::resolver::Resolver as ShoesResolver;

/// Tuning options for hickory-backed resolvers.
#[derive(Debug, Clone)]
pub struct HickoryResolverOptions {
    pub ip_strategy: IpStrategy,
    pub use_native_roots: bool,
    /// Per-request timeout passed to hickory's ResolverOpts.timeout.
    /// None means use hickory's default.
    pub request_timeout: Option<Duration>,
    /// Timeout for establishing TCP/TLS connections to DNS upstreams.
    pub connect_timeout: Duration,
    /// Number of retry attempts for failed queries.
    pub attempts: usize,
    /// Disable Hickory's response cache for every query in this profile.
    pub disable_cache: bool,
    /// Clamp positive and negative response cache lifetime to this value.
    pub rewrite_ttl: Option<u32>,
    /// Fixed EDNS Client Subnet for this isolated resolver profile.
    pub client_subnet: Option<DnsClientSubnet>,
    /// Go-compatible answer cache shared by every resolver graph in this DNS
    /// client generation.
    pub shared_cache: Option<Arc<DnsQueryCache>>,
    /// Original DNS server tag used by Go's transport-scoped single-flight
    /// lock. Private query-profile variants retain the same value.
    pub transport_tag: Arc<str>,
    /// Set the DNS AD header bit on outgoing questions. This is populated only
    /// by an ordinary system resolver whose resolv.conf requests `trust-ad`.
    pub trust_ad: bool,
}

impl Default for HickoryResolverOptions {
    fn default() -> Self {
        Self {
            ip_strategy: IpStrategy::default(),
            use_native_roots: false,
            request_timeout: Some(Duration::from_secs(5)),
            connect_timeout: Duration::from_secs(5),
            attempts: 2,
            disable_cache: false,
            rewrite_ttl: None,
            client_subnet: None,
            shared_cache: None,
            transport_tag: Arc::from(""),
            trust_ad: false,
        }
    }
}

impl HickoryResolverOptions {
    pub(crate) fn is_pool_compatible_with(&self, other: &Self) -> bool {
        self.ip_strategy == other.ip_strategy
            && self.use_native_roots == other.use_native_roots
            && self.request_timeout == other.request_timeout
            && self.connect_timeout == other.connect_timeout
            && self.attempts == other.attempts
            && self.disable_cache == other.disable_cache
            && self.rewrite_ttl == other.rewrite_ttl
            && self.client_subnet == other.client_subnet
            && self.transport_tag == other.transport_tag
            && self.trust_ad == other.trust_ad
            && match (&self.shared_cache, &other.shared_cache) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

fn attach_client_subnet(request: &mut DnsRequest, client_subnet: Option<DnsClientSubnet>) {
    let Some(client_subnet) = client_subnet else {
        return;
    };
    let options = request.edns.get_or_insert_with(Edns::new).options_mut();
    options.remove(EdnsCode::Subnet);
    options.insert(EdnsOption::Subnet(client_subnet.to_hickory()));
}

fn decorate_system_query(
    request: &mut DnsRequest,
    client_subnet: Option<DnsClientSubnet>,
    trust_ad: bool,
) {
    attach_client_subnet(request, client_subnet);
    if trust_ad {
        request.metadata.authentic_data = true;
    }
}

fn apply_query_profile_options(resolver_opts: &mut ResolverOpts, options: &HickoryResolverOptions) {
    // Hickory's cache is resolver-local and caps positive TTLs at 86400 by
    // default. Go instead owns one 1024-question cache at DNS-client scope, so
    // always bypass Hickory storage and retain the full uint32 wire TTL range.
    resolver_opts.cache_size = 0;
    let max_dns_ttl = Duration::from_secs(u64::from(u32::MAX));
    resolver_opts.positive_min_ttl = Some(Duration::ZERO);
    resolver_opts.positive_max_ttl = Some(max_dns_ttl);
    resolver_opts.negative_min_ttl = Some(Duration::ZERO);
    resolver_opts.negative_max_ttl = Some(max_dns_ttl);

    // RewriteTTL is applied by DnsQueryCache after Exchange, matching Go's
    // response-code filtering and cache-store order. ECS still gets a warm
    // question-cache read, but its cold exchange bypasses cache writes.
    let _ = options;
}

fn apply_runtime_resolver_options(
    resolver_opts: &mut ResolverOpts,
    options: &HickoryResolverOptions,
    preserve_system_query_tuning: bool,
) {
    resolver_opts.ip_strategy = options.ip_strategy.to_hickory();
    if !preserve_system_query_tuning {
        // Explicit upstream transports must never be short-circuited by the
        // machine's hosts file. Besides bypassing the requested upstream, a
        // hosts hit would also silently bypass per-profile ECS behaviour.
        resolver_opts.use_hosts_file = ResolveHosts::Never;
        if let Some(timeout) = options.request_timeout {
            resolver_opts.timeout = timeout;
        }
        resolver_opts.attempts = options.attempts;
    }
    apply_query_profile_options(resolver_opts, options);
}

fn apply_system_transport_security(
    system_options: &mut ResolverOpts,
    profile_options: &mut HickoryResolverOptions,
) {
    system_options.use_hosts_file = ResolveHosts::Never;
    profile_options.use_native_roots = true;
}

fn query_profile_result_cache_ttl(_options: &HickoryResolverOptions) -> Option<Duration> {
    // Hickory owns the authoritative DNS expiry. An outer per-stream cache
    // cannot observe the remaining TTL of a Hickory cache hit and would renew
    // that entry from "now", potentially extending it past its DNS expiry.
    None
}

fn net_error_to_io(error: NetError) -> std::io::Error {
    let kind = match &error {
        NetError::Timeout => std::io::ErrorKind::TimedOut,
        NetError::Io(error) => error.kind(),
        NetError::NoConnections => std::io::ErrorKind::NotConnected,
        NetError::Busy => std::io::ErrorKind::WouldBlock,
        NetError::H2(error) => error
            .get_io()
            .map_or(std::io::ErrorKind::ConnectionAborted, std::io::Error::kind),
        NetError::H3(_) | NetError::QuinnConnection(_) => std::io::ErrorKind::ConnectionAborted,
        NetError::QuinnConnect(_) | NetError::QuinnStreamError(_) => {
            std::io::ErrorKind::NotConnected
        }
        NetError::QuinnReadError(_) => std::io::ErrorKind::ConnectionReset,
        NetError::QuinnWriteError(_) => std::io::ErrorKind::BrokenPipe,
        NetError::Decode(_)
        | NetError::Proto(_)
        | NetError::QueryCaseMismatch
        | NetError::ParseInt(_)
        | NetError::QuicMessageIdNot0(_)
        | NetError::QuinnConfigError(_)
        | NetError::QuinnTlsConfigError(_)
        | NetError::QuinnUnknownStreamError
        | NetError::RustlsError(_) => std::io::ErrorKind::InvalidData,
        NetError::Dns(_) if error.is_nx_domain() => std::io::ErrorKind::NotFound,
        _ => std::io::ErrorKind::Other,
    };

    // Keep NetError itself as the source. In particular, do not stringify an
    // underlying io::Error: RefreshingResolver needs its ErrorKind and callers
    // still need the transport/protocol cause for diagnostics.
    std::io::Error::new(kind, error)
}

#[derive(Clone)]
struct QueryProfileDnsHandle<H> {
    inner: H,
    client_subnet: Option<DnsClientSubnet>,
    trust_ad: bool,
}

impl<H: DnsHandle> DnsHandle for QueryProfileDnsHandle<H> {
    type Response = H::Response;
    type Runtime = H::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        self.inner.is_verifying_dnssec()
    }

    fn is_using_edns(&self) -> bool {
        self.inner.is_using_edns()
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        decorate_system_query(&mut request, self.client_subnet, self.trust_ad);
        self.inner.send(request)
    }
}

/// Connection provider decorator that injects ECS before a request is encoded
/// or encrypted. The same implementation therefore covers UDP, TCP, DoT,
/// DoH, DoQ, and DoH3 without modifying their transports.
#[derive(Clone)]
struct QueryProfileConnectionProvider {
    inner: ProxyRuntimeProvider,
    client_subnet: Option<DnsClientSubnet>,
    trust_ad: bool,
}

impl ConnectionProvider for QueryProfileConnectionProvider {
    type Conn = QueryProfileDnsHandle<<ProxyRuntimeProvider as ConnectionProvider>::Conn>;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send>>;
    type RuntimeProvider = <ProxyRuntimeProvider as ConnectionProvider>::RuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        context: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let future = <ProxyRuntimeProvider as ConnectionProvider>::new_connection(
            &self.inner,
            ip,
            config,
            context,
        )?;
        let client_subnet = self.client_subnet;
        let trust_ad = self.trust_ad;
        Ok(Box::pin(async move {
            future.await.map(|inner| QueryProfileDnsHandle {
                inner,
                client_subnet,
                trust_ad,
            })
        }))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        <ProxyRuntimeProvider as ConnectionProvider>::runtime_provider(&self.inner)
    }
}

/// Resolver implementation using hickory-dns.
/// Uses ProxyRuntimeProvider for all connections (both direct and proxied).
pub struct HickoryResolver {
    inner: Resolver<QueryProfileConnectionProvider>,
    description: String,
    ip_strategy: IpStrategy,
    query_cache: Option<Arc<DnsQueryCache>>,
    query_policy: DnsCachePolicy,
    transport_tag: Arc<str>,
    result_cache_ttl: Option<Duration>,
}

impl Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("description", &self.description)
            .field("ip_strategy", &self.ip_strategy)
            .field("query_policy", &self.query_policy)
            .field("transport_tag", &self.transport_tag)
            .field("result_cache_ttl", &self.result_cache_ttl)
            .finish()
    }
}

impl HickoryResolver {
    /// Perform one uncached transport exchange. Ordered system transports wrap
    /// their complete TLS/plain/next-server sequence in the outer shared-cache
    /// single-flight and use this as the raw per-hop operation.
    pub(crate) fn exchange_dns_question(
        &self,
        name: Name,
        question_type: DnsQuestionType,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DnsExchangeResponse>> + Send>> {
        Box::pin(exchange_question(self.inner.clone(), name, question_type))
    }

    pub(crate) fn system_from_configuration(
        config: ResolverConfig,
        mut system_options: ResolverOpts,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        mut options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        // Advanced local resolution performs its own hosts lookup so it can
        // apply Go's 600-second hosts TTL through the shared question cache.
        apply_system_transport_security(&mut system_options, &mut options);
        Self::build_with_config(
            config,
            chain_group,
            bootstrap,
            options,
            Some(system_options),
            "system".to_string(),
        )
    }

    /// Build one direct systemd-resolved transport. Direct transports must not
    /// consult the hosts file (which would bypass ECS/query-profile controls),
    /// and DoT always authenticates with the platform native root store just
    /// like sing-box's resolved transport.
    pub(crate) fn system_transport_from_configuration(
        config: ResolverConfig,
        mut system_options: ResolverOpts,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        mut options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        apply_system_transport_security(&mut system_options, &mut options);
        Self::build_with_config(
            config,
            chain_group,
            bootstrap,
            options,
            Some(system_options),
            description,
        )
    }

    /// Create a UDP DNS resolver.
    /// Note: UDP uses the chain_group but only works with direct chains.
    pub fn udp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::udp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("udp://{}", addr),
        )
    }

    /// Create a TCP DNS resolver.
    pub fn tcp(
        addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tcp();
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tcp://{}", addr),
        )
    }

    /// Create a DNS-over-TLS resolver.
    pub fn tls(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::tls(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("tls://{}#{}", addr, server_name),
        )
    }

    /// Create a DNS-over-QUIC resolver (RFC 9250).
    ///
    /// Direct chains use a native UDP socket. Other UDP-capable chains are
    /// exposed to Quinn as a fixed-destination datagram socket, preserving one
    /// QUIC packet per proxy message.
    pub fn quic(
        addr: SocketAddr,
        server_name: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        if !chain_group.supports_udp() {
            return Err(std::io::Error::other(
                "DNS-over-QUIC client_chain has no UDP-capable chain",
            ));
        }

        let mut conn_config = ConnectionConfig::quic(server_name.clone());
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("quic://{}#{}", addr, server_name),
        )
    }

    /// Create a DNS-over-HTTPS resolver.
    pub fn https(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        let mut conn_config = ConnectionConfig::https(server_name.clone(), Some(path));
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("https://{}", server_name),
        )
    }

    /// Create a DNS-over-HTTP/3 resolver.
    pub fn h3(
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
    ) -> std::io::Result<Self> {
        if !chain_group.supports_udp() {
            return Err(std::io::Error::other(
                "DNS-over-HTTP/3 client_chain has no UDP-capable chain",
            ));
        }
        // Cloudflare has a broken GREASE implementation.
        // See: https://github.com/hyperium/h3/issues/206
        let protocol = ProtocolConfig::H3 {
            server_name: server_name.clone(),
            path,
            disable_grease: true,
        };
        let mut conn_config = ConnectionConfig::new(protocol);
        conn_config.port = addr.port();
        Self::build(
            addr.ip(),
            conn_config,
            chain_group,
            bootstrap,
            options,
            format!("h3://{}", server_name),
        )
    }

    /// Create a resolver with multiple nameservers in a single hickory pool.
    /// Hickory's NameServerPool handles ordering and parallelism internally,
    /// avoiding the sequential fallback behavior of CompositeResolver.
    pub fn build_pooled(
        servers: Vec<(std::net::IpAddr, ConnectionConfig)>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_configs: Vec<NameServerConfig> = servers
            .into_iter()
            .map(|(ip, conn_config)| NameServerConfig::new(ip, true, vec![conn_config]))
            .collect();

        Self::build_with_ns_configs(ns_configs, chain_group, bootstrap, options, description)
    }

    fn build(
        ip: std::net::IpAddr,
        conn_config: ConnectionConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        let ns_config = NameServerConfig::new(ip, true, vec![conn_config]);
        Self::build_with_ns_configs(
            vec![ns_config],
            chain_group,
            bootstrap,
            options,
            description,
        )
    }

    fn build_with_ns_configs(
        ns_configs: Vec<NameServerConfig>,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        description: String,
    ) -> std::io::Result<Self> {
        for connection in ns_configs
            .iter()
            .flat_map(|server| server.connections.iter())
        {
            match &connection.protocol {
                ProtocolConfig::Udp if !chain_group.is_direct_only() => {
                    return Err(std::io::Error::other(
                        "UDP DNS only supports a direct client_chain (optionally with bind_interface)",
                    ));
                }
                ProtocolConfig::Quic { .. } | ProtocolConfig::H3 { .. }
                    if !chain_group.supports_udp() =>
                {
                    return Err(std::io::Error::other(
                        "QUIC DNS client_chain has no UDP-capable chain",
                    ));
                }
                _ => {}
            }
        }

        let config = ResolverConfig::from_parts(None, vec![], ns_configs);
        Self::build_with_config(config, chain_group, bootstrap, options, None, description)
    }

    fn build_with_config(
        config: ResolverConfig,
        chain_group: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn ShoesResolver>,
        options: HickoryResolverOptions,
        base_options: Option<ResolverOpts>,
        description: String,
    ) -> std::io::Result<Self> {
        let result_cache_ttl = query_profile_result_cache_ttl(&options);
        let query_cache = options.shared_cache.clone();
        let query_policy = DnsCachePolicy {
            disable_cache: options.disable_cache,
            rewrite_ttl: options.rewrite_ttl,
            client_subnet: options.client_subnet.is_some(),
        };
        let transport_tag = options.transport_tag.clone();
        let provider = QueryProfileConnectionProvider {
            inner: ProxyRuntimeProvider::with_bootstrap(
                chain_group,
                bootstrap,
                options.connect_timeout,
            ),
            client_subnet: options.client_subnet,
            trust_ad: options.trust_ad,
        };

        let mut builder = Resolver::builder_with_config(config, provider);
        let resolver_opts = builder.options_mut();
        let preserve_system_query_tuning = base_options.is_some();
        if let Some(base_options) = base_options {
            // Preserve platform-derived system options first. Shoes then
            // overrides only lookup/profile controls that system resolution
            // cannot expose. In particular, do not let Shoes' serde defaults
            // (timeout=5s, attempts=1) silently replace platform timeout and
            // retry settings for an advanced `system` profile.
            *resolver_opts = base_options;
        }
        apply_runtime_resolver_options(resolver_opts, &options, preserve_system_query_tuning);
        let builder = builder.with_tls_config(crate::rustls_config_util::create_dns_client_config(
            options.use_native_roots,
        ));
        let resolver = builder
            .build()
            .map_err(|e| std::io::Error::other(format!("failed to build resolver: {e}")))?;

        Ok(Self {
            inner: resolver,
            description,
            ip_strategy: options.ip_strategy,
            query_cache,
            query_policy,
            transport_tag,
            result_cache_ttl,
        })
    }
}

fn lookup_min_ttl(lookup: &Lookup) -> Duration {
    let mut minimum = 0;
    for record in lookup
        .answers()
        .iter()
        .chain(lookup.authorities())
        .chain(lookup.additionals())
    {
        if record.record_type() == RecordType::OPT {
            continue;
        }
        if minimum == 0 || record.ttl > 0 && record.ttl < minimum {
            minimum = record.ttl;
        }
    }
    Duration::from_secs(u64::from(minimum))
}

fn negative_response_ttl(no_records: &NoRecords) -> Duration {
    // A non-zero SOA-derived lifetime is exact: both Hickory and Go use
    // min(SOA TTL, SOA MINIMUM). Without one, Go scans Answer, Authority, and
    // Additional (except OPT) for the smallest non-zero TTL. Hickory's
    // NoRecords error does not retain Answer or arbitrary Additional records
    // (only Authority and NS referral glue), so a minimum computed from that
    // visible subset could outlive an omitted record. TTL zero deliberately
    // bypasses DnsQueryCache and is the only non-stale fallback available
    // without replacing Hickory's high-level lookup pipeline.
    Duration::from_secs(u64::from(no_records.negative_ttl.unwrap_or(0)))
}

fn lookup_addresses(lookup: &Lookup) -> Arc<[IpAddr]> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(IpAddr::V4(address.0)),
            RData::AAAA(address) => Some(IpAddr::V6(address.0)),
            _ => None,
        })
        .collect::<Vec<_>>()
        .into()
}

async fn exchange_question(
    resolver: Resolver<QueryProfileConnectionProvider>,
    name: Name,
    question_type: DnsQuestionType,
) -> std::io::Result<DnsExchangeResponse> {
    let record_type = match question_type {
        DnsQuestionType::A => RecordType::A,
        DnsQuestionType::Aaaa => RecordType::AAAA,
    };
    match resolver.lookup(name, record_type).await {
        Ok(lookup) => Ok(DnsExchangeResponse::success(
            lookup_addresses(&lookup),
            lookup_min_ttl(&lookup),
        )),
        Err(error) => match &error {
            NetError::Dns(DnsError::NoRecordsFound(no_records))
                if no_records.response_code
                    == hickory_resolver::proto::op::ResponseCode::NXDomain =>
            {
                Ok(DnsExchangeResponse::nx_domain(
                    negative_response_ttl(no_records),
                    net_error_to_io(error),
                ))
            }
            NetError::Dns(DnsError::NoRecordsFound(no_records))
                if no_records.response_code
                    == hickory_resolver::proto::op::ResponseCode::NoError =>
            {
                // NODATA is a successful empty lookup and follows the SOA
                // negative lifetime, just like sing-box's response cache.
                Ok(DnsExchangeResponse::success(
                    Arc::<[IpAddr]>::from([]),
                    negative_response_ttl(no_records),
                ))
            }
            _ => Err(net_error_to_io(error)),
        },
    }
}

async fn resolve_question(
    resolver: Resolver<QueryProfileConnectionProvider>,
    cache: Option<Arc<DnsQueryCache>>,
    name: Name,
    question_name: Arc<str>,
    question_type: DnsQuestionType,
    transport_tag: Arc<str>,
    policy: DnsCachePolicy,
) -> std::io::Result<Arc<[IpAddr]>> {
    let question = DnsQuestion::new(question_name, question_type);
    if let Some(cache) = cache {
        cache
            .resolve(question, transport_tag, policy, move || {
                exchange_question(resolver, name, question_type)
            })
            .await
    } else {
        exchange_question(resolver, name, question_type)
            .await?
            .into_result()
    }
}

fn merge_dual_stack_results(
    ipv4: std::io::Result<Arc<[IpAddr]>>,
    ipv6: std::io::Result<Arc<[IpAddr]>>,
    ipv6_first: bool,
) -> std::io::Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    let mut first_error = None;
    let mut append = |result: std::io::Result<Arc<[IpAddr]>>| match result {
        Ok(result) => addresses.extend_from_slice(&result),
        Err(error) => {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    };
    if ipv6_first {
        append(ipv6);
        append(ipv4);
    } else {
        append(ipv4);
        append(ipv6);
    }
    if addresses.is_empty()
        && let Some(error) = first_error
    {
        return Err(error);
    }
    Ok(addresses)
}

impl ShoesResolver for HickoryResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let name = location.address().to_string();
        let question_name: Arc<str> = if name.ends_with('.') {
            Arc::from(name.as_str())
        } else {
            Arc::from(format!("{name}."))
        };
        let mut dns_name = match Name::from_utf8(&name) {
            Ok(name) => name,
            Err(error) => {
                return Box::pin(std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error,
                ))));
            }
        };
        dns_name.set_fqdn(true);
        let port = location.port();
        let description = self.description.clone();
        let resolver = self.inner.clone();
        let ip_strategy = self.ip_strategy;
        let cache = self.query_cache.clone();
        let policy = self.query_policy;
        let transport_tag = self.transport_tag.clone();

        Box::pin(async move {
            let started = std::time::Instant::now();
            let query = |question_type| {
                resolve_question(
                    resolver.clone(),
                    cache.clone(),
                    dns_name.clone(),
                    question_name.clone(),
                    question_type,
                    transport_tag.clone(),
                    policy,
                )
            };

            let addresses = match ip_strategy {
                IpStrategy::Ipv4Only => query(DnsQuestionType::A)
                    .await
                    .map(|result| result.to_vec()),
                IpStrategy::Ipv6Only => query(DnsQuestionType::Aaaa)
                    .await
                    .map(|result| result.to_vec()),
                IpStrategy::Ipv4AndIpv6 | IpStrategy::Ipv6AndIpv4 => {
                    let (ipv4, ipv6) =
                        tokio::join!(query(DnsQuestionType::A), query(DnsQuestionType::Aaaa));
                    merge_dual_stack_results(
                        ipv4,
                        ipv6,
                        matches!(ip_strategy, IpStrategy::Ipv6AndIpv4),
                    )
                }
                IpStrategy::Ipv4ThenIpv6 | IpStrategy::Ipv6ThenIpv4 => {
                    let (first, second) = if matches!(ip_strategy, IpStrategy::Ipv6ThenIpv4) {
                        (DnsQuestionType::Aaaa, DnsQuestionType::A)
                    } else {
                        (DnsQuestionType::A, DnsQuestionType::Aaaa)
                    };
                    match query(first).await {
                        Ok(result) if !result.is_empty() => Ok(result.to_vec()),
                        first_result => match query(second).await {
                            Ok(result) if !result.is_empty() => Ok(result.to_vec()),
                            Ok(_) => first_result.map(|result| result.to_vec()),
                            Err(second_error) => first_result
                                .map(|result| result.to_vec())
                                .and_then(|result| {
                                    if result.is_empty() {
                                        Err(second_error)
                                    } else {
                                        Ok(result)
                                    }
                                }),
                        },
                    }
                }
            }
            .map_err(|error| {
                log::warn!(
                    "DNS lookup failed via {}: {}:{} in {:?}: {}",
                    description,
                    name,
                    port,
                    started.elapsed(),
                    error
                );
                error
            })?;

            let addrs: Vec<SocketAddr> = addresses
                .into_iter()
                .filter(|ip| !ip.is_unspecified())
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {name}"
                )));
            }

            let elapsed = started.elapsed();
            if elapsed > Duration::from_millis(500) {
                log::info!(
                    "slow DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            } else {
                log::debug!(
                    "DNS lookup via {}: {}:{} -> {:?} in {:?}",
                    description,
                    name,
                    port,
                    addrs,
                    elapsed
                );
            }
            Ok(addrs)
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        self.result_cache_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection,
    };
    use crate::option_util::{NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_client_chain_group;

    fn single_proxy_chain(protocol: ClientProxyConfig) -> Arc<ClientChainGroup> {
        let resolver: Arc<dyn ShoesResolver> = Arc::new(NativeResolver::new());
        let config = ClientConfig {
            address: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
            protocol,
            ..Default::default()
        };
        Arc::new(build_client_chain_group(
            NoneOrSome::One(ClientChain {
                hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
            }),
            resolver,
        ))
    }

    #[test]
    fn test_hickory_resolver_options_default() {
        let opts = HickoryResolverOptions::default();
        assert_eq!(opts.ip_strategy, IpStrategy::default());
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(5)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(5));
        assert_eq!(opts.attempts, 2);
    }

    #[test]
    fn test_hickory_resolver_options_zero_timeout() {
        let opts = HickoryResolverOptions {
            request_timeout: None,
            ..Default::default()
        };
        assert!(opts.request_timeout.is_none());
    }

    #[test]
    fn test_hickory_resolver_options_custom() {
        let opts = HickoryResolverOptions {
            ip_strategy: IpStrategy::Ipv4Only,
            use_native_roots: true,
            request_timeout: Some(Duration::from_secs(3)),
            connect_timeout: Duration::from_secs(1),
            attempts: 1,
            disable_cache: false,
            rewrite_ttl: None,
            client_subnet: None,
            shared_cache: None,
            transport_tag: Arc::from("test"),
            trust_ad: false,
        };
        assert_eq!(opts.ip_strategy, IpStrategy::Ipv4Only);
        assert!(opts.use_native_roots);
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(3)));
        assert_eq!(opts.connect_timeout, Duration::from_secs(1));
        assert_eq!(opts.attempts, 1);
    }

    #[test]
    fn system_profile_preserves_platform_timeout_and_attempts() {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_secs(17);
        resolver_opts.attempts = 4;
        resolver_opts.use_hosts_file = ResolveHosts::Always;
        let profile = HickoryResolverOptions {
            request_timeout: Some(Duration::from_secs(5)),
            attempts: 1,
            disable_cache: true,
            rewrite_ttl: Some(60),
            ..HickoryResolverOptions::default()
        };

        apply_runtime_resolver_options(&mut resolver_opts, &profile, true);

        assert_eq!(resolver_opts.timeout, Duration::from_secs(17));
        assert_eq!(resolver_opts.attempts, 4);
        assert_eq!(resolver_opts.use_hosts_file, ResolveHosts::Always);
        assert_eq!(resolver_opts.cache_size, 0);
        assert_eq!(resolver_opts.positive_min_ttl, Some(Duration::ZERO));
        assert_eq!(
            resolver_opts.negative_max_ttl,
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
    }

    #[test]
    fn custom_upstream_never_uses_the_system_hosts_file() {
        let mut resolver_opts = ResolverOpts::default();
        assert_eq!(resolver_opts.use_hosts_file, ResolveHosts::Auto);

        apply_runtime_resolver_options(
            &mut resolver_opts,
            &HickoryResolverOptions::default(),
            false,
        );

        assert_eq!(resolver_opts.use_hosts_file, ResolveHosts::Never);
    }

    #[test]
    fn resolved_direct_transport_forces_native_roots_and_bypasses_hosts() {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.use_hosts_file = ResolveHosts::Always;
        let mut profile = HickoryResolverOptions {
            use_native_roots: false,
            ..HickoryResolverOptions::default()
        };

        apply_system_transport_security(&mut resolver_opts, &mut profile);

        assert_eq!(resolver_opts.use_hosts_file, ResolveHosts::Never);
        assert!(profile.use_native_roots);
    }

    #[test]
    fn hickory_network_errors_keep_refreshable_io_kinds_and_sources() {
        let timeout = net_error_to_io(NetError::Timeout);
        assert_eq!(timeout.kind(), std::io::ErrorKind::TimedOut);
        assert!(timeout.get_ref().unwrap().is::<NetError>());

        let reset = net_error_to_io(NetError::Io(Arc::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset by test upstream",
        ))));
        assert_eq!(reset.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(reset.get_ref().unwrap().is::<NetError>());

        let unavailable = net_error_to_io(NetError::NoConnections);
        assert_eq!(unavailable.kind(), std::io::ErrorKind::NotConnected);
        assert!(unavailable.get_ref().unwrap().is::<NetError>());

        let busy = net_error_to_io(NetError::Busy);
        assert_eq!(busy.kind(), std::io::ErrorKind::WouldBlock);

        let h2_stream = net_error_to_io(NetError::H2(Arc::new(h2::Reason::INTERNAL_ERROR.into())));
        assert_eq!(h2_stream.kind(), std::io::ErrorKind::ConnectionAborted);

        let closed_quic_stream =
            net_error_to_io(NetError::QuinnStreamError(quinn::ClosedStream::default()));
        assert_eq!(closed_quic_stream.kind(), std::io::ErrorKind::NotConnected);
    }

    #[test]
    fn query_profile_configures_hickory_and_outer_cache_lifetimes() {
        let profile = HickoryResolverOptions {
            rewrite_ttl: Some(0),
            ..Default::default()
        };
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.cache_size = 4096;
        apply_query_profile_options(&mut resolver_opts, &profile);
        assert_eq!(resolver_opts.cache_size, 0);
        assert_eq!(resolver_opts.positive_min_ttl, Some(Duration::ZERO));
        assert_eq!(
            resolver_opts.positive_max_ttl,
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
        assert_eq!(resolver_opts.negative_min_ttl, Some(Duration::ZERO));
        assert_eq!(
            resolver_opts.negative_max_ttl,
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
        assert_eq!(query_profile_result_cache_ttl(&profile), None);

        let ecs_profile = HickoryResolverOptions {
            client_subnet: Some("192.0.2.7/24".parse().unwrap()),
            ..Default::default()
        };
        apply_query_profile_options(&mut resolver_opts, &ecs_profile);
        assert_eq!(resolver_opts.cache_size, 0);
        assert_eq!(query_profile_result_cache_ttl(&ecs_profile), None);

        let disabled_profile = HickoryResolverOptions {
            disable_cache: true,
            ..Default::default()
        };
        assert_eq!(query_profile_result_cache_ttl(&disabled_profile), None);
        assert_eq!(
            query_profile_result_cache_ttl(&HickoryResolverOptions::default()),
            None
        );
    }

    #[test]
    fn cache_lifetime_uses_all_dns_sections_without_hickory_day_cap() {
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::Record;
        use hickory_resolver::proto::rr::rdata::{A, AAAA, NS};

        let name = Name::from_utf8("ttl.example.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let answer = Record::from_rdata(
            name.clone(),
            200_000,
            RData::A(A("192.0.2.1".parse().unwrap())),
        );
        let mut lookup = Lookup::new_with_deadline(
            query,
            [answer],
            std::time::Instant::now() + Duration::from_secs(200_000),
        );
        lookup.extend_authorities([Record::from_rdata(
            name.clone(),
            120_000,
            RData::NS(NS(Name::from_utf8("ns.example.").unwrap())),
        )]);
        lookup.extend_additionals([
            Record::from_rdata(name.clone(), 0, RData::A(A("192.0.2.2".parse().unwrap()))),
            Record::from_rdata(
                name,
                90_000,
                RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
            ),
        ]);

        assert_eq!(lookup_min_ttl(&lookup), Duration::from_secs(90_000));
        assert!(lookup_min_ttl(&lookup) > Duration::from_secs(86_400));
    }

    #[test]
    fn negative_lifetime_uses_nonzero_soa_or_safely_bypasses_cache() {
        use hickory_resolver::net::ForwardNSData;
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::Record;
        use hickory_resolver::proto::rr::rdata::{A, NS};

        let name = Name::from_utf8("missing.example.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        let authority = Record::from_rdata(
            name.clone(),
            45,
            RData::NS(NS(Name::from_utf8("ns.example.").unwrap())),
        );
        let glue = Record::from_rdata(
            Name::from_utf8("ns.example.").unwrap(),
            15,
            RData::A(A("192.0.2.53".parse().unwrap())),
        );
        let mut no_records = NoRecords::new(query, ResponseCode::NXDomain);
        no_records.authorities = Some(Arc::from([authority.clone()]));
        no_records.ns = Some(Arc::from([ForwardNSData {
            ns: authority,
            glue: Arc::from([glue]),
        }]));
        assert_eq!(negative_response_ttl(&no_records), Duration::ZERO);

        no_records.negative_ttl = Some(7);
        assert_eq!(negative_response_ttl(&no_records), Duration::from_secs(7));
        no_records.negative_ttl = Some(0);
        assert_eq!(
            negative_response_ttl(&no_records),
            Duration::ZERO,
            "a zero SOA lifetime cannot safely fall back to Hickory's incomplete record subset"
        );
    }

    #[test]
    fn dual_stack_returns_a_partial_success_and_preserves_family_order() {
        let ipv4 = IpAddr::from([192, 0, 2, 1]);
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            merge_dual_stack_results(
                Ok(Arc::from([ipv4])),
                Err(std::io::Error::other("AAAA failed")),
                false,
            )
            .unwrap(),
            vec![ipv4]
        );
        assert_eq!(
            merge_dual_stack_results(Ok(Arc::from([ipv4])), Ok(Arc::from([ipv6])), true,).unwrap(),
            vec![ipv6, ipv4]
        );
    }

    #[test]
    fn ecs_is_inserted_once_and_replaces_an_existing_subnet() {
        let mut request: DnsRequest = hickory_resolver::proto::op::Message::query().into();
        attach_client_subnet(&mut request, Some("192.0.2.7/24".parse().unwrap()));
        attach_client_subnet(&mut request, Some("2001:db8::1/64".parse().unwrap()));

        let options = request.edns.as_ref().unwrap().options();
        assert_eq!(options.get_all(EdnsCode::Subnet).len(), 1);
        let Some(EdnsOption::Subnet(subnet)) = options.get(EdnsCode::Subnet) else {
            panic!("ECS option missing");
        };
        assert_eq!(subnet.addr(), "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(subnet.source_prefix(), 64);
        assert_eq!(subnet.scope_prefix(), 0);
    }

    #[test]
    fn system_trust_ad_sets_the_authenticated_data_header_bit() {
        let mut request: DnsRequest = hickory_resolver::proto::op::Message::query().into();
        assert!(!request.metadata.authentic_data);

        decorate_system_query(&mut request, None, true);

        assert!(request.metadata.authentic_data);
    }

    #[test]
    fn quic_dns_accepts_udp_capable_proxy_chain_and_rejects_tcp_only_chain() {
        let bootstrap: Arc<dyn ShoesResolver> = Arc::new(NativeResolver::new());
        let server_addr: SocketAddr = "127.0.0.1:853".parse().unwrap();
        let server_name: Arc<str> = Arc::from("dns.example.com");

        let vless = single_proxy_chain(ClientProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            udp_enabled: true,
            packet_encoding: None,
            h2mux: None,
        });
        HickoryResolver::quic(
            server_addr,
            server_name.clone(),
            vless,
            bootstrap.clone(),
            HickoryResolverOptions::default(),
        )
        .expect("UDP-capable proxy must be accepted for DoQ");

        let h3_vless = single_proxy_chain(ClientProxyConfig::Vless {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            udp_enabled: true,
            packet_encoding: None,
            h2mux: None,
        });
        HickoryResolver::h3(
            server_addr,
            server_name.clone(),
            Arc::from("/dns-query"),
            h3_vless,
            bootstrap.clone(),
            HickoryResolverOptions::default(),
        )
        .expect("UDP-capable proxy must be accepted for DoH3");

        let socks = single_proxy_chain(ClientProxyConfig::Socks {
            username: None,
            password: None,
        });
        let error = HickoryResolver::quic(
            server_addr,
            server_name,
            socks,
            bootstrap,
            HickoryResolverOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("no UDP-capable chain"));

        let h3_socks = single_proxy_chain(ClientProxyConfig::Socks {
            username: None,
            password: None,
        });
        let error = HickoryResolver::h3(
            server_addr,
            Arc::from("dns.example.com"),
            Arc::from("/dns-query"),
            h3_socks,
            Arc::new(NativeResolver::new()),
            HickoryResolverOptions::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no UDP-capable chain"));
    }
}
