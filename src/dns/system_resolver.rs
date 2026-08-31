//! Ordered direct transports for advanced system DNS profiles.
//!
//! systemd-resolved's opportunistic mode is deliberately TLS-first. Hickory's
//! `OpportunisticEncryption` group probes plaintext UDP first, so this module
//! composes one TLS resolver and one plaintext UDP-with-TCP-truncation resolver
//! per server and performs the narrow transport-only fallback itself.

use std::fmt::Debug;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Hosts;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts,
    ServerOrderingStrategy,
};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::address::NetLocation;
use crate::client_proxy_chain::ClientChainGroup;
use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::dns::parsed::IpStrategy;
use crate::dns::system_config::{
    ResolvedDnsOverTlsMode, ResolvedNameServer, SystemConfiguration, SystemdResolvedConfiguration,
};
use crate::dns::{
    DnsCachePolicy, DnsExchangeResponse, DnsQueryCache, DnsQuestion, DnsQuestionType,
};
use crate::resolver::{Resolver, is_connection_error_kind};
use crate::tcp::chain_builder::build_bound_direct_chain_group;

pub(crate) fn build_system_resolver(
    configuration: SystemConfiguration,
    system_options: ResolverOpts,
    configured_chain: Arc<ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    profile_options: HickoryResolverOptions,
) -> std::io::Result<Arc<dyn Resolver>> {
    match configuration {
        SystemConfiguration::Resolver(config) => {
            let mut system_options = system_options;
            normalize_ordinary_system_options(&mut system_options);
            let mut profile_options = profile_options;
            profile_options.trust_ad = config.trust_ad;
            let transport = Arc::new(HickoryResolver::system_from_configuration(
                config.resolver,
                system_options,
                configured_chain,
                bootstrap,
                profile_options.clone(),
            )?);
            Ok(Arc::new(OrderedSystemResolver::new(
                "platform".to_string(),
                ResolvedDnsOverTlsMode::No,
                vec![OrderedServer {
                    primary: transport,
                    fallback: None,
                    description: "system".to_string(),
                }],
                profile_options,
                true,
            )))
        }
        SystemConfiguration::SystemdResolved(config) => {
            build_systemd_resolved(config, system_options, bootstrap, profile_options)
        }
    }
}

fn normalize_ordinary_system_options(options: &mut ResolverOpts) {
    // Hickory defaults to racing two upstreams and ranking them by runtime
    // statistics. Go's local transport tries resolv.conf servers serially in
    // user order, rotating only when `options rotate` was explicitly set.
    options.num_concurrent_reqs = 1;
    if options.server_ordering_strategy != ServerOrderingStrategy::RoundRobin {
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    }
}

fn build_systemd_resolved(
    configuration: SystemdResolvedConfiguration,
    system_options: ResolverOpts,
    bootstrap: Arc<dyn Resolver>,
    profile_options: HickoryResolverOptions,
) -> std::io::Result<Arc<dyn Resolver>> {
    if configuration.servers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "systemd-resolved default link has no usable DNS servers",
        ));
    }

    // OrderedSystemResolver owns the per-server and TLS-to-plaintext retry
    // sequence. A Hickory transport must therefore perform exactly one wire
    // exchange; otherwise one unavailable DoT endpoint is retried before the
    // Go-compatible plaintext downgrade or next-server step can run.
    let system_options = systemd_transport_options(system_options);

    // Go's resolved transport binds both TCP/TLS and UDP to the default link.
    // This also supplies the interface context which Hickory's IpAddr-only
    // nameserver representation cannot retain for IPv6 link-local addresses.
    let chain = Arc::new(build_bound_direct_chain_group(
        configuration.interface.clone(),
        bootstrap.clone(),
    ));
    let mut servers = Vec::with_capacity(configuration.servers.len());

    for (index, server) in configuration.servers.iter().enumerate() {
        let (primary_connections, fallback_connections) =
            resolved_server_connections(server, configuration.dns_over_tls);
        let primary_description = transport_description(
            &configuration.interface,
            index,
            server,
            &primary_connections[0].protocol,
        );
        let primary = build_transport(
            &configuration.base_config,
            system_options.clone(),
            server,
            primary_connections,
            chain.clone(),
            bootstrap.clone(),
            profile_options.clone(),
            primary_description.clone(),
        )?;
        let fallback = fallback_connections
            .map(|connections| {
                let description = transport_description(
                    &configuration.interface,
                    index,
                    server,
                    &connections[0].protocol,
                );
                build_transport(
                    &configuration.base_config,
                    system_options.clone(),
                    server,
                    connections,
                    chain.clone(),
                    bootstrap.clone(),
                    profile_options.clone(),
                    description,
                )
            })
            .transpose()?;
        servers.push(OrderedServer {
            primary,
            fallback,
            description: primary_description,
        });
    }

    Ok(Arc::new(OrderedSystemResolver::new(
        configuration.interface,
        configuration.dns_over_tls,
        servers,
        profile_options,
        false,
    )))
}

fn systemd_transport_options(mut options: ResolverOpts) -> ResolverOpts {
    options.attempts = 0;
    options
}

#[allow(clippy::too_many_arguments)]
fn build_transport(
    base_config: &ResolverConfig,
    system_options: ResolverOpts,
    server: &ResolvedNameServer,
    connections: Vec<ConnectionConfig>,
    chain: Arc<ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    profile_options: HickoryResolverOptions,
    description: String,
) -> std::io::Result<Arc<dyn SystemQuestionTransport>> {
    let (domain, search, _) = base_config.clone().into_parts();
    let config = ResolverConfig::from_parts(
        domain,
        search,
        vec![NameServerConfig::new(server.address, true, connections)],
    );
    Ok(Arc::new(
        HickoryResolver::system_transport_from_configuration(
            config,
            system_options,
            chain,
            bootstrap,
            profile_options,
            description,
        )?,
    ))
}

fn resolved_server_connections(
    server: &ResolvedNameServer,
    mode: ResolvedDnsOverTlsMode,
) -> (Vec<ConnectionConfig>, Option<Vec<ConnectionConfig>>) {
    let plaintext = || {
        let port = server.port.unwrap_or(53);
        let mut udp = ConnectionConfig::udp();
        udp.port = port;
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = port;
        // Keep UDP and its truncation-only TCP continuation in one Hickory
        // nameserver. Hickory disables UDP after a TC response and retries the
        // same query over TCP; TCP is not an ordered sibling which could be
        // selected merely because UDP had an unrelated transport failure.
        vec![udp, tcp]
    };
    let tls = || {
        let server_name = server
            .server_name
            .clone()
            .unwrap_or_else(|| server.address.to_string());
        let mut connection = ConnectionConfig::tls(Arc::from(server_name));
        connection.port = server.port.unwrap_or(853);
        vec![connection]
    };

    match mode {
        ResolvedDnsOverTlsMode::No => (plaintext(), None),
        ResolvedDnsOverTlsMode::Yes => (tls(), None),
        ResolvedDnsOverTlsMode::Opportunistic => (tls(), Some(plaintext())),
    }
}

fn transport_description(
    interface: &str,
    index: usize,
    server: &ResolvedNameServer,
    protocol: &ProtocolConfig,
) -> String {
    let protocol = match protocol {
        ProtocolConfig::Udp => "udp",
        ProtocolConfig::Tls { .. } => "tls",
        _ => "unexpected",
    };
    format!(
        "systemd-resolved[{interface}]#{index}:{protocol}://{}",
        server.address
    )
}

type SystemQuestionFuture =
    Pin<Box<dyn Future<Output = std::io::Result<DnsExchangeResponse>> + Send>>;

trait SystemQuestionTransport: Debug + Send + Sync {
    fn exchange_question(&self, name: Name, question_type: DnsQuestionType)
    -> SystemQuestionFuture;
}

impl SystemQuestionTransport for HickoryResolver {
    fn exchange_question(
        &self,
        name: Name,
        question_type: DnsQuestionType,
    ) -> SystemQuestionFuture {
        self.exchange_dns_question(name, question_type)
    }
}

#[derive(Clone)]
struct OrderedServer {
    primary: Arc<dyn SystemQuestionTransport>,
    fallback: Option<Arc<dyn SystemQuestionTransport>>,
    description: String,
}

const SYSTEM_HOSTS_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Default)]
struct SystemHosts {
    inner: Hosts,
}

impl SystemHosts {
    fn from_system() -> Self {
        match Hosts::from_system() {
            Ok(inner) => Self { inner },
            Err(error) => {
                // sing-box treats an unreadable initial hosts file as empty and
                // retries after its five-second snapshot interval. The system
                // configuration fingerprint likewise rebuilds this wrapper
                // when the file appears or changes.
                log::warn!("failed to load the system hosts file: {error}");
                Self::default()
            }
        }
    }

    fn exchange(&self, name: &Name, question_type: DnsQuestionType) -> Option<DnsExchangeResponse> {
        let record_type = match question_type {
            DnsQuestionType::A => RecordType::A,
            DnsQuestionType::Aaaa => RecordType::AAAA,
        };
        let requested = self
            .inner
            .lookup_static_host(&Query::query(name.clone(), record_type));
        let other_type = match record_type {
            RecordType::A => RecordType::AAAA,
            RecordType::AAAA => RecordType::A,
            _ => unreachable!("system hosts only handles address questions"),
        };
        let name_exists = requested.is_some()
            || self
                .inner
                .lookup_static_host(&Query::query(name.clone(), other_type))
                .is_some();
        if !name_exists {
            return None;
        }

        let requested_family_exists = requested.is_some();
        let addresses = requested
            .into_iter()
            .flat_map(|lookup| {
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::A(address) => Some(IpAddr::V4(address.0)),
                        RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // A hosts name that exists only in the other address family is a
        // terminal NOERROR/NODATA answer, but unlike a positive hosts hit it
        // must not become a ten-minute shared-cache entry. Go returns it with
        // TTL zero, so a later hosts-file refresh is immediately observable.
        let ttl = if requested_family_exists {
            SYSTEM_HOSTS_TTL
        } else {
            Duration::ZERO
        };
        Some(DnsExchangeResponse::success(addresses, ttl))
    }
}

struct OrderedSystemResolver {
    interface: String,
    dns_over_tls: ResolvedDnsOverTlsMode,
    servers: Vec<OrderedServer>,
    hosts: Option<Arc<SystemHosts>>,
    ip_strategy: IpStrategy,
    query_cache: Option<Arc<DnsQueryCache>>,
    query_policy: DnsCachePolicy,
    transport_tag: Arc<str>,
}

#[derive(Clone)]
struct SystemQuestionContext {
    servers: Vec<OrderedServer>,
    hosts: Option<Arc<SystemHosts>>,
    cache: Option<Arc<DnsQueryCache>>,
    policy: DnsCachePolicy,
    transport_tag: Arc<str>,
}

impl OrderedSystemResolver {
    fn new(
        interface: String,
        dns_over_tls: ResolvedDnsOverTlsMode,
        servers: Vec<OrderedServer>,
        options: HickoryResolverOptions,
        use_hosts: bool,
    ) -> Self {
        Self {
            interface,
            dns_over_tls,
            servers,
            hosts: use_hosts.then(|| Arc::new(SystemHosts::from_system())),
            ip_strategy: options.ip_strategy,
            query_cache: options.shared_cache,
            query_policy: DnsCachePolicy {
                disable_cache: options.disable_cache,
                rewrite_ttl: options.rewrite_ttl,
                client_subnet: options.client_subnet.is_some(),
            },
            transport_tag: options.transport_tag,
        }
    }

    async fn exchange_ordered(
        servers: Vec<OrderedServer>,
        name: Name,
        question_type: DnsQuestionType,
    ) -> std::io::Result<DnsExchangeResponse> {
        let mut last_transport_error = None;
        for (index, server) in servers.into_iter().enumerate() {
            match server
                .primary
                .exchange_question(name.clone(), question_type)
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) if !is_transport_or_handshake_error(&error) => return Err(error),
                Err(primary_error) => {
                    let Some(fallback) = server.fallback else {
                        log::debug!(
                            "ordered system DNS server #{index} ({}) had a transport failure for {question_type:?}: {primary_error}",
                            server.description
                        );
                        last_transport_error = Some(primary_error);
                        continue;
                    };

                    log::debug!(
                        "ordered system DNS server #{index} ({}) TLS transport failed for {question_type:?}; trying its plaintext fallback: {primary_error}",
                        server.description
                    );
                    match fallback
                        .exchange_question(name.clone(), question_type)
                        .await
                    {
                        Ok(response) => return Ok(response),
                        Err(error) if !is_transport_or_handshake_error(&error) => {
                            return Err(error);
                        }
                        Err(error) => last_transport_error = Some(error),
                    }
                }
            }
        }

        Err(last_transport_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "system DNS has no usable servers",
            )
        }))
    }

    async fn resolve_question(
        context: SystemQuestionContext,
        question_name: Arc<str>,
        name: Name,
        question_type: DnsQuestionType,
    ) -> std::io::Result<Arc<[IpAddr]>> {
        let question = DnsQuestion::new(question_name, question_type);
        let SystemQuestionContext {
            servers,
            hosts,
            cache,
            policy,
            transport_tag,
        } = context;
        let exchange = move || async move {
            if let Some(hosts) = hosts
                && let Some(response) = hosts.exchange(&name, question_type)
            {
                return Ok(response);
            }
            Self::exchange_ordered(servers, name, question_type).await
        };

        if let Some(cache) = cache {
            cache
                .resolve(question, transport_tag, policy, exchange)
                .await
        } else {
            exchange().await?.into_result()
        }
    }
}

impl Debug for OrderedSystemResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrderedSystemResolver")
            .field("interface", &self.interface)
            .field("dns_over_tls", &self.dns_over_tls)
            .field("server_count", &self.servers.len())
            .finish()
    }
}

impl Resolver for OrderedSystemResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(std::future::ready(Ok(vec![socket_addr])));
        }

        let original_name = location.address().to_string();
        let question_name: Arc<str> = if original_name.ends_with('.') {
            Arc::from(original_name.clone())
        } else {
            Arc::from(format!("{original_name}."))
        };
        let mut name = match Name::from_utf8(&original_name) {
            Ok(name) => name,
            Err(error) => {
                return Box::pin(std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error,
                ))));
            }
        };
        name.set_fqdn(true);
        let port = location.port();
        let question_context = SystemQuestionContext {
            servers: self.servers.clone(),
            hosts: self.hosts.clone(),
            cache: self.query_cache.clone(),
            policy: self.query_policy,
            transport_tag: self.transport_tag.clone(),
        };
        let ip_strategy = self.ip_strategy;

        Box::pin(async move {
            let query = |question_type| {
                Self::resolve_question(
                    question_context.clone(),
                    question_name.clone(),
                    name.clone(),
                    question_type,
                )
            };
            let addresses = match ip_strategy {
                IpStrategy::Ipv4Only => query(DnsQuestionType::A).await.map(|value| value.to_vec()),
                IpStrategy::Ipv6Only => query(DnsQuestionType::Aaaa)
                    .await
                    .map(|value| value.to_vec()),
                IpStrategy::Ipv4AndIpv6 | IpStrategy::Ipv6AndIpv4 => {
                    let (ipv4, ipv6) =
                        tokio::join!(query(DnsQuestionType::A), query(DnsQuestionType::Aaaa));
                    merge_question_results(
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
            }?;
            let addresses = addresses
                .into_iter()
                .filter(|address| !address.is_unspecified())
                .map(|address| SocketAddr::new(address, port))
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(std::io::Error::other(format!(
                    "system DNS lookup returned no addresses for {name}"
                )));
            }
            Ok(addresses)
        })
    }

    fn result_cache_ttl(&self) -> Option<Duration> {
        // Each Hickory transport owns DNS TTL/cache semantics. An outer cache
        // would hide the remaining TTL and could also bypass a changed link.
        None
    }
}

fn merge_question_results(
    ipv4: std::io::Result<Arc<[IpAddr]>>,
    ipv6: std::io::Result<Arc<[IpAddr]>>,
    ipv6_first: bool,
) -> std::io::Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    let mut first_error = None;
    let mut append = |result: std::io::Result<Arc<[IpAddr]>>| match result {
        Ok(result) => addresses.extend_from_slice(&result),
        Err(error) if first_error.is_none() => first_error = Some(error),
        Err(_) => {}
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

fn is_transport_or_handshake_error(error: &std::io::Error) -> bool {
    if let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<NetError>())
    {
        // Hickory's Dns variant is the only semantic response outcome
        // (NXDOMAIN/NoRecords/RCODE). Every other NetError represents failure
        // to complete a valid exchange. This matches Go's transport.Exchange
        // boundary: an RCODE response stops, while framing/decoding/handshake
        // failures may try the opportunistic plaintext transport.
        return !matches!(error, NetError::Dns(_));
    }
    is_connection_error_kind(error.kind())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hickory_resolver::net::DnsError;
    use hickory_resolver::proto::op::ResponseCode;

    use super::*;

    #[test]
    fn ordinary_system_nameservers_are_serial_and_keep_explicit_rotation() {
        let mut options = ResolverOpts::default();
        assert!(options.num_concurrent_reqs > 1);
        normalize_ordinary_system_options(&mut options);
        assert_eq!(options.num_concurrent_reqs, 1);
        assert_eq!(
            options.server_ordering_strategy,
            ServerOrderingStrategy::UserProvidedOrder
        );

        options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
        normalize_ordinary_system_options(&mut options);
        assert_eq!(
            options.server_ordering_strategy,
            ServerOrderingStrategy::RoundRobin
        );
    }

    #[test]
    fn systemd_transports_do_not_retry_inside_one_ordered_server() {
        let mut options = ResolverOpts::default();
        options.attempts = 7;
        let options = systemd_transport_options(options);
        assert_eq!(options.attempts, 0);
    }

    #[test]
    fn resolved_connections_preserve_transport_specific_ports_and_tls_name() {
        let implicit = ResolvedNameServer {
            address: "2001:db8::53".parse().unwrap(),
            port: None,
            server_name: None,
        };
        let (tls, plaintext) =
            resolved_server_connections(&implicit, ResolvedDnsOverTlsMode::Opportunistic);
        assert_eq!(tls.len(), 1);
        assert_eq!(tls[0].port, 853);
        assert!(matches!(
            &tls[0].protocol,
            ProtocolConfig::Tls { server_name } if &**server_name == "2001:db8::53"
        ));
        let plaintext = plaintext.unwrap();
        assert_eq!(plaintext.len(), 2);
        assert_eq!(plaintext[0].port, 53);
        assert!(matches!(&plaintext[0].protocol, ProtocolConfig::Udp));
        assert_eq!(plaintext[1].port, 53);
        assert!(matches!(&plaintext[1].protocol, ProtocolConfig::Tcp));

        let explicit = ResolvedNameServer {
            address: "192.0.2.53".parse().unwrap(),
            port: Some(8853),
            server_name: Some("dns.example".to_string()),
        };
        let (tls, plaintext) =
            resolved_server_connections(&explicit, ResolvedDnsOverTlsMode::Opportunistic);
        assert_eq!(tls.len(), 1);
        assert_eq!(tls[0].port, 8853);
        assert!(matches!(
            &tls[0].protocol,
            ProtocolConfig::Tls { server_name } if &**server_name == "dns.example"
        ));
        let plaintext = plaintext.unwrap();
        assert_eq!(plaintext[0].port, 8853);
        assert_eq!(plaintext[1].port, 8853);

        let (plain, fallback) = resolved_server_connections(&implicit, ResolvedDnsOverTlsMode::No);
        assert_eq!(plain.len(), 2);
        assert!(matches!(&plain[0].protocol, ProtocolConfig::Udp));
        assert!(matches!(&plain[1].protocol, ProtocolConfig::Tcp));
        assert!(fallback.is_none());
    }

    #[derive(Clone, Copy, Debug)]
    enum Outcome {
        Success,
        Transport,
        SemanticDns,
    }

    #[derive(Clone, Copy, Debug)]
    struct FamilyOutcomes {
        a: Outcome,
        aaaa: Outcome,
    }

    impl FamilyOutcomes {
        const fn same(outcome: Outcome) -> Self {
            Self {
                a: outcome,
                aaaa: outcome,
            }
        }

        const fn new(a: Outcome, aaaa: Outcome) -> Self {
            Self { a, aaaa }
        }

        fn get(self, question_type: DnsQuestionType) -> Outcome {
            match question_type {
                DnsQuestionType::A => self.a,
                DnsQuestionType::Aaaa => self.aaaa,
            }
        }
    }

    type Call = (&'static str, DnsQuestionType);
    type ServerDefinition = (
        &'static str,
        FamilyOutcomes,
        Option<(&'static str, FamilyOutcomes)>,
    );

    #[derive(Debug)]
    struct ScriptedTransport {
        name: &'static str,
        outcomes: FamilyOutcomes,
        calls: Arc<Mutex<Vec<Call>>>,
    }

    impl SystemQuestionTransport for ScriptedTransport {
        fn exchange_question(
            &self,
            _name: Name,
            question_type: DnsQuestionType,
        ) -> SystemQuestionFuture {
            self.calls.lock().unwrap().push((self.name, question_type));
            let outcome = self.outcomes.get(question_type);
            Box::pin(async move {
                // Force concurrent cache-miss tests to overlap at the outer
                // question single-flight boundary.
                tokio::task::yield_now().await;
                match outcome {
                    Outcome::Success => {
                        let address = match question_type {
                            DnsQuestionType::A => "192.0.2.80".parse().unwrap(),
                            DnsQuestionType::Aaaa => "2001:db8::80".parse().unwrap(),
                        };
                        Ok(DnsExchangeResponse::success(
                            [address],
                            Duration::from_secs(60),
                        ))
                    }
                    Outcome::Transport => Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "test transport failure",
                    )),
                    Outcome::SemanticDns => Err(std::io::Error::other(NetError::Dns(
                        DnsError::ResponseCode(ResponseCode::Refused),
                    ))),
                }
            })
        }
    }

    fn scripted(
        name: &'static str,
        outcomes: FamilyOutcomes,
        calls: &Arc<Mutex<Vec<Call>>>,
    ) -> Arc<dyn SystemQuestionTransport> {
        Arc::new(ScriptedTransport {
            name,
            outcomes,
            calls: calls.clone(),
        })
    }

    fn ordered(
        calls: &Arc<Mutex<Vec<Call>>>,
        definitions: &[ServerDefinition],
        ip_strategy: IpStrategy,
        query_cache: Option<Arc<DnsQueryCache>>,
    ) -> OrderedSystemResolver {
        OrderedSystemResolver {
            interface: "eth0".to_string(),
            dns_over_tls: ResolvedDnsOverTlsMode::Opportunistic,
            servers: definitions
                .iter()
                .map(|(name, outcomes, fallback)| OrderedServer {
                    primary: scripted(name, *outcomes, calls),
                    fallback: fallback.map(|(name, outcomes)| scripted(name, outcomes, calls)),
                    description: (*name).to_string(),
                })
                .collect(),
            hosts: None,
            ip_strategy,
            query_cache,
            query_policy: DnsCachePolicy::default(),
            transport_tag: Arc::from("system-test"),
        }
    }

    fn test_location() -> NetLocation {
        NetLocation::new(
            crate::address::Address::Hostname("example.test".to_string()),
            443,
        )
    }

    #[tokio::test]
    async fn opportunistic_mode_is_tls_first_then_udp_for_the_same_server() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[(
                "tls-1",
                FamilyOutcomes::same(Outcome::Transport),
                Some(("udp-1", FamilyOutcomes::same(Outcome::Success))),
            )],
            IpStrategy::Ipv4Only,
            None,
        );

        resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            [("tls-1", DnsQuestionType::A), ("udp-1", DnsQuestionType::A)]
        );
    }

    #[tokio::test]
    async fn semantic_dns_error_never_downgrades_or_tries_another_server() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[
                (
                    "tls-1",
                    FamilyOutcomes::same(Outcome::SemanticDns),
                    Some(("udp-1", FamilyOutcomes::same(Outcome::Success))),
                ),
                ("tls-2", FamilyOutcomes::same(Outcome::Success), None),
            ],
            IpStrategy::Ipv4Only,
            None,
        );

        resolver
            .resolve_location(&test_location())
            .await
            .unwrap_err();
        assert_eq!(*calls.lock().unwrap(), [("tls-1", DnsQuestionType::A)]);
    }

    #[tokio::test]
    async fn next_server_runs_only_after_both_transports_fail() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[
                (
                    "tls-1",
                    FamilyOutcomes::same(Outcome::Transport),
                    Some(("udp-1", FamilyOutcomes::same(Outcome::Transport))),
                ),
                ("tls-2", FamilyOutcomes::same(Outcome::Success), None),
            ],
            IpStrategy::Ipv4Only,
            None,
        );

        resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            [
                ("tls-1", DnsQuestionType::A),
                ("udp-1", DnsQuestionType::A),
                ("tls-2", DnsQuestionType::A)
            ]
        );
    }

    fn calls_for(calls: &[Call], question_type: DnsQuestionType) -> Vec<&'static str> {
        calls
            .iter()
            .filter_map(|(name, observed)| (*observed == question_type).then_some(*name))
            .collect()
    }

    #[tokio::test]
    async fn tls_fallback_is_independent_for_each_address_question() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[(
                "tls-1",
                FamilyOutcomes::new(Outcome::Transport, Outcome::Success),
                Some(("udp-1", FamilyOutcomes::same(Outcome::Success))),
            )],
            IpStrategy::Ipv4AndIpv6,
            None,
        );

        let addresses = resolver.resolve_location(&test_location()).await.unwrap();
        assert!(addresses.iter().any(SocketAddr::is_ipv4));
        assert!(addresses.iter().any(SocketAddr::is_ipv6));
        let calls = calls.lock().unwrap();
        assert_eq!(calls_for(&calls, DnsQuestionType::A), ["tls-1", "udp-1"]);
        assert_eq!(calls_for(&calls, DnsQuestionType::Aaaa), ["tls-1"]);
    }

    #[tokio::test]
    async fn semantic_a_does_not_block_aaaa_transport_fallback() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[(
                "tls-1",
                FamilyOutcomes::new(Outcome::SemanticDns, Outcome::Transport),
                Some(("udp-1", FamilyOutcomes::same(Outcome::Success))),
            )],
            IpStrategy::Ipv4AndIpv6,
            None,
        );

        let addresses = resolver.resolve_location(&test_location()).await.unwrap();
        assert!(addresses.iter().all(SocketAddr::is_ipv6));
        let calls = calls.lock().unwrap();
        assert_eq!(calls_for(&calls, DnsQuestionType::A), ["tls-1"]);
        assert_eq!(calls_for(&calls, DnsQuestionType::Aaaa), ["tls-1", "udp-1"]);
    }

    #[tokio::test]
    async fn one_question_singleflight_covers_tls_and_plaintext_fallback() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[(
                "tls-1",
                FamilyOutcomes::same(Outcome::Transport),
                Some(("udp-1", FamilyOutcomes::same(Outcome::Success))),
            )],
            IpStrategy::Ipv4Only,
            Some(Arc::new(DnsQueryCache::default())),
        );

        let (first, second) = tokio::join!(
            resolver.resolve_location(&test_location()),
            resolver.resolve_location(&test_location())
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(
            calls_for(&calls.lock().unwrap(), DnsQuestionType::A),
            ["tls-1", "udp-1"]
        );
    }

    #[tokio::test]
    async fn hosts_hit_is_terminal_for_a_missing_address_family() {
        let mut hosts = Hosts::default();
        hosts
            .read_hosts_conf(&b"192.0.2.44 local-only.example\n"[..])
            .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut resolver = ordered(
            &calls,
            &[("tls-1", FamilyOutcomes::same(Outcome::Success), None)],
            IpStrategy::Ipv6Only,
            Some(Arc::new(DnsQueryCache::default())),
        );
        resolver.hosts = Some(Arc::new(SystemHosts { inner: hosts }));

        resolver
            .resolve_location(&NetLocation::new(
                crate::address::Address::Hostname("local-only.example".to_string()),
                443,
            ))
            .await
            .unwrap_err();
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(SYSTEM_HOSTS_TTL, Duration::from_secs(600));
    }

    #[test]
    fn hosts_other_family_is_terminal_noerror_with_zero_ttl() {
        let mut hosts = Hosts::default();
        hosts
            .read_hosts_conf(&b"192.0.2.44 local-only.example\n"[..])
            .unwrap();
        let hosts = SystemHosts { inner: hosts };
        let name = Name::from_utf8("local-only.example.").unwrap();

        let missing_family = hosts
            .exchange(&name, DnsQuestionType::Aaaa)
            .expect("the name exists in the other hosts family");
        assert!(missing_family.into_result().unwrap().is_empty());
        let missing_family = hosts.exchange(&name, DnsQuestionType::Aaaa).unwrap();
        assert_eq!(missing_family.ttl_for_test(), Duration::ZERO);

        let present_family = hosts.exchange(&name, DnsQuestionType::A).unwrap();
        assert_eq!(present_family.ttl_for_test(), SYSTEM_HOSTS_TTL);
    }

    #[tokio::test]
    async fn systemd_resolved_path_does_not_short_circuit_through_hosts() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = ordered(
            &calls,
            &[("tls-1", FamilyOutcomes::same(Outcome::Success), None)],
            IpStrategy::Ipv4Only,
            None,
        );
        assert!(resolver.hosts.is_none());

        resolver
            .resolve_location(&NetLocation::new(
                crate::address::Address::Hostname("localhost".to_string()),
                443,
            ))
            .await
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), [("tls-1", DnsQuestionType::A)]);
    }

    #[test]
    fn hickory_dns_errors_are_not_transport_failures() {
        let semantic = std::io::Error::other(NetError::Dns(DnsError::ResponseCode(
            ResponseCode::ServFail,
        )));
        assert!(!is_transport_or_handshake_error(&semantic));
        let transport = std::io::Error::other(NetError::Io(Arc::new(std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "unreachable",
        ))));
        assert!(is_transport_or_handshake_error(&transport));
    }
}
