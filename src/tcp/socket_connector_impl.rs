//! SocketConnectorImpl - Implementation of SocketConnector trait.
//!
//! Handles TCP and QUIC transports. Rich dialer socket options are isolated to
//! TCP/direct-UDP; configuration validation rejects them for QUIC.
//! Created from the socket-related fields of any ClientConfig.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, error};
use tokio::net::UdpSocket;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::config::{ClientConfig, ClientQuicConfig, Transport};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_addresses_via};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::{
    OutboundSocketOptions, new_outbound_tcp_socket, new_outbound_udp_socket, new_udp_socket,
    set_tcp_keepalive,
};
use crate::thread_util::get_num_threads;

use super::socket_connector::SocketConnector;

const MAX_QUIC_ENDPOINTS: usize = 32;

#[derive(Debug)]
enum TransportConfig {
    Tcp {
        no_delay: bool,
    },
    Quic {
        sni_hostname: Option<String>,
        endpoints_v4: Vec<Arc<quinn::Endpoint>>,
        endpoints_v6: Vec<Arc<quinn::Endpoint>>,
        next_endpoint_index: AtomicU8,
    },
}

fn build_quic_endpoint_pool(
    is_ipv6: bool,
    endpoints_len: usize,
    bind_interface: Option<String>,
    client_config: &quinn::ClientConfig,
) -> std::io::Result<Vec<Arc<quinn::Endpoint>>> {
    let mut endpoints = Vec::with_capacity(endpoints_len);
    for _ in 0..endpoints_len {
        let udp_socket = new_udp_socket(is_ipv6, bind_interface.clone())?.into_std()?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config.clone());
        endpoints.push(Arc::new(endpoint));
    }
    Ok(endpoints)
}

fn quic_target_families(address: &crate::address::Address) -> (bool, bool) {
    match address {
        crate::address::Address::Ipv4(_) => (true, false),
        crate::address::Address::Ipv6(_) => (false, true),
        crate::address::Address::Hostname(_) => (true, true),
    }
}

/// Implementation of SocketConnector for TCP and QUIC transports.
///
/// Created from the socket-related fields of any ClientConfig:
/// - `bind_interface`
/// - `inet4_bind_address` / `inet6_bind_address`
/// - `routing_mark` / `bind_address_no_port`
/// - `connect_timeout`
/// - `transport`
/// - `tcp_settings`
/// - `quic_settings`
#[derive(Debug)]
pub struct SocketConnectorImpl {
    socket_options: OutboundSocketOptions,
    connect_timeout: Option<Duration>,
    dns_resolver: Option<String>,
    transport: TransportConfig,
}

async fn with_connect_timeout<F, T>(
    future: F,
    connect_timeout: Option<Duration>,
    target: SocketAddr,
) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    let Some(connect_timeout) = connect_timeout else {
        return future.await;
    };
    // sing-box treats an explicitly configured zero duration as its standard
    // dial timeout. Absence remains None so legacy shoes behavior is unchanged.
    let connect_timeout = if connect_timeout.is_zero() {
        Duration::from_secs(5)
    } else {
        connect_timeout
    };
    tokio::time::timeout(connect_timeout, future)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("TCP connect to {target} timed out after {connect_timeout:?}"),
            )
        })?
}

fn serial_socket_attempt_error(
    operation: &str,
    mut errors: Vec<(SocketAddr, std::io::Error)>,
) -> std::io::Error {
    if errors.is_empty() {
        return std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{operation}: DNS resolution returned no addresses"),
        );
    }
    if errors.len() == 1 {
        return errors.pop().expect("length checked above").1;
    }

    let kind = errors
        .last()
        .expect("non-empty errors checked above")
        .1
        .kind();
    let details = errors
        .into_iter()
        .map(|(address, error)| format!("{address}: {error}"))
        .collect::<Vec<_>>()
        .join(" | ");
    std::io::Error::new(
        kind,
        format!("{operation} failed for every address ({details})"),
    )
}

async fn connect_udp_candidates(
    target_addrs: &[SocketAddr],
    socket_options: &OutboundSocketOptions,
) -> std::io::Result<(UdpSocket, SocketAddr)> {
    let mut errors = Vec::new();
    for (index, remote_addr) in target_addrs.iter().copied().enumerate() {
        let socket = match new_outbound_udp_socket(remote_addr.is_ipv6(), socket_options) {
            Ok(socket) => socket,
            Err(error) => {
                debug!(
                    "UDP socket setup for {} failed: {}, trying next resolved address",
                    remote_addr, error
                );
                errors.push((remote_addr, error));
                continue;
            }
        };

        match socket.connect(remote_addr).await {
            Ok(()) => {
                if index > 0 {
                    debug!(
                        "UDP connect succeeded on address #{} ({}) after {} failures",
                        index, remote_addr, index
                    );
                }
                return Ok((socket, remote_addr));
            }
            Err(error) => {
                debug!(
                    "UDP connect to {} failed: {}, trying next resolved address",
                    remote_addr, error
                );
                errors.push((remote_addr, error));
            }
        }
    }
    Err(serial_socket_attempt_error("UDP connect", errors))
}

impl SocketConnectorImpl {
    /// Create a SocketConnector from a ClientConfig's socket-related fields.
    ///
    /// # Arguments
    /// * `config` - The client config (socket fields are extracted)
    /// * `target_address` - The address this connector will connect to (used for QUIC SNI default).
    ///   Pass None for direct protocol (QUIC is not supported for direct).
    ///
    /// # Returns
    /// None if QUIC endpoint creation fails.
    pub fn from_config(
        config: &ClientConfig,
        target_address: Option<&NetLocation>,
    ) -> Option<Self> {
        let socket_options = OutboundSocketOptions {
            bind_interface: config.bind_interface.clone().into_option(),
            inet4_bind_address: config.inet4_bind_address,
            inet6_bind_address: config.inet6_bind_address,
            routing_mark: config.routing_mark,
            bind_address_no_port: config.bind_address_no_port,
        };

        let default_sni_hostname =
            target_address.and_then(|addr| addr.address().hostname().map(ToString::to_string));

        // Direct protocol only supports TCP (no proxy server to connect via QUIC)
        let effective_transport = if config.protocol.is_direct() {
            &Transport::Tcp
        } else {
            &config.transport
        };

        let transport = match *effective_transport {
            Transport::Tcp | Transport::Udp => {
                let no_delay = config
                    .tcp_settings
                    .as_ref()
                    .map(|tc| tc.no_delay)
                    .unwrap_or(true);
                TransportConfig::Tcp { no_delay }
            }
            Transport::Quic => {
                // QUIC requires a target address for endpoint creation
                let target_address = target_address.expect(
                    "QUIC transport requires target_address (direct protocol should use TCP)",
                );

                let ClientQuicConfig {
                    verify,
                    use_native_roots,
                    server_fingerprints,
                    alpn_protocols,
                    sni_hostname,
                    key,
                    cert,
                } = config.quic_settings.clone().unwrap_or_default();

                let sni_hostname = if sni_hostname.is_unspecified() {
                    if let Some(ref hostname) = default_sni_hostname {
                        debug!(
                            "Using default sni hostname for QUIC client connection: {}",
                            hostname
                        );
                    }
                    default_sni_hostname.clone()
                } else {
                    sni_hostname.into_option()
                };

                let tls13_suite =
                    match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
                        rustls::SupportedCipherSuite::Tls13(t) => t,
                        _ => {
                            panic!("Could not retrieve Tls13CipherSuite");
                        }
                    };

                let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                    let cert_bytes = cert.as_bytes().to_vec();
                    let key_bytes = key.as_bytes().to_vec();
                    (key_bytes, cert_bytes)
                });

                let rustls_client_config = create_client_config(
                    verify,
                    server_fingerprints.into_vec(),
                    alpn_protocols.into_vec(),
                    sni_hostname.is_some(),
                    key_and_cert_bytes,
                    false, // tls13_only - QUIC enforces TLS 1.3 anyway
                    use_native_roots,
                );

                let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
                    Arc::new(rustls_client_config),
                    tls13_suite.quic_suite().unwrap(),
                )
                .unwrap();

                let mut quinn_client_config =
                    quinn::ClientConfig::new(Arc::new(quic_client_config));

                let mut transport_config = quinn::TransportConfig::default();
                transport_config
                    .max_concurrent_bidi_streams(0_u32.into())
                    .max_concurrent_uni_streams(0_u8.into())
                    .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                    .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

                quinn_client_config.transport_config(Arc::new(transport_config));

                let endpoints_len = std::cmp::min(get_num_threads(), MAX_QUIC_ENDPOINTS);
                let (needs_v4, needs_v6) = quic_target_families(target_address.address());
                let endpoints_v4 = if needs_v4 {
                    match build_quic_endpoint_pool(
                        false,
                        endpoints_len,
                        socket_options.bind_interface.clone(),
                        &quinn_client_config,
                    ) {
                        Ok(endpoints) => endpoints,
                        Err(error) => {
                            error!("Failed to build IPv4 QUIC endpoint pool: {error}");
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };
                let endpoints_v6 = if needs_v6 {
                    match build_quic_endpoint_pool(
                        true,
                        endpoints_len,
                        socket_options.bind_interface.clone(),
                        &quinn_client_config,
                    ) {
                        Ok(endpoints) => endpoints,
                        Err(error) => {
                            error!("Failed to build IPv6 QUIC endpoint pool: {error}");
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };
                if endpoints_v4.is_empty() && endpoints_v6.is_empty() {
                    return None;
                }

                TransportConfig::Quic {
                    sni_hostname,
                    endpoints_v4,
                    endpoints_v6,
                    next_endpoint_index: AtomicU8::new(0),
                }
            }
        };

        Some(Self {
            socket_options,
            connect_timeout: config.connect_timeout,
            dns_resolver: config.dns_resolver.clone(),
            transport,
        })
    }

    /// Create a simple TCP SocketConnector for direct connections.
    ///
    /// Used when only TCP is needed (no QUIC).
    #[cfg(test)]
    pub fn new_tcp(bind_interface: Option<String>, no_delay: bool) -> Self {
        Self {
            socket_options: OutboundSocketOptions {
                bind_interface,
                ..Default::default()
            },
            connect_timeout: None,
            dns_resolver: None,
            transport: TransportConfig::Tcp { no_delay },
        }
    }
}

#[async_trait]
impl SocketConnector for SocketConnectorImpl {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let target_addrs = match address.resolved_addrs() {
            Some(addresses) => addresses.to_vec(),
            None => {
                resolve_addresses_via(resolver, self.dns_resolver.as_deref(), address.location())
                    .await?
            }
        };

        match &self.transport {
            TransportConfig::Tcp { no_delay } => {
                let mut errors = Vec::new();
                for (i, target_addr) in target_addrs.iter().enumerate() {
                    let tcp_socket = match new_outbound_tcp_socket(
                        target_addr.is_ipv6(),
                        &self.socket_options,
                    ) {
                        Ok(socket) => socket,
                        Err(error) => {
                            debug!(
                                "TCP socket setup for {} failed: {}, trying next resolved address",
                                target_addr, error
                            );
                            errors.push((*target_addr, error));
                            continue;
                        }
                    };
                    match with_connect_timeout(
                        tcp_socket.connect(*target_addr),
                        self.connect_timeout,
                        *target_addr,
                    )
                    .await
                    {
                        Ok(stream) => {
                            if i > 0 {
                                debug!(
                                    "TCP connect succeeded on address #{} ({}) after {} failures",
                                    i, target_addr, i
                                );
                            }
                            if let Err(e) = set_tcp_keepalive(
                                &stream,
                                std::time::Duration::from_secs(120),
                                std::time::Duration::from_secs(30),
                            ) {
                                error!("Failed to set TCP keepalive: {e}");
                            }
                            if *no_delay && let Err(e) = stream.set_nodelay(true) {
                                error!("Failed to set TCP no-delay: {e}");
                            }
                            return Ok(Box::new(stream));
                        }
                        Err(e) => {
                            debug!("TCP connect to {} failed: {}, trying next", target_addr, e);
                            errors.push((*target_addr, e));
                        }
                    }
                }
                Err(serial_socket_attempt_error("TCP connect", errors))
            }
            TransportConfig::Quic {
                endpoints_v4,
                endpoints_v6,
                next_endpoint_index,
                sni_hostname,
            } => {
                let domain = match sni_hostname {
                    Some(s) => s.as_str(),
                    None => address.address().hostname().unwrap_or("example.com"),
                };

                let mut errors = Vec::new();
                for (i, target_addr) in target_addrs.iter().enumerate() {
                    let endpoints = if target_addr.is_ipv6() {
                        endpoints_v6
                    } else {
                        endpoints_v4
                    };
                    if endpoints.is_empty() {
                        let error = std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            format!(
                                "no {} QUIC endpoint could be created",
                                if target_addr.is_ipv6() {
                                    "IPv6"
                                } else {
                                    "IPv4"
                                }
                            ),
                        );
                        debug!(
                            "QUIC endpoint family for {} is unavailable: {}, trying next",
                            target_addr, error
                        );
                        errors.push((*target_addr, error));
                        continue;
                    }
                    let endpoint = if endpoints.len() == 1 {
                        &endpoints[0]
                    } else {
                        let idx = next_endpoint_index.fetch_add(1, Ordering::Relaxed) as usize;
                        &endpoints[idx % endpoints.len()]
                    };

                    match endpoint.connect(*target_addr, domain) {
                        Ok(connecting) => match connecting.await {
                            Ok(conn) => match conn.open_bi().await {
                                Ok((send, recv)) => {
                                    if i > 0 {
                                        debug!(
                                            "QUIC connect succeeded on address #{} ({}) after {} failures",
                                            i, target_addr, i
                                        );
                                    }
                                    return Ok(Box::new(QuicStream::from(send, recv)));
                                }
                                Err(e) => {
                                    debug!("QUIC open_bi to {} failed: {}", target_addr, e);
                                    errors.push((
                                        *target_addr,
                                        std::io::Error::other(format!(
                                            "Failed to open QUIC stream: {e}"
                                        )),
                                    ));
                                }
                            },
                            Err(e) => {
                                debug!("QUIC connection to {} failed: {}", target_addr, e);
                                errors.push((
                                    *target_addr,
                                    std::io::Error::other(format!("QUIC connection failed: {e}")),
                                ));
                            }
                        },
                        Err(e) => {
                            debug!("QUIC connect to {} failed: {}", target_addr, e);
                            errors.push((
                                *target_addr,
                                std::io::Error::other(format!(
                                    "Failed to connect to QUIC endpoint: {e}"
                                )),
                            ));
                        }
                    }
                }
                Err(serial_socket_attempt_error("QUIC connect", errors))
            }
        }
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        debug!(
            "[SocketConnector] connect_udp_bidirectional called, target: {}",
            target.location()
        );

        let target_addrs = match target.resolved_addrs() {
            Some(addresses) => addresses.to_vec(),
            None => {
                resolve_addresses_via(resolver, self.dns_resolver.as_deref(), target.location())
                    .await?
            }
        };

        let (client_socket, remote_addr) =
            connect_udp_candidates(&target_addrs, &self.socket_options).await?;
        debug!("[SocketConnector] connected UDP socket to {remote_addr}");
        Ok(Box::new(client_socket))
    }

    fn bind_interface(&self) -> Option<&str> {
        self.socket_options.bind_interface.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientProxyConfig;
    use std::pin::Pin;

    #[derive(Debug)]
    struct OrderedResolver {
        addresses: Vec<SocketAddr>,
    }

    impl Resolver for OrderedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[test]
    fn test_new_tcp() {
        let connector = SocketConnectorImpl::new_tcp(Some("eth0".to_string()), true);
        assert!(matches!(
            connector.transport,
            TransportConfig::Tcp { no_delay: true }
        ));
        assert_eq!(
            connector.socket_options.bind_interface,
            Some("eth0".to_string())
        );
    }

    #[test]
    fn test_from_config_direct_protocol() {
        let config = ClientConfig::default(); // default is direct protocol
        let connector = SocketConnectorImpl::from_config(&config, None);
        assert!(connector.is_some());
        assert!(matches!(
            connector.unwrap().transport,
            TransportConfig::Tcp { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_connect_timeout_wraps_tcp_connect() {
        let target = "192.0.2.1:443".parse().unwrap();
        let error = with_connect_timeout(
            std::future::pending::<std::io::Result<()>>(),
            Some(Duration::from_secs(2)),
            target,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("192.0.2.1:443"));
    }

    #[test]
    fn test_from_config_copies_dialer_socket_options() {
        let config = ClientConfig {
            inet4_bind_address: Some("192.0.2.10".parse().unwrap()),
            inet6_bind_address: Some("2001:db8::10".parse().unwrap()),
            routing_mark: 100,
            connect_timeout: Some(Duration::from_secs(8)),
            bind_address_no_port: true,
            dns_resolver: Some("proxy-dns-v6".to_string()),
            ..Default::default()
        };
        let connector = SocketConnectorImpl::from_config(&config, None).unwrap();
        assert_eq!(
            connector.socket_options.inet4_bind_address,
            config.inet4_bind_address
        );
        assert_eq!(
            connector.socket_options.inet6_bind_address,
            config.inet6_bind_address
        );
        assert_eq!(connector.socket_options.routing_mark, 100);
        assert_eq!(connector.connect_timeout, Some(Duration::from_secs(8)));
        assert_eq!(connector.dns_resolver.as_deref(), Some("proxy-dns-v6"));
        assert!(connector.socket_options.bind_address_no_port);
    }

    #[tokio::test]
    async fn quic_hostname_builds_both_address_family_endpoint_pools_and_keeps_sni() {
        crate::thread_util::set_num_threads(1);
        let address = NetLocation::new(
            crate::address::Address::Hostname("proxy.example".to_string()),
            443,
        );
        assert_eq!(quic_target_families(address.address()), (true, true));
        let config = ClientConfig {
            address: address.clone(),
            protocol: ClientProxyConfig::Http {
                username: None,
                password: None,
                resolve_hostname: false,
            },
            transport: Transport::Quic,
            ..ClientConfig::default()
        };

        let connector = SocketConnectorImpl::from_config(&config, Some(&address)).unwrap();
        let TransportConfig::Quic {
            sni_hostname,
            endpoints_v4,
            endpoints_v6,
            ..
        } = connector.transport
        else {
            panic!("expected QUIC transport");
        };
        assert_eq!(sni_hostname.as_deref(), Some("proxy.example"));
        assert!(!endpoints_v4.is_empty());
        assert!(!endpoints_v6.is_empty());
    }

    #[tokio::test]
    async fn udp_socket_setup_tries_every_resolved_address_family() {
        let mut connector = SocketConnectorImpl::new_tcp(None, true);
        // Binding a documentation-only IPv6 address fails without IP_FREEBIND,
        // while the following IPv4 candidate can use an ordinary wildcard bind.
        connector.socket_options.inet6_bind_address = Some("2001:db8::10".parse().unwrap());
        let resolver: Arc<dyn Resolver> = Arc::new(OrderedResolver {
            addresses: vec![
                "[2001:db8::53]:53".parse().unwrap(),
                "127.0.0.1:53".parse().unwrap(),
            ],
        });
        let target = ResolvedLocation::from(NetLocation::new(
            crate::address::Address::Hostname("dns.example".to_string()),
            53,
        ));

        let stream = connector
            .connect_udp_bidirectional(&resolver, target)
            .await
            .expect("the IPv4 candidate after the unusable IPv6 bind must be tried");

        assert_eq!(
            stream.connected_remote_addr(),
            Some("127.0.0.1:53".parse().unwrap()),
            "the selected fallback candidate must remain visible to the UDP router"
        );

        drop(stream);
    }

    #[tokio::test]
    async fn udp_candidate_selection_returns_a_socket_connected_to_the_remote() {
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_address = remote.local_addr().unwrap();
        let (socket, selected_address) =
            connect_udp_candidates(&[remote_address], &OutboundSocketOptions::default())
                .await
                .unwrap();

        assert_eq!(selected_address, remote_address);
        assert_eq!(socket.peer_addr().unwrap(), remote_address);

        socket.send(b"connected").await.unwrap();
        let mut buffer = [0_u8; 32];
        let (length, source) = remote.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"connected");
        assert_eq!(source, socket.local_addr().unwrap());
    }

    #[tokio::test]
    async fn tcp_socket_setup_failure_advances_to_the_next_resolved_family() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let mut connector = SocketConnectorImpl::new_tcp(None, true);
        connector.socket_options.inet6_bind_address = Some("2001:db8::10".parse().unwrap());
        let resolver: Arc<dyn Resolver> = Arc::new(OrderedResolver {
            addresses: vec![
                SocketAddr::new("2001:db8::53".parse().unwrap(), port),
                SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            ],
        });
        let target = ResolvedLocation::from(NetLocation::new(
            crate::address::Address::Hostname("proxy.example".to_string()),
            port,
        ));

        let stream = connector
            .connect(&resolver, &target)
            .await
            .expect("the IPv4 candidate after the unusable IPv6 bind must be tried");
        let _accepted = accept.await.unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn tcp_connect_retries_candidates_retained_by_prior_route_resolution() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let connector = SocketConnectorImpl::new_tcp(None, true);
        let resolver: Arc<dyn Resolver> = Arc::new(OrderedResolver {
            addresses: Vec::new(),
        });
        let mut target = ResolvedLocation::from(NetLocation::new(
            crate::address::Address::Hostname("routed.example".to_string()),
            port,
        ));
        target.set_resolved_addrs(vec![
            SocketAddr::new("127.0.0.2".parse().unwrap(), port),
            SocketAddr::new("127.0.0.1".parse().unwrap(), port),
        ]);

        let stream = connector
            .connect(&resolver, &target)
            .await
            .expect("the connector must advance past the failed routed candidate");
        let _accepted = accept.await.unwrap();
        drop(stream);
    }

    #[test]
    fn serial_socket_errors_keep_every_failed_address_in_the_diagnostic() {
        let first = "192.0.2.1:443".parse().unwrap();
        let second = "192.0.2.2:443".parse().unwrap();
        let error = serial_socket_attempt_error(
            "test dial",
            vec![
                (
                    first,
                    std::io::Error::new(std::io::ErrorKind::NetworkUnreachable, "no route"),
                ),
                (
                    second,
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
                ),
            ],
        );

        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains(&first.to_string()));
        assert!(error.to_string().contains(&second.to_string()));
    }
}
