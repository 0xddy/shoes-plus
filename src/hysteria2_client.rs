//! Hysteria2 outbound client.
//!
//! Hysteria2 is not a byte-stream wrapper like SOCKS or VLESS.  One authenticated
//! QUIC connection owns both independently opened TCP streams and all UDP
//! datagrams, so it cannot be implemented by handing the ordinary proxy handler a
//! connected TCP socket.  This module keeps that connection-local state behind a
//! [`SocketConnector`](crate::tcp::socket_connector::SocketConnector): the normal
//! proxy handler still owns the small TCP/UDP wire headers, while the connector
//! owns QUIC, HTTP/3 authentication, congestion-control negotiation and datagram
//! session demultiplexing.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use lru::LruCache;
use parking_lot::Mutex;
use rand::RngExt;
use rand::distr::Alphanumeric;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::config::{ClientConfig, ClientProxyConfig, ClientQuicConfig, Hysteria2ClientObfs};
use crate::hysteria2::brutal::{self, BrutalConfig, mbps_to_bytes_per_second};
use crate::hysteria2_obfs::{ObfuscatedUdpSocket, Salamander};
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_addresses_via};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::{
    OutboundSocketOptions, QUIC_UDP_SOCKET_BUFFER_TARGET, new_outbound_udp_socket_with_buffer_size,
};
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const TCP_FRAME_TYPE: u64 = 0x401;
const MAX_ADDRESS_LENGTH: usize = 2048;
const MAX_MESSAGE_LENGTH: usize = 2048;
const MAX_PADDING_LENGTH: usize = 4096;
const MAX_UDP_PAYLOAD: usize = 4096;
const MAX_FRAGMENT_CACHE_SIZE: usize = 256;
const FRAGMENT_MAX_AGE: Duration = Duration::from_secs(10);

// QUIC guarantees a 1200-byte path packet, but encryption and QUIC's own frame
// header consume part of it.  The dynamic maximum is only visible to the socket
// connector, while protocol framing lives one layer above it.  Keeping the entire
// Hysteria datagram at 1000 bytes is deliberately conservative and interoperable;
// it avoids a second copy/retry path while still requiring at most five fragments
// for the protocol's 4096-byte payload ceiling.
const SAFE_WIRE_DATAGRAM: usize = 1000;
const SESSION_ID_LENGTH: usize = 4;

/// Construction data for one Hysteria2 proxy endpoint.
///
/// The secret fields intentionally have a redacted [`Debug`] implementation.
#[derive(Clone)]
pub struct Hysteria2ClientOptions {
    pub server: NetLocation,
    pub password: String,
    pub udp_enabled: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub salamander_password: Option<String>,
    pub tls: ClientQuicConfig,
    pub socket_options: OutboundSocketOptions,
    pub dns_resolver: Option<String>,
}

impl std::fmt::Debug for Hysteria2ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2ClientOptions")
            .field("server", &self.server)
            .field("password_len", &self.password.len())
            .field("udp_enabled", &self.udp_enabled)
            .field("up_mbps", &self.up_mbps)
            .field("down_mbps", &self.down_mbps)
            .field(
                "salamander_password_len",
                &self.salamander_password.as_ref().map(String::len),
            )
            .field("tls", &self.tls)
            .field("socket_options", &self.socket_options)
            .field("dns_resolver", &self.dns_resolver)
            .finish()
    }
}

/// A socket connector backed by a reusable authenticated Hysteria2 connection.
#[derive(Debug, Clone)]
pub struct Hysteria2SocketConnector {
    manager: Arc<Hysteria2ConnectionManager>,
}

impl Hysteria2SocketConnector {
    pub fn new(options: Hysteria2ClientOptions) -> Self {
        Self {
            manager: Arc::new(Hysteria2ConnectionManager {
                options,
                connection: AsyncMutex::new(None),
            }),
        }
    }

    /// Build from the ordinary client-chain schema after configuration
    /// validation has enforced Hysteria2's placement and unsupported options.
    pub fn from_client_config(config: &ClientConfig) -> io::Result<Self> {
        let ClientProxyConfig::Hysteria2 {
            password,
            udp_enabled,
            up_mbps,
            down_mbps,
            obfs,
            server_ports,
            hop_interval,
        } = &config.protocol
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 socket connector requires protocol type hysteria2",
            ));
        };
        if !server_ports.is_empty() || hop_interval.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria2 server_ports/hop_interval port hopping is not supported",
            ));
        }
        let salamander_password = obfs.as_ref().map(|obfs| match obfs {
            Hysteria2ClientObfs::Salamander { password } => password.clone(),
        });
        Ok(Self::new(Hysteria2ClientOptions {
            server: config.address.clone(),
            password: password.clone(),
            udp_enabled: *udp_enabled,
            up_mbps: *up_mbps,
            down_mbps: *down_mbps,
            salamander_password,
            tls: config.quic_settings.clone().unwrap_or_default(),
            socket_options: OutboundSocketOptions {
                bind_interface: config.bind_interface.clone().into_option(),
                inet4_bind_address: config.inet4_bind_address,
                inet6_bind_address: config.inet6_bind_address,
                routing_mark: config.routing_mark,
                bind_address_no_port: config.bind_address_no_port,
            },
            dns_resolver: config.dns_resolver.clone(),
        }))
    }
}

#[async_trait]
impl SocketConnector for Hysteria2SocketConnector {
    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        self.manager.ensure_expected_server(address)?;
        let connection = self.manager.connection(resolver).await?;
        let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.connection.open_bi())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("opening a Hysteria2 TCP stream timed out after {HANDSHAKE_TIMEOUT:?}"),
                )
            })?
            .map_err(|error| {
                io::Error::other(format!("failed to open Hysteria2 TCP stream: {error}"))
            })?;
        Ok(Box::new(QuicStream::from(send, recv)))
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.manager.ensure_expected_server(&target)?;
        if !self.manager.options.udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled by this Hysteria2 outbound configuration",
            ));
        }
        let connection = self.manager.connection(resolver).await?;
        if !connection.server_udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled by the Hysteria2 server",
            ));
        }
        Ok(Box::new(connection.register_udp_session()?))
    }

    fn bind_interface(&self) -> Option<&str> {
        self.manager
            .options
            .socket_options
            .bind_interface
            .as_deref()
    }
}

#[derive(Debug)]
struct Hysteria2ConnectionManager {
    options: Hysteria2ClientOptions,
    connection: AsyncMutex<Option<Arc<AuthenticatedConnection>>>,
}

impl Hysteria2ConnectionManager {
    fn ensure_expected_server(&self, target: &ResolvedLocation) -> io::Result<()> {
        if target.location() == &self.options.server {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Hysteria2 connector for {} cannot dial unexpected endpoint {}",
                self.options.server,
                target.location()
            ),
        ))
    }

    async fn connection(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<Arc<AuthenticatedConnection>> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot.as_ref()
            && connection.connection.close_reason().is_none()
        {
            return Ok(Arc::clone(connection));
        }

        let connection = Arc::new(self.connect_new(resolver).await?);
        *slot = Some(Arc::clone(&connection));
        Ok(connection)
    }

    async fn connect_new(
        &self,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<AuthenticatedConnection> {
        let addresses = resolve_addresses_via(
            resolver,
            self.options.dns_resolver.as_deref(),
            &self.options.server,
        )
        .await?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Hysteria2 server {} resolved to no addresses",
                    self.options.server
                ),
            ));
        }

        // TLS identity/configuration belongs to the Hysteria2 client, not to
        // one resolved address attempt. Build it once so a static TLS error is
        // never misclassified as a reason to advance through DNS candidates.
        let (client_config, server_name) = self.create_client_config(addresses[0])?;

        connect_resolved_udp_endpoint(
            addresses,
            |address| self.prepare_udp_endpoint(address),
            |address, endpoint| {
                self.connect_prepared_endpoint(address, (endpoint, client_config, server_name))
            },
        )
        .await
    }

    async fn connect_prepared_endpoint(
        &self,
        address: SocketAddr,
        (endpoint, client_config, server_name): (quinn::Endpoint, quinn::ClientConfig, String),
    ) -> io::Result<AuthenticatedConnection> {
        let connecting = endpoint
            .connect_with(client_config, address, &server_name)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid Hysteria2 QUIC server name {server_name:?}: {error}"),
                )
            })?;

        let connection = connecting.await.map_err(|error| {
            io::Error::other(format!("Hysteria2 QUIC handshake failed: {error}"))
        })?;
        authenticate_connection(
            endpoint,
            connection,
            &self.options.password,
            self.options.udp_enabled,
            self.options.up_mbps,
            self.options.down_mbps,
        )
        .await
    }

    fn create_client_config(
        &self,
        target: SocketAddr,
    ) -> io::Result<(quinn::ClientConfig, String)> {
        let mut alpn_protocols = self.options.tls.alpn_protocols.clone().into_vec();
        if alpn_protocols.is_empty() {
            alpn_protocols.push("h3".to_string());
        }

        let sni_hostname = self
            .options
            .tls
            .sni_hostname
            .clone()
            .into_option()
            .or_else(|| self.options.server.address().hostname().map(str::to_owned))
            .unwrap_or_else(|| target.ip().to_string());
        let key_and_cert = self
            .options
            .tls
            .key
            .clone()
            .zip(self.options.tls.cert.clone())
            .map(|(key, cert)| (key.into_bytes(), cert.into_bytes()));
        let rustls_config = create_client_config(
            self.options.tls.verify,
            self.options.tls.server_fingerprints.clone().into_vec(),
            alpn_protocols,
            true,
            key_and_cert,
            false,
            self.options.tls.use_native_roots,
        );

        let tls13_suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            rustls::SupportedCipherSuite::Tls13(suite) => suite,
            _ => unreachable!("the selected cipher suite is TLS 1.3"),
        };
        let crypto = quinn::crypto::rustls::QuicClientConfig::with_initial(
            Arc::new(rustls_config),
            tls13_suite
                .quic_suite()
                .expect("TLS 1.3 suite has QUIC keys"),
        )
        .map_err(|error| io::Error::other(format!("invalid Hysteria2 TLS config: {error}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));

        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(0_u32.into())
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20_u32 * 1024 * 1024).into())
            .stream_receive_window((8_u32 * 1024 * 1024).into())
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .congestion_controller_factory(Arc::new(BrutalConfig))
            .enable_segmentation_offload(self.options.salamander_password.is_none())
            .initial_rtt(Duration::from_millis(100));
        client_config.transport_config(Arc::new(transport));

        Ok((client_config, sni_hostname))
    }

    async fn prepare_udp_endpoint(&self, target: SocketAddr) -> io::Result<quinn::Endpoint> {
        // sing-quic calls ResolveDialer.DialContext("udp"), whose DialSerial
        // returns the connected UDP socket itself. Keep that exact socket for
        // Quinn so its selected source route, peer filtering, and asynchronous
        // ICMP errors are not lost between candidate selection and handshake.
        let socket =
            new_connected_hysteria_udp_socket(target, &self.options.socket_options).await?;
        let runtime = Arc::new(quinn::TokioRuntime);
        use quinn::Runtime as _;
        let endpoint = match self.options.salamander_password.as_deref() {
            Some(password) => {
                let inner = runtime.wrap_udp_socket(socket)?;
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    Arc::new(ObfuscatedUdpSocket::new(inner, Salamander::new(password))),
                    runtime,
                )?
            }
            None => quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?,
        };

        Ok(endpoint)
    }
}

async fn new_connected_hysteria_udp_socket(
    target: SocketAddr,
    socket_options: &OutboundSocketOptions,
) -> io::Result<std::net::UdpSocket> {
    // A larger kernel queue reduces local drops during bursty QUIC traffic. It
    // does not make Quinn's stream assembler immune to arbitrary reordering.
    let socket = new_outbound_udp_socket_with_buffer_size(
        target.is_ipv6(),
        socket_options,
        QUIC_UDP_SOCKET_BUFFER_TARGET,
    )?;
    socket.connect(target).await?;
    let socket = socket.into_std()?;
    debug_assert_eq!(socket.peer_addr().ok(), Some(target));
    Ok(socket)
}

/// Match sing-box's `ResolveDialer.DialContext("udp")` / `DialSerial`: only
/// connected UDP route/socket preparation failures advance to the next DNS
/// address. Once one endpoint exists, QUIC/TLS and HTTP/3 authentication run
/// once; their failure must not be misclassified as an address-family setup
/// failure.
async fn connect_resolved_udp_endpoint<T, U, P, PrepareFuture, C, ConnectFuture>(
    addresses: Vec<SocketAddr>,
    mut prepare: P,
    connect: C,
) -> io::Result<U>
where
    P: FnMut(SocketAddr) -> PrepareFuture,
    PrepareFuture: Future<Output = io::Result<T>>,
    C: FnOnce(SocketAddr, T) -> ConnectFuture,
    ConnectFuture: Future<Output = io::Result<U>>,
{
    let mut last_error = None;
    let mut selected = None;
    for address in addresses {
        match prepare(address).await {
            Ok(endpoint) => {
                selected = Some((address, endpoint));
                break;
            }
            Err(error) => {
                log::debug!(
                    "Hysteria2 UDP endpoint setup for {address} failed: {error}; trying next"
                );
                last_error = Some(error);
            }
        }
    }
    let (address, endpoint) = selected.ok_or_else(|| {
        last_error.unwrap_or_else(|| io::Error::other("no Hysteria2 UDP endpoint succeeded"))
    })?;
    run_with_handshake_timeout(connect(address, endpoint)).await
}

/// Apply the one deadline used by sing-quic's Hysteria2 client. The selected
/// endpoint's QUIC/TLS handshake and HTTP/3 authentication exchange consume the
/// same budget; no phase gets a fresh 15 seconds.
async fn run_with_handshake_timeout<T>(
    handshake: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Hysteria2 QUIC/TLS and authentication timed out after {HANDSHAKE_TIMEOUT:?}"
                ),
            )
        })?
}

struct AuthenticatedConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    server_udp_enabled: bool,
    sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    next_session_id: AtomicU32,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for AuthenticatedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedConnection")
            .field("remote_address", &self.connection.remote_address())
            .field("server_udp_enabled", &self.server_udp_enabled)
            .field("udp_sessions", &self.sessions.lock().len())
            .finish()
    }
}

impl AuthenticatedConnection {
    fn register_udp_session(self: &Arc<Self>) -> io::Result<Hysteria2RawUdpStream> {
        if !self.server_udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is disabled by the Hysteria2 server",
            ));
        }

        let (sender, receiver) = mpsc::channel(64);
        let mut sessions = self.sessions.lock();
        // At most `sessions.len()` candidates can already be occupied, so one
        // additional sequential probe must find a free ID.  This also prevents a
        // corrupted/full map from turning allocation into a four-billion-step loop.
        let session_id = (0..=sessions.len())
            .find_map(|_| {
                let candidate = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                (!sessions.contains_key(&candidate)).then_some(candidate)
            })
            .ok_or_else(|| io::Error::other("all Hysteria2 UDP session IDs are in use"))?;
        sessions.insert(session_id, sender);
        drop(sessions);

        Ok(Hysteria2RawUdpStream {
            connection: Arc::clone(self),
            session_id,
            receiver,
            pending_write: None,
            closed: false,
        })
    }
}

impl Drop for AuthenticatedConnection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.connection.close(0_u32.into(), b"");
        self.endpoint.close(0_u32.into(), b"");
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn authenticate_connection(
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    password: &str,
    client_udp_enabled: bool,
    up_mbps: u64,
    down_mbps: u64,
) -> io::Result<AuthenticatedConnection> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut sender) = h3::client::new(h3_connection)
        .await
        .map_err(|error| io::Error::other(format!("Hysteria2 HTTP/3 setup failed: {error}")))?;

    let driver_task = tokio::spawn(async move {
        let error = driver.wait_idle().await;
        log::debug!("Hysteria2 HTTP/3 driver ended: {error}");
    });

    let request = http::Request::post("https://hysteria/auth")
        .header(
            "Hysteria-Auth",
            http::HeaderValue::from_str(password).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid Hysteria2 password header: {error}"),
                )
            })?,
        )
        .header(
            "Hysteria-CC-RX",
            mbps_to_bytes_per_second(down_mbps).to_string(),
        )
        .header("Hysteria-Padding", random_ascii(256, 2048))
        .body(())
        .expect("static Hysteria2 auth URI and headers are valid");

    let auth_result = async {
        let mut stream = sender.send_request(request).await.map_err(|error| {
            io::Error::other(format!("failed to send Hysteria2 auth request: {error}"))
        })?;
        stream.finish().await.map_err(|error| {
            io::Error::other(format!("failed to finish Hysteria2 auth request: {error}"))
        })?;
        stream.recv_response().await.map_err(|error| {
            io::Error::other(format!("failed to read Hysteria2 auth response: {error}"))
        })
    }
    .await;

    let response = match auth_result {
        Ok(response) => response,
        Err(error) => {
            driver_task.abort();
            connection.close(0_u32.into(), b"auth failed");
            endpoint.close(0_u32.into(), b"auth failed");
            return Err(error);
        }
    };
    if response.status().as_u16() != 233 {
        driver_task.abort();
        connection.close(0_u32.into(), b"auth rejected");
        endpoint.close(0_u32.into(), b"auth rejected");
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Hysteria2 authentication failed with HTTP status {}",
                response.status()
            ),
        ));
    }

    let server_udp_enabled = response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(false);
    let response_rx = response
        .headers()
        .get("Hysteria-CC-RX")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let rx_auto = response_rx == "auto";
    let server_receive_bps = response_rx.parse::<u64>().unwrap_or(0);
    let configured_send_bps = mbps_to_bytes_per_second(up_mbps);
    let actual_send_bps = if server_receive_bps == 0 || server_receive_bps > configured_send_bps {
        configured_send_bps
    } else {
        server_receive_bps
    };
    if !rx_auto && actual_send_bps > 0 {
        brutal::activate(&connection, actual_send_bps)?;
    }

    let cancel = CancellationToken::new();
    let keep_sender_cancel = cancel.clone();
    let keep_sender_task = tokio::spawn(async move {
        keep_sender_cancel.cancelled().await;
        drop(sender);
    });

    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let mut tasks = vec![driver_task, keep_sender_task];
    if client_udp_enabled {
        let reader_cancel = cancel.clone();
        let reader_connection = connection.clone();
        let reader_sessions = Arc::clone(&sessions);
        tasks.push(tokio::spawn(async move {
            run_udp_reader(reader_connection, reader_sessions, reader_cancel).await;
        }));
    }

    // A client disabling UDP must not accidentally enable it just because the
    // peer advertised support.  Avoid starting consumers from treating the
    // negotiated flag as configuration authority.
    let server_udp_enabled = client_udp_enabled && server_udp_enabled;
    Ok(AuthenticatedConnection {
        endpoint,
        connection,
        server_udp_enabled,
        sessions,
        next_session_id: AtomicU32::new(0),
        cancel,
        tasks,
    })
}

async fn run_udp_reader(
    connection: quinn::Connection,
    sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    cancel: CancellationToken,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            result = connection.read_datagram() => match result {
                Ok(datagram) => datagram,
                Err(error) => {
                    log::debug!("Hysteria2 UDP reader ended: {error}");
                    break;
                }
            },
        };
        if datagram.len() < SESSION_ID_LENGTH {
            connection.close(0_u32.into(), b"invalid UDP datagram");
            break;
        }
        let session_id = u32::from_be_bytes(datagram[..4].try_into().unwrap());
        let sender = sessions.lock().get(&session_id).cloned();
        if let Some(sender) = sender {
            // Match sing-quic's bounded per-session queue: a slow UDP consumer
            // drops datagrams instead of applying head-of-line blocking to every
            // other session sharing this QUIC connection.
            let _ = sender.try_send(datagram.slice(SESSION_ID_LENGTH..));
        }
    }

    // The connection owns the map's send halves.  If QUIC dies while a caller is
    // blocked in `poll_read_message`, leaving those senders behind would make the
    // UDP stream wait forever even though no packet can ever arrive again.
    sessions.lock().clear();
}

type DatagramSendFuture =
    Pin<Box<dyn Future<Output = Result<(), quinn::SendDatagramError>> + Send + 'static>>;

struct Hysteria2RawUdpStream {
    connection: Arc<AuthenticatedConnection>,
    session_id: u32,
    receiver: mpsc::Receiver<Bytes>,
    pending_write: Option<DatagramSendFuture>,
    closed: bool,
}

impl std::fmt::Debug for Hysteria2RawUdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2RawUdpStream")
            .field("session_id", &self.session_id)
            .field("closed", &self.closed)
            .finish()
    }
}

impl Drop for Hysteria2RawUdpStream {
    fn drop(&mut self) {
        self.connection.sessions.lock().remove(&self.session_id);
    }
}

impl AsyncReadMessage for Hysteria2RawUdpStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                if datagram.len() > buf.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Hysteria2 datagram is too large for the read buffer: {} > {}",
                            datagram.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&datagram);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Hysteria2 UDP connection closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteMessage for Hysteria2RawUdpStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Hysteria2 UDP session is closed",
            )));
        }

        if self.pending_write.is_none() {
            let max_datagram = self
                .connection
                .connection
                .max_datagram_size()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "QUIC datagrams disabled")
                });
            let max_datagram = match max_datagram {
                Ok(max_datagram) => max_datagram,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if SESSION_ID_LENGTH + buf.len() > max_datagram {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Hysteria2 framed datagram exceeds negotiated QUIC maximum: {} > {}",
                        SESSION_ID_LENGTH + buf.len(),
                        max_datagram
                    ),
                )));
            }
            let mut datagram = BytesMut::with_capacity(SESSION_ID_LENGTH + buf.len());
            datagram.extend_from_slice(&self.session_id.to_be_bytes());
            datagram.extend_from_slice(buf);
            let connection = self.connection.connection.clone();
            let datagram = datagram.freeze();
            self.pending_write = Some(Box::pin(async move {
                connection.send_datagram_wait(datagram).await
            }));
        }

        let future = self.pending_write.as_mut().unwrap();
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.pending_write = None;
                Poll::Ready(Err(io::Error::other(format!(
                    "failed to send Hysteria2 datagram: {error}"
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for Hysteria2RawUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(future) = this.pending_write.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(format!(
                    "failed to flush Hysteria2 datagram: {error}"
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for Hysteria2RawUdpStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self).poll_flush_message(cx) {
            Poll::Ready(Ok(())) => {
                self.closed = true;
                self.connection.sessions.lock().remove(&self.session_id);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncPing for Hysteria2RawUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for Hysteria2RawUdpStream {}

/// Protocol header handler paired with [`Hysteria2SocketConnector`].
#[derive(Debug)]
pub struct Hysteria2TcpClientHandler {
    udp_enabled: bool,
}

impl Hysteria2TcpClientHandler {
    pub fn new(udp_enabled: bool) -> Self {
        Self { udp_enabled }
    }
}

#[async_trait]
impl TcpClientHandler for Hysteria2TcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let destination = remote_location.location().to_string();
        let setup = async {
            let request = encode_tcp_request(&destination)?;
            client_stream.write_all(&request).await?;
            client_stream.flush().await?;
            read_tcp_response(&mut client_stream).await?;
            Ok::<_, io::Error>(())
        };
        if let Err(error) = tokio::time::timeout(HANDSHAKE_TIMEOUT, setup)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Hysteria2 TCP setup timed out after {HANDSHAKE_TIMEOUT:?}"),
                )
            })?
        {
            let _ = client_stream.shutdown().await;
            return Err(error);
        }

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_native_udp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_native_udp(
        &self,
        client_stream: Box<dyn AsyncMessageStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Ok(Box::new(Hysteria2UdpMessageStream::new(
            client_stream,
            target.into_location(),
        )?))
    }
}

fn encode_tcp_request(destination: &str) -> io::Result<Bytes> {
    if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid Hysteria2 TCP destination length: {}",
                destination.len()
            ),
        ));
    }
    let padding = random_ascii(64, 512);
    let mut request = BytesMut::with_capacity(8 + destination.len() + padding.len());
    put_varint(&mut request, TCP_FRAME_TYPE)?;
    put_varint(&mut request, destination.len() as u64)?;
    request.extend_from_slice(destination.as_bytes());
    put_varint(&mut request, padding.len() as u64)?;
    request.extend_from_slice(padding.as_bytes());
    Ok(request.freeze())
}

async fn read_tcp_response(stream: &mut Box<dyn AsyncStream>) -> io::Result<()> {
    let status = stream.read_u8().await?;
    let message_len = read_varint(stream).await?;
    if message_len > MAX_MESSAGE_LENGTH as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 TCP response message is too long",
        ));
    }
    let mut message = vec![0_u8; message_len as usize];
    stream.read_exact(&mut message).await?;
    let padding_len = read_varint(stream).await?;
    if padding_len > MAX_PADDING_LENGTH as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 TCP response padding is too long",
        ));
    }
    let mut padding = vec![0_u8; padding_len as usize];
    stream.read_exact(&mut padding).await?;
    if status != 0 {
        return Err(io::Error::other(format!(
            "Hysteria2 server rejected TCP request: {}",
            String::from_utf8_lossy(&message)
        )));
    }
    Ok(())
}

fn random_ascii(min: usize, max: usize) -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(min..max);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn put_varint(output: &mut BytesMut, value: u64) -> io::Result<()> {
    if value <= 63 {
        output.extend_from_slice(&[value as u8]);
    } else if value < 1 << 14 {
        let mut bytes = (value as u16).to_be_bytes();
        bytes[0] |= 0x40;
        output.extend_from_slice(&bytes);
    } else if value < 1 << 30 {
        let mut bytes = (value as u32).to_be_bytes();
        bytes[0] |= 0x80;
        output.extend_from_slice(&bytes);
    } else if value < 1 << 62 {
        let mut bytes = value.to_be_bytes();
        bytes[0] |= 0xc0;
        output.extend_from_slice(&bytes);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value does not fit a QUIC varint",
        ));
    }
    Ok(())
}

async fn read_varint(stream: &mut Box<dyn AsyncStream>) -> io::Result<u64> {
    let first = stream.read_u8().await?;
    let byte_count = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..byte_count {
        value = (value << 8) | u64::from(stream.read_u8().await?);
    }
    Ok(value)
}

struct Hysteria2UdpMessageStream {
    inner: Box<dyn AsyncMessageStream>,
    destination: String,
    next_packet_id: u16,
    pending_fragments: Vec<Bytes>,
    pending_fragment_index: usize,
    read_buffer: Box<[u8; 65_535]>,
    fragments: LruCache<u16, ClientFragmentedPacket>,
}

impl std::fmt::Debug for Hysteria2UdpMessageStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2UdpMessageStream")
            .field("destination", &self.destination)
            .field("pending_fragments", &self.pending_fragments.len())
            .field("fragment_cache", &self.fragments.len())
            .finish()
    }
}

impl Hysteria2UdpMessageStream {
    fn new(inner: Box<dyn AsyncMessageStream>, target: NetLocation) -> io::Result<Self> {
        let destination = target.to_string();
        if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid Hysteria2 UDP destination length: {}",
                    destination.len()
                ),
            ));
        }
        Ok(Self {
            inner,
            destination,
            next_packet_id: 0,
            pending_fragments: Vec::new(),
            pending_fragment_index: 0,
            read_buffer: Box::new([0; 65_535]),
            fragments: LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap()),
        })
    }

    fn build_fragments(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Hysteria2 UDP payload exceeds the {MAX_UDP_PAYLOAD}-byte protocol limit"),
            ));
        }

        let address_len_size = encoded_varint_len(self.destination.len() as u64)?;
        let header_len = 2 + 1 + 1 + address_len_size + self.destination.len();
        let available_payload = SAFE_WIRE_DATAGRAM
            .checked_sub(SESSION_ID_LENGTH + header_len)
            .ok_or_else(|| io::Error::other("Hysteria2 UDP address does not fit a datagram"))?;
        if available_payload == 0 {
            return Err(io::Error::other(
                "Hysteria2 UDP datagram has no room for payload",
            ));
        }
        let fragment_count = payload.len().max(1).div_ceil(available_payload);
        let fragment_count = u8::try_from(fragment_count).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 UDP payload needs more than 255 fragments",
            )
        })?;
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        self.pending_fragments.clear();
        self.pending_fragment_index = 0;

        for fragment_id in 0..fragment_count {
            let start = usize::from(fragment_id) * available_payload;
            let end = (start + available_payload).min(payload.len());
            let data = if start <= end {
                &payload[start..end]
            } else {
                &[]
            };
            let mut fragment = BytesMut::with_capacity(header_len + data.len());
            fragment.extend_from_slice(&packet_id.to_be_bytes());
            fragment.extend_from_slice(&[fragment_id, fragment_count]);
            put_varint(&mut fragment, self.destination.len() as u64)?;
            fragment.extend_from_slice(self.destination.as_bytes());
            fragment.extend_from_slice(data);
            self.pending_fragments.push(fragment.freeze());
        }
        Ok(())
    }

    fn process_fragment(&mut self, datagram: &[u8]) -> io::Result<Option<Bytes>> {
        let decoded = decode_udp_fragment(datagram)?;
        if decoded.fragment_count == 1 {
            return Ok(Some(Bytes::copy_from_slice(decoded.payload)));
        }

        let now = Instant::now();
        while self
            .fragments
            .peek_lru()
            .is_some_and(|(_, packet)| now.duration_since(packet.created) > FRAGMENT_MAX_AGE)
        {
            self.fragments.pop_lru();
        }

        if !self.fragments.contains(&decoded.packet_id) {
            self.fragments.put(
                decoded.packet_id,
                ClientFragmentedPacket {
                    created: now,
                    source: decoded.destination.to_string(),
                    fragment_count: decoded.fragment_count,
                    received_count: 0,
                    total_len: 0,
                    fragments: vec![None; usize::from(decoded.fragment_count)],
                },
            );
        }
        let packet = self.fragments.get_mut(&decoded.packet_id).unwrap();
        if packet.fragment_count != decoded.fragment_count {
            self.fragments.pop(&decoded.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hysteria2 UDP fragment count changed within one packet",
            ));
        }
        if packet.source != decoded.destination {
            self.fragments.pop(&decoded.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hysteria2 UDP fragment source changed within one packet",
            ));
        }
        let slot = &mut packet.fragments[usize::from(decoded.fragment_id)];
        if slot.is_some() {
            self.fragments.pop(&decoded.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate Hysteria2 UDP fragment",
            ));
        }
        packet.total_len = packet
            .total_len
            .checked_add(decoded.payload.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP length overflow"))?;
        if packet.total_len > MAX_UDP_PAYLOAD {
            self.fragments.pop(&decoded.packet_id);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reassembled Hysteria2 UDP packet exceeds 4096 bytes",
            ));
        }
        *slot = Some(Bytes::copy_from_slice(decoded.payload));
        packet.received_count += 1;
        if packet.received_count != packet.fragment_count {
            return Ok(None);
        }

        let packet = self.fragments.pop(&decoded.packet_id).unwrap();
        let mut payload = BytesMut::with_capacity(packet.total_len);
        for fragment in packet.fragments {
            payload.extend_from_slice(fragment.as_deref().expect("all fragments received"));
        }
        Ok(Some(payload.freeze()))
    }
}

struct ClientFragmentedPacket {
    created: Instant,
    source: String,
    fragment_count: u8,
    received_count: u8,
    total_len: usize,
    fragments: Vec<Option<Bytes>>,
}

struct DecodedUdpFragment<'a> {
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    destination: &'a str,
    payload: &'a [u8],
}

fn decode_udp_fragment(datagram: &[u8]) -> io::Result<DecodedUdpFragment<'_>> {
    if datagram.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated Hysteria2 UDP datagram",
        ));
    }
    let packet_id = u16::from_be_bytes(datagram[..2].try_into().unwrap());
    let fragment_id = datagram[2];
    let fragment_count = datagram[3];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Hysteria2 UDP fragment {fragment_id}/{fragment_count}"),
        ));
    }
    let (address_len, address_offset) = decode_varint_slice(&datagram[4..])?;
    let address_len = usize::try_from(address_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UDP address length overflow"))?;
    if address_len == 0 || address_len > MAX_ADDRESS_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Hysteria2 UDP address length {address_len}"),
        ));
    }
    let address_start = 4 + address_offset;
    let address_end = address_start
        .checked_add(address_len)
        .filter(|end| *end <= datagram.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated UDP address"))?;
    let destination =
        std::str::from_utf8(&datagram[address_start..address_end]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid UTF-8 Hysteria2 UDP address: {error}"),
            )
        })?;
    let payload = &datagram[address_end..];
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 UDP fragment exceeds the 4096-byte protocol limit",
        ));
    }
    Ok(DecodedUdpFragment {
        packet_id,
        fragment_id,
        fragment_count,
        destination,
        payload,
    })
}

fn encoded_varint_len(value: u64) -> io::Result<usize> {
    if value <= 63 {
        Ok(1)
    } else if value < 1 << 14 {
        Ok(2)
    } else if value < 1 << 30 {
        Ok(4)
    } else if value < 1 << 62 {
        Ok(8)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value does not fit a QUIC varint",
        ))
    }
}

fn decode_varint_slice(input: &[u8]) -> io::Result<(u64, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated QUIC varint"))?;
    let byte_count = 1_usize << (first >> 6);
    if input.len() < byte_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated QUIC varint",
        ));
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..byte_count] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, byte_count))
}

impl AsyncReadMessage for Hysteria2UdpMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = &mut *self;
            let mut datagram = ReadBuf::new(&mut *this.read_buffer);
            match Pin::new(&mut this.inner).poll_read_message(cx, &mut datagram) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let length = datagram.filled().len();
                    let owned = Bytes::copy_from_slice(&datagram.filled()[..length]);
                    match this.process_fragment(&owned)? {
                        Some(payload) => {
                            if payload.len() > output.remaining() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "Hysteria2 UDP payload is too large for read buffer: {} > {}",
                                        payload.len(),
                                        output.remaining()
                                    ),
                                )));
                            }
                            output.put_slice(&payload);
                            return Poll::Ready(Ok(()));
                        }
                        None => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWriteMessage for Hysteria2UdpMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.pending_fragments.is_empty() {
            self.build_fragments(payload)?;
        }
        while self.pending_fragment_index < self.pending_fragments.len() {
            let index = self.pending_fragment_index;
            let fragment = self.pending_fragments[index].clone();
            match Pin::new(&mut self.inner).poll_write_message(cx, &fragment) {
                Poll::Ready(Ok(())) => self.pending_fragment_index += 1,
                Poll::Ready(Err(error)) => {
                    self.pending_fragments.clear();
                    self.pending_fragment_index = 0;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_fragments.clear();
        self.pending_fragment_index = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for Hysteria2UdpMessageStream {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for Hysteria2UdpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}

impl AsyncPing for Hysteria2UdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for Hysteria2UdpMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;

    use crate::address::NetLocationMask;
    use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
    use crate::dynamic::{SelectorSlot, StaticUserRegistry};
    use crate::hysteria2_masquerade::Hysteria2Masquerade;
    use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::{build_client_proxy_chain, build_direct_chain_group};

    #[test]
    fn quic_varints_cover_every_wire_width_and_reject_truncation() {
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30] {
            let mut encoded = BytesMut::new();
            put_varint(&mut encoded, value).unwrap();
            let (decoded, used) = decode_varint_slice(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(used, encoded.len());
            if encoded.len() > 1 {
                assert!(decode_varint_slice(&encoded[..encoded.len() - 1]).is_err());
            }
        }
        assert!(put_varint(&mut BytesMut::new(), 1 << 62).is_err());
    }

    #[test]
    fn tcp_request_uses_hysteria2_frame_and_bounded_padding() {
        let request = encode_tcp_request("example.com:443").unwrap();
        let (frame, first) = decode_varint_slice(&request).unwrap();
        assert_eq!(frame, TCP_FRAME_TYPE);
        let (address_len, second) = decode_varint_slice(&request[first..]).unwrap();
        let address_start = first + second;
        let address_end = address_start + address_len as usize;
        assert_eq!(&request[address_start..address_end], b"example.com:443");
        let (padding_len, padding_header) = decode_varint_slice(&request[address_end..]).unwrap();
        assert!((64..512).contains(&(padding_len as usize)));
        assert_eq!(
            request.len(),
            address_end + padding_header + padding_len as usize
        );
    }

    #[test]
    fn udp_fragment_decoder_enforces_wire_boundaries() {
        let mut valid = BytesMut::new();
        valid.extend_from_slice(&7_u16.to_be_bytes());
        valid.extend_from_slice(&[0, 1]);
        put_varint(&mut valid, 15).unwrap();
        valid.extend_from_slice(b"example.com:443");
        valid.extend_from_slice(b"payload");
        let decoded = decode_udp_fragment(&valid).unwrap();
        assert_eq!(decoded.packet_id, 7);
        assert_eq!(decoded.destination, "example.com:443");
        assert_eq!(decoded.payload, b"payload");

        let mut bad_index = valid.clone();
        bad_index[2] = 1;
        assert!(decode_udp_fragment(&bad_index).is_err());
        assert!(decode_udp_fragment(&valid[..4]).is_err());

        let mut too_long = BytesMut::new();
        too_long.extend_from_slice(&0_u16.to_be_bytes());
        too_long.extend_from_slice(&[0, 1]);
        put_varint(&mut too_long, (MAX_ADDRESS_LENGTH + 1) as u64).unwrap();
        assert!(decode_udp_fragment(&too_long).is_err());

        let mut oversized_payload = valid;
        oversized_payload.extend_from_slice(&vec![0_u8; MAX_UDP_PAYLOAD]);
        assert!(decode_udp_fragment(&oversized_payload).is_err());
    }

    #[test]
    fn bandwidth_negotiation_matches_sing_quic_client_direction() {
        fn actual_send(configured_mbps: u64, server_rx: u64, auto: bool) -> Option<u64> {
            let configured = mbps_to_bytes_per_second(configured_mbps);
            let actual = if server_rx == 0 || server_rx > configured {
                configured
            } else {
                server_rx
            };
            (!auto && actual > 0).then_some(actual)
        }

        assert_eq!(actual_send(0, 10_000_000, false), None);
        assert_eq!(actual_send(100, 0, false), Some(12_500_000));
        assert_eq!(actual_send(100, 5_000_000, false), Some(5_000_000));
        assert_eq!(actual_send(100, 20_000_000, false), Some(12_500_000));
        assert_eq!(actual_send(100, 5_000_000, true), None);
    }

    #[tokio::test(start_paused = true)]
    async fn quic_and_auth_share_one_fifteen_second_handshake_budget() {
        let started = tokio::time::Instant::now();
        let error = run_with_handshake_timeout(async {
            // Model a slow QUIC/TLS phase followed by a slow HTTP/3 auth phase.
            // Separate phase-local deadlines would allow the full twenty seconds.
            tokio::time::sleep(Duration::from_secs(10)).await;
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<_, io::Error>(())
        })
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), HANDSHAKE_TIMEOUT);
    }

    #[tokio::test]
    async fn resolved_addresses_retry_udp_endpoint_creation_before_handshake() {
        let first = "127.0.0.1:1".parse().unwrap();
        let second = "127.0.0.1:2".parse().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_attempts = Arc::clone(&attempts);
        let handshakes = Arc::new(AtomicU32::new(0));
        let observed_handshakes = Arc::clone(&handshakes);

        let selected = connect_resolved_udp_endpoint(
            vec![first, second],
            move |address| {
                observed_attempts.lock().unwrap().push(address);
                async move {
                    if address == first {
                        Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "mock IPv6/source bind failure",
                        ))
                    } else {
                        Ok(address)
                    }
                }
            },
            move |address, endpoint| async move {
                observed_handshakes.fetch_add(1, Ordering::Relaxed);
                assert_eq!(address, endpoint);
                Ok(address)
            },
        )
        .await
        .unwrap();

        assert_eq!(selected, second);
        assert_eq!(&*attempts.lock().unwrap(), &[first, second]);
        assert_eq!(handshakes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn quic_or_auth_failure_does_not_retry_the_next_server_address() {
        let first = "127.0.0.1:1".parse().unwrap();
        let second = "127.0.0.1:2".parse().unwrap();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_attempts = Arc::clone(&attempts);

        let error = connect_resolved_udp_endpoint(
            vec![first, second],
            move |address| {
                observed_attempts.lock().unwrap().push(address);
                async move { Ok(address) }
            },
            |_address, _endpoint| async {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mock Hysteria2 authentication failure",
                ))
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(&*attempts.lock().unwrap(), &[first]);
    }

    #[tokio::test]
    async fn hysteria_endpoint_socket_remains_connected_and_filters_other_peers() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket =
            new_connected_hysteria_udp_socket(peer_address, &OutboundSocketOptions::default())
                .await
                .unwrap();

        assert_eq!(socket.peer_addr().unwrap(), peer_address);
        let client_address = socket.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::from_std(socket).unwrap();
        stranger.send_to(b"stranger", client_address).await.unwrap();
        peer.send_to(b"peer", client_address).await.unwrap();

        let mut buffer = [0_u8; 32];
        let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buffer))
            .await
            .expect("the connected peer's datagram should be delivered")
            .unwrap();
        assert_eq!(&buffer[..length], b"peer");
    }

    #[tokio::test]
    async fn quinn_runtime_transmits_on_the_connected_hysteria_socket() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let socket =
            new_connected_hysteria_udp_socket(peer_address, &OutboundSocketOptions::default())
                .await
                .unwrap();
        let client_address = socket.local_addr().unwrap();
        assert_eq!(socket.peer_addr().unwrap(), peer_address);

        use quinn::Runtime as _;
        let socket = quinn::TokioRuntime.wrap_udp_socket(socket).unwrap();
        let transmit = quinn::udp::Transmit {
            destination: peer_address,
            ecn: None,
            contents: b"quinn-connected",
            segment_size: None,
            src_ip: None,
        };
        loop {
            match socket.try_send(&transmit) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut poller = socket.clone().create_io_poller();
                    poll_fn(|context| poller.as_mut().poll_writable(context))
                        .await
                        .unwrap();
                }
                Err(error) => panic!("Quinn rejected a connected UDP socket: {error}"),
            }
        }

        let mut buffer = [0_u8; 32];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
                .await
                .expect("Quinn must send through the connected socket")
                .unwrap();
        assert_eq!(source, client_address);
        assert_eq!(&buffer[..length], b"quinn-connected");
    }

    #[test]
    fn tcp_only_network_is_not_advertised_as_udp_capable() {
        assert!(!Hysteria2TcpClientHandler::new(false).supports_native_udp());
        assert!(Hysteria2TcpClientHandler::new(true).supports_native_udp());
    }

    #[tokio::test]
    async fn client_interoperates_with_shoes_server_for_tcp_udp_obfs_and_brutal() {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test certificate");
        let server_tls = Arc::new(crate::rustls_config_util::create_server_config(
            certificate.cert.pem().as_bytes(),
            certificate.signing_key.serialize_pem().as_bytes(),
            Vec::new(),
            &["h3".to_string()],
            &[],
        ));
        let server_quic: quinn::crypto::rustls::QuicServerConfig =
            server_tls.try_into().expect("convert test QUIC server TLS");

        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = reservation.local_addr().unwrap();
        drop(reservation);

        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::ANY],
            ConnectAction::new_allow(None, build_direct_chain_group(Arc::clone(&resolver))),
        )]));
        let selector = SelectorSlot::new(selector, Arc::clone(&resolver));
        let shutdown = CancellationToken::new();
        let server_tasks = crate::hysteria2_server::start_hysteria2_server(
            server_address,
            Arc::new(server_quic),
            StaticUserRegistry::single_password("test-password"),
            false,
            selector,
            1,
            true,
            100,
            100,
            false,
            Some(Salamander::new("test-obfs")),
            Arc::new(Hysteria2Masquerade::new(None).unwrap()),
            shutdown.clone(),
            CancellationToken::new(),
        )
        .await
        .expect("start Hysteria2 test server");

        let tcp_echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_echo_address = tcp_echo.local_addr().unwrap();
        let tcp_echo_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_echo.accept().await.unwrap();
            let mut data = [0_u8; 32];
            let length = stream.read(&mut data).await.unwrap();
            stream.write_all(&data[..length]).await.unwrap();
        });

        let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_echo_address = udp_echo.local_addr().unwrap();
        let udp_echo_task = tokio::spawn(async move {
            let mut data = [0_u8; 4096];
            for _ in 0..2 {
                let (length, peer) = udp_echo.recv_from(&mut data).await.unwrap();
                udp_echo.send_to(&data[..length], peer).await.unwrap();
            }
        });

        // The accept task owns the actual bind.  One yield is sufficient in the
        // common case; the small delay removes scheduler-order flakes on Windows.
        tokio::time::sleep(Duration::from_millis(25)).await;

        let tls = ClientQuicConfig {
            verify: false,
            sni_hostname: NoneOrOne::One("localhost".to_string()),
            ..ClientQuicConfig::default()
        };
        let build_chain = |password: &str| {
            build_client_proxy_chain(
                OneOrSome::One(crate::config::ClientChainHop::Single(
                    crate::config::ConfigSelection::Config(ClientConfig {
                        address: NetLocation::from_ip_addr(
                            server_address.ip(),
                            server_address.port(),
                        ),
                        protocol: ClientProxyConfig::Hysteria2 {
                            password: password.to_string(),
                            udp_enabled: true,
                            up_mbps: 50,
                            down_mbps: 50,
                            obfs: Some(Hysteria2ClientObfs::Salamander {
                                password: "test-obfs".to_string(),
                            }),
                            server_ports: NoneOrSome::None,
                            hop_interval: None,
                        },
                        transport: crate::config::Transport::Quic,
                        quic_settings: Some(tls.clone()),
                        ..ClientConfig::default()
                    }),
                )),
                Arc::clone(&resolver),
            )
        };

        let rejected_chain = build_chain("wrong-password");
        let rejection = match rejected_chain
            .connect_tcp(
                NetLocation::from_ip_addr(tcp_echo_address.ip(), tcp_echo_address.port()).into(),
                &resolver,
            )
            .await
        {
            Ok(_) => panic!("a non-233 authentication response was accepted"),
            Err(error) => error,
        };
        assert_eq!(rejection.kind(), io::ErrorKind::PermissionDenied);

        let chain = build_chain("test-password");

        let mut proxied = chain
            .connect_tcp(
                NetLocation::from_ip_addr(tcp_echo_address.ip(), tcp_echo_address.port()).into(),
                &resolver,
            )
            .await
            .expect("open Hysteria2 TCP request")
            .client_stream;
        proxied.write_all(b"tcp-round-trip").await.unwrap();
        proxied.flush().await.unwrap();
        let mut tcp_reply = [0_u8; 14];
        tokio::time::timeout(Duration::from_secs(3), proxied.read_exact(&mut tcp_reply))
            .await
            .expect("TCP echo timeout")
            .unwrap();
        assert_eq!(&tcp_reply, b"tcp-round-trip");

        let mut proxied_udp = chain
            .connect_udp_bidirectional(
                &resolver,
                NetLocation::from_ip_addr(udp_echo_address.ip(), udp_echo_address.port()).into(),
            )
            .await
            .expect("open Hysteria2 UDP request");

        let fragmented_payload = vec![0x5a; 2048];
        poll_fn(|cx| Pin::new(&mut *proxied_udp).poll_write_message(cx, &fragmented_payload))
            .await
            .unwrap();
        let mut fragmented_reply = [0_u8; 4096];
        let mut fragmented_reply = ReadBuf::new(&mut fragmented_reply);
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| Pin::new(&mut *proxied_udp).poll_read_message(cx, &mut fragmented_reply)),
        )
        .await
        .expect("fragmented UDP echo timeout")
        .unwrap();
        assert_eq!(fragmented_reply.filled(), fragmented_payload);

        poll_fn(|cx| Pin::new(&mut *proxied_udp).poll_write_message(cx, b"udp-round-trip"))
            .await
            .unwrap();
        let mut udp_reply = [0_u8; 4096];
        let mut udp_reply = ReadBuf::new(&mut udp_reply);
        tokio::time::timeout(
            Duration::from_secs(3),
            poll_fn(|cx| Pin::new(&mut *proxied_udp).poll_read_message(cx, &mut udp_reply)),
        )
        .await
        .expect("UDP echo timeout")
        .unwrap();
        assert_eq!(udp_reply.filled(), b"udp-round-trip");

        shutdown.cancel();
        tcp_echo_task.await.unwrap();
        udp_echo_task.await.unwrap();
        for task in server_tasks {
            let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
        }
    }
}
