//! Custom RuntimeProvider that routes TCP connections through proxy chains.

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures::future::poll_fn;
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{QuicSocketBinder, RuntimeProvider, Spawn, TokioTime};
use parking_lot::Mutex;
use quinn::Runtime as QuinnRuntime;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;
use crate::socket_util::new_udp_socket;

/// Default connection timeout for DNS server connections. Matches hickory-dns CONNECT_TIMEOUT.
#[cfg(test)]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// RuntimeProvider that routes stream and datagram connections through a proxy chain.
/// Direct-only QUIC keeps using a native UDP socket so interface binding and the
/// operating system's UDP implementation remain unchanged. Proxied QUIC uses a
/// fixed-destination message stream supplied by `ClientChainGroup`.
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    chain_group: Arc<ClientChainGroup>,
    /// Resolver for proxy server hostnames (not the DNS queries themselves).
    /// Uses NativeResolver since we can't use the DNS server we're trying to reach.
    bootstrap_resolver: Arc<dyn Resolver>,
    /// Bind interface for UDP/QUIC (from direct-only chain).
    bind_interface: Option<String>,
    /// QUIC socket binder that uses the bind_interface.
    quic_binder: ProxyQuicBinder,
    /// Timeout for establishing connections to DNS upstreams.
    connect_timeout: Duration,
}

impl ProxyRuntimeProvider {
    /// Create with the given chain group, bootstrap resolver, and connect timeout.
    pub fn with_bootstrap(
        chain_group: Arc<ClientChainGroup>,
        bootstrap_resolver: Arc<dyn Resolver>,
        connect_timeout: Duration,
    ) -> Self {
        let bind_interface = chain_group.get_bind_interface().map(ToString::to_string);
        let quic_binder = ProxyQuicBinder {
            chain_group: chain_group.clone(),
            bootstrap_resolver: bootstrap_resolver.clone(),
            bind_interface: bind_interface.clone(),
            connect_timeout,
        };
        Self {
            chain_group,
            bootstrap_resolver,
            bind_interface,
            quic_binder,
            connect_timeout,
        }
    }
}

/// Spawn handle for tokio runtime.
#[derive(Clone, Default)]
pub struct TokioSpawnHandle;

impl Spawn for TokioSpawnHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        tokio::spawn(future);
    }
}

/// Type alias for our wrapped TCP stream.
type ProxiedTcp = AsyncIoTokioAsStd<Box<dyn AsyncStream>>;

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioSpawnHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = ProxiedTcp;

    fn create_handle(&self) -> Self::Handle {
        TokioSpawnHandle
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();
        let timeout = timeout
            .map(|timeout| timeout.min(self.connect_timeout))
            .unwrap_or(self.connect_timeout);

        Box::pin(async move {
            let address = match server_addr.ip() {
                IpAddr::V4(addr) => Address::Ipv4(addr),
                IpAddr::V6(addr) => Address::Ipv6(addr),
            };
            let target = NetLocation::new(address, server_addr.port());

            let started = std::time::Instant::now();
            let connect_future = chain_group.connect_tcp(target.into(), &resolver);
            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(result)) => {
                    log::debug!(
                        "DNS upstream connect to {} succeeded in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    Ok(AsyncIoTokioAsStd(result.client_stream))
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "DNS upstream connect to {} failed in {:?}: {}",
                        server_addr,
                        started.elapsed(),
                        e
                    );
                    Err(e)
                }
                Err(_) => {
                    log::warn!(
                        "DNS upstream connect to {} timed out in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "DNS server connection to {server_addr} timed out after {timeout:?}"
                        ),
                    ))
                }
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let bind_interface = self.bind_interface.clone();

        Box::pin(async move {
            if bind_interface.is_some() {
                // Use our socket_util which supports bind_interface.
                new_udp_socket(local_addr.is_ipv6(), bind_interface)
            } else {
                // Default: bind directly.
                tokio::net::UdpSocket::bind(local_addr).await
            }
        })
    }

    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&self.quic_binder)
    }
}

/// QUIC socket binder that supports both native direct UDP and proxy datagram streams.
#[derive(Clone)]
struct ProxyQuicBinder {
    chain_group: Arc<ClientChainGroup>,
    bootstrap_resolver: Arc<dyn Resolver>,
    bind_interface: Option<String>,
    connect_timeout: Duration,
}

impl QuicSocketBinder for ProxyQuicBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        if !self.chain_group.is_direct_only() {
            if !self.chain_group.supports_udp() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "DNS-over-QUIC client_chain has no UDP-capable chain",
                ));
            }
            return ProxyQuicSocket::spawn(
                local_addr,
                server_addr,
                self.chain_group.clone(),
                self.bootstrap_resolver.clone(),
                self.connect_timeout,
            )
            .map(|socket| socket as Arc<dyn quinn::AsyncUdpSocket>);
        }

        let socket = if self.bind_interface.is_some() {
            // Use socket2 for bind_interface support.
            let socket2_socket = crate::socket_util::new_socket2_udp_socket(
                local_addr.is_ipv6(),
                self.bind_interface.clone(),
                Some(local_addr),
                false,
            )?;
            // Convert socket2 -> std::net::UdpSocket.
            #[cfg(unix)]
            {
                use std::os::unix::io::FromRawFd;
                use std::os::unix::io::IntoRawFd;
                let raw_fd = socket2_socket.into_raw_fd();
                unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) }
            }
            #[cfg(windows)]
            {
                use std::os::windows::io::FromRawSocket;
                use std::os::windows::io::IntoRawSocket;
                let raw_socket = socket2_socket.into_raw_socket();
                unsafe { std::net::UdpSocket::from_raw_socket(raw_socket) }
            }
        } else {
            // Default: bind directly.
            std::net::UdpSocket::bind(local_addr)?
        };

        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

const PROXY_QUIC_SEND_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
struct SharedIoError {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl SharedIoError {
    fn new(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: Arc::from(error.to_string()),
        }
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }
}

enum ProxyQuicTransport {
    Connecting,
    Connected(Box<dyn AsyncMessageStream>),
    Failed(SharedIoError),
}

struct ProxyQuicState {
    transport: ProxyQuicTransport,
    /// Quinn has one receive driver, but keeping the latest waker also lets a
    /// background write failure terminate that driver immediately.
    read_waker: Option<Waker>,
}

struct ProxyQuicShared {
    state: Mutex<ProxyQuicState>,
}

impl ProxyQuicShared {
    fn new_connecting() -> Self {
        Self {
            state: Mutex::new(ProxyQuicState {
                transport: ProxyQuicTransport::Connecting,
                read_waker: None,
            }),
        }
    }

    fn connected(&self, stream: Box<dyn AsyncMessageStream>) {
        let waker = {
            let mut state = self.state.lock();
            state.transport = ProxyQuicTransport::Connected(stream);
            state.read_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn fail(&self, error: io::Error) {
        let waker = {
            let mut state = self.state.lock();
            if matches!(state.transport, ProxyQuicTransport::Failed(_)) {
                return;
            }
            state.transport = ProxyQuicTransport::Failed(SharedIoError::new(error));
            state.read_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn error(&self) -> Option<io::Error> {
        let state = self.state.lock();
        match &state.transport {
            ProxyQuicTransport::Failed(error) => Some(error.to_io_error()),
            ProxyQuicTransport::Connecting | ProxyQuicTransport::Connected(_) => None,
        }
    }
}

/// Adapts shoes' fixed-destination UDP message abstraction to Quinn's abstract
/// UDP socket. Each `AsyncMessageStream` message is exactly one QUIC datagram;
/// no byte-stream framing or destination rewriting happens in this adapter.
struct ProxyQuicSocket {
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    shared: Arc<ProxyQuicShared>,
    send_tx: mpsc::Sender<Vec<u8>>,
}

impl std::fmt::Debug for ProxyQuicSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyQuicSocket")
            .field("local_addr", &self.local_addr)
            .field("server_addr", &self.server_addr)
            .finish_non_exhaustive()
    }
}

impl ProxyQuicSocket {
    fn spawn(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        chain_group: Arc<ClientChainGroup>,
        resolver: Arc<dyn Resolver>,
        connect_timeout: Duration,
    ) -> io::Result<Arc<Self>> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            io::Error::other(format!(
                "DNS-over-QUIC proxy detour requires a Tokio runtime: {error}"
            ))
        })?;
        let shared = Arc::new(ProxyQuicShared::new_connecting());
        let (send_tx, send_rx) = mpsc::channel(PROXY_QUIC_SEND_QUEUE_CAPACITY);
        let socket = Arc::new(Self {
            local_addr,
            server_addr,
            shared: shared.clone(),
            send_tx,
        });

        runtime.spawn(async move {
            let address = match server_addr.ip() {
                IpAddr::V4(address) => Address::Ipv4(address),
                IpAddr::V6(address) => Address::Ipv6(address),
            };
            let location = NetLocation::new(address, server_addr.port());
            let target = ResolvedLocation::with_resolved(location, server_addr);
            let connect = chain_group.connect_udp_bidirectional(&resolver, target);
            let stream = match tokio::time::timeout(connect_timeout, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    shared.fail(io::Error::new(
                        error.kind(),
                        format!(
                            "DNS-over-QUIC proxy detour to {server_addr} failed: {error}"
                        ),
                    ));
                    return;
                }
                Err(_) => {
                    shared.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "DNS-over-QUIC proxy detour to {server_addr} timed out after {connect_timeout:?}"
                        ),
                    ));
                    return;
                }
            };
            shared.connected(stream);
            run_proxy_quic_writer(shared, send_rx).await;
        });

        Ok(socket)
    }

    #[cfg(test)]
    fn from_connected_stream(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        stream: Box<dyn AsyncMessageStream>,
    ) -> Arc<Self> {
        let shared = Arc::new(ProxyQuicShared::new_connecting());
        shared.connected(stream);
        let (send_tx, send_rx) = mpsc::channel(PROXY_QUIC_SEND_QUEUE_CAPACITY);
        tokio::spawn(run_proxy_quic_writer(shared.clone(), send_rx));
        Arc::new(Self {
            local_addr,
            server_addr,
            shared,
            send_tx,
        })
    }
}

async fn run_proxy_quic_writer(shared: Arc<ProxyQuicShared>, mut send_rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(message) = send_rx.recv().await {
        let write_result = poll_fn(|cx| {
            let mut state = shared.state.lock();
            match &mut state.transport {
                ProxyQuicTransport::Connecting => Poll::Pending,
                ProxyQuicTransport::Connected(stream) => {
                    Pin::new(&mut **stream).poll_write_message(cx, &message)
                }
                ProxyQuicTransport::Failed(error) => Poll::Ready(Err(error.to_io_error())),
            }
        })
        .await;
        if let Err(error) = write_result {
            shared.fail(error);
            return;
        }

        let flush_result = poll_fn(|cx| {
            let mut state = shared.state.lock();
            match &mut state.transport {
                ProxyQuicTransport::Connecting => Poll::Pending,
                ProxyQuicTransport::Connected(stream) => {
                    Pin::new(&mut **stream).poll_flush_message(cx)
                }
                ProxyQuicTransport::Failed(error) => Poll::Ready(Err(error.to_io_error())),
            }
        })
        .await;
        if let Err(error) = flush_result {
            shared.fail(error);
            return;
        }
    }
}

type ReserveFuture = Pin<
    Box<
        dyn Future<
                Output = Result<
                    mpsc::OwnedPermit<Vec<u8>>,
                    tokio::sync::mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;

struct ProxyQuicPoller {
    sender: mpsc::Sender<Vec<u8>>,
    shared: Arc<ProxyQuicShared>,
    reserve: Mutex<Option<ReserveFuture>>,
}

impl std::fmt::Debug for ProxyQuicPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyQuicPoller").finish_non_exhaustive()
    }
}

impl quinn::UdpPoller for ProxyQuicPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.shared.error() {
            return Poll::Ready(Err(error));
        }

        let mut reserve = self.reserve.lock();
        if reserve.is_none() {
            *reserve = Some(Box::pin(self.sender.clone().reserve_owned()));
        }
        let result = reserve
            .as_mut()
            .expect("reserve future was just initialized")
            .as_mut()
            .poll(cx);
        match result {
            Poll::Ready(Ok(permit)) => {
                // Readiness is advisory. Releasing the reservation lets the
                // immediately following `try_send` put the actual datagram in
                // the bounded queue.
                drop(permit);
                *reserve = None;
                Poll::Ready(self.shared.error().map_or(Ok(()), Err))
            }
            Poll::Ready(Err(_)) => {
                *reserve = None;
                Poll::Ready(Err(self.shared.error().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "QUIC proxy writer stopped")
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl quinn::AsyncUdpSocket for ProxyQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(ProxyQuicPoller {
            sender: self.send_tx.clone(),
            shared: self.shared.clone(),
            reserve: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if let Some(error) = self.shared.error() {
            return Err(error);
        }
        if transmit.destination != self.server_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "QUIC proxy socket is fixed to {}, cannot send to {}",
                    self.server_addr, transmit.destination
                ),
            ));
        }
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "QUIC proxy socket does not support UDP segmentation offload",
            ));
        }

        self.send_tx
            .try_send(transmit.contents.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "QUIC proxy send queue is full")
                }
                mpsc::error::TrySendError::Closed(_) => self.shared.error().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "QUIC proxy writer stopped")
                }),
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive requires at least one buffer and metadata slot",
            )));
        }

        let mut state = self.shared.state.lock();
        state.read_waker = Some(cx.waker().clone());
        let result = match &mut state.transport {
            ProxyQuicTransport::Connecting => return Poll::Pending,
            ProxyQuicTransport::Failed(error) => return Poll::Ready(Err(error.to_io_error())),
            ProxyQuicTransport::Connected(stream) => {
                let mut read_buf = ReadBuf::new(&mut bufs[0]);
                match Pin::new(&mut **stream).poll_read_message(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            }
        };

        match result {
            Poll::Ready(Ok(len)) => {
                if len == 0 {
                    let error = io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QUIC proxy datagram stream closed",
                    );
                    state.transport = ProxyQuicTransport::Failed(SharedIoError::new(
                        io::Error::new(error.kind(), error.to_string()),
                    ));
                    return Poll::Ready(Err(error));
                }
                meta[0] = quinn::udp::RecvMeta {
                    addr: self.server_addr,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: (!self.local_addr.ip().is_unspecified())
                        .then_some(self.local_addr.ip()),
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Err(error)) => {
                state.transport = ProxyQuicTransport::Failed(SharedIoError::new(io::Error::new(
                    error.kind(),
                    error.to_string(),
                )));
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        // Proxy transports do not expose path MTU feedback to Quinn.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
    };
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;

    struct MockMessageStream {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl AsyncReadMessage for MockMessageStream {
        fn poll_read_message(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut().inbound.poll_recv(cx) {
                Poll::Ready(Some(message)) if message.len() <= buf.remaining() => {
                    buf.put_slice(&message);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Some(message)) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "mock datagram length {} exceeds receive buffer {}",
                        message.len(),
                        buf.remaining()
                    ),
                ))),
                Poll::Ready(None) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWriteMessage for MockMessageStream {
        fn poll_write_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(
                self.get_mut()
                    .outbound
                    .send(buf.to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mock receiver closed")),
            )
        }
    }

    impl AsyncFlushMessage for MockMessageStream {
        fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncShutdownMessage for MockMessageStream {
        fn poll_shutdown_message(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for MockMessageStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncMessageStream for MockMessageStream {}

    #[test]
    fn test_provider_is_clone() {
        // RuntimeProvider requires Clone
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
        let _cloned = provider.clone();
    }

    #[test]
    fn test_spawn_handle_is_clone() {
        let handle = TokioSpawnHandle;
        let _cloned = handle.clone();
    }

    #[tokio::test]
    async fn test_bind_udp_works_directly() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // UDP DNS works directly (not through proxy)
        let result = provider.bind_udp(local_addr, server_addr).await;
        assert!(
            result.is_ok(),
            "bind_udp should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_with_direct_chain_connects_to_target() {
        // This test verifies the provider correctly routes to the target.
        // Use localhost with a port that should be refused quickly.
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

        // Use localhost port 1 (reserved, should be refused quickly)
        let server_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = provider.connect_tcp(server_addr, None, None).await;
        // Connection should fail (connection refused)
        assert!(result.is_err());
    }

    #[test]
    fn test_create_handle() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
        let _handle = provider.create_handle();
    }

    #[test]
    fn test_quic_binder_available() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);
        assert!(provider.quic_binder().is_some());
    }

    #[tokio::test]
    async fn proxied_quic_socket_preserves_packet_boundaries_and_fixed_target() {
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let server_addr: SocketAddr = "192.0.2.53:853".parse().unwrap();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel();
        let socket = ProxyQuicSocket::from_connected_stream(
            local_addr,
            server_addr,
            Box::new(MockMessageStream {
                inbound: inbound_rx,
                outbound: outbound_tx,
            }),
        );

        let mut poller = quinn::AsyncUdpSocket::create_io_poller(socket.clone());
        poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: server_addr,
                ecn: None,
                contents: b"one-quic-packet",
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap();
        assert_eq!(outbound_rx.recv().await.unwrap(), b"one-quic-packet");

        inbound_tx.send(b"one-quic-response".to_vec()).unwrap();
        let mut storage = [0_u8; 64];
        let mut buffers = [IoSliceMut::new(&mut storage)];
        let mut metadata = [quinn::udp::RecvMeta::default()];
        let count = poll_fn(|cx| {
            quinn::AsyncUdpSocket::poll_recv(&*socket, cx, &mut buffers, &mut metadata)
        })
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(metadata[0].addr, server_addr);
        assert_eq!(metadata[0].len, b"one-quic-response".len());
        assert_eq!(metadata[0].stride, metadata[0].len);
        assert_eq!(
            &storage[..metadata[0].len],
            b"one-quic-response",
            "one proxy message must remain one QUIC datagram"
        );

        let wrong_target: SocketAddr = "192.0.2.54:853".parse().unwrap();
        let error = quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: wrong_target,
                ecn: None,
                contents: b"must-not-be-rerouted",
                segment_size: None,
                src_ip: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(outbound_rx.try_recv().is_err());

        let segmented = quinn::AsyncUdpSocket::try_send(
            &*socket,
            &quinn::udp::Transmit {
                destination: server_addr,
                ecn: None,
                contents: b"two-segments-must-not-be-flattened",
                segment_size: Some(16),
                src_ip: None,
            },
        )
        .unwrap_err();
        assert_eq!(segmented.kind(), io::ErrorKind::Unsupported);
        assert!(outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_connect_tcp_respects_timeout() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

        // Use an address that will hang (black hole) rather than refuse immediately.
        // 10.255.255.1 is a non-routable address that should cause the connection to hang.
        let server_addr: SocketAddr = "10.255.255.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(server_addr, None, Some(Duration::from_millis(100)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        // Verify timeout was respected (should complete in ~100ms, not 5+ seconds)
        assert!(
            elapsed < Duration::from_secs(1),
            "timeout should fire quickly, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_caps_passed_timeout_by_configured_connect_timeout() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, Duration::from_millis(100));

        let server_addr: SocketAddr = "10.255.255.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider
            .connect_tcp(server_addr, None, Some(Duration::from_secs(5)))
            .await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(1),
            "configured connect timeout should cap a longer request timeout, but took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_uses_default_timeout_when_none() {
        let resolver = Arc::new(NativeResolver::new());
        let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
        let provider =
            ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, DEFAULT_CONNECT_TIMEOUT);

        // Use a black hole address
        let server_addr: SocketAddr = "10.255.255.1:53".parse().unwrap();

        let start = std::time::Instant::now();
        let result = provider.connect_tcp(server_addr, None, None).await;
        let elapsed = start.elapsed();

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("connection should fail"),
        };
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "should be timeout error"
        );

        // Default timeout is 5 seconds; verify it's bounded (less than 10 seconds)
        assert!(
            elapsed < Duration::from_secs(10),
            "default timeout should apply, but took {:?}",
            elapsed
        );
        // Also verify it waited at least close to 5 seconds (with some tolerance)
        assert!(
            elapsed >= Duration::from_secs(4),
            "should wait for default timeout (~5s), but only waited {:?}",
            elapsed
        );
    }
}
