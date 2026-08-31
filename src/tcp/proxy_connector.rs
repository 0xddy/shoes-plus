//! ProxyConnector trait - Wraps protocols on existing streams.
//!
//! This trait handles protocol setup for proxy connections. It is responsible for:
//! - Setting up proxy protocols (VLESS, VMess, SOCKS5, etc.) on existing streams
//! - UDP-over-TCP tunneling through proxy protocols
//!
//! ## Design
//!
//! Every `ClientConfig` with a non-direct protocol implicitly defines a `ProxyConnector`
//! through its `protocol` and `address` fields.
//!
//! When a config is used:
//! - **As hop 0**: The ProxyConnector wraps the stream from SocketConnector
//! - **As hop 1+**: The ProxyConnector wraps the stream from the previous hop
//!
//! `protocol: direct` does NOT create a ProxyConnector - it only creates a SocketConnector.

use async_trait::async_trait;
use std::fmt::Debug;

use tokio::time::Instant;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// Trait for proxy protocol connectors.
///
/// Used to wrap protocols on existing streams. The stream may come from:
/// - A SocketConnector (at hop 0)
/// - A previous ProxyConnector (at hop 1+)
///
/// ## Implementations
///
/// - `TcpClientConnector`: For all proxy protocols (SOCKS5, HTTP, VMess, VLESS, etc.)
#[async_trait]
pub trait ProxyConnector: Send + Sync + Debug {
    /// Returns the proxy server address.
    ///
    /// This is used to determine where the SocketConnector should connect to
    /// when this is the first ProxyConnector in the chain.
    fn proxy_location(&self) -> &NetLocation;

    /// Optional exact DNS upstream used to resolve this proxy server before
    /// the preceding hop connects to it. Hop 0 is resolved by its
    /// [`SocketConnector`](super::socket_connector::SocketConnector); this
    /// accessor preserves the same per-outbound resolver semantics for hop 1+.
    fn dns_resolver(&self) -> Option<&str> {
        None
    }

    /// Check if this connector supports UDP-over-TCP tunneling.
    fn supports_udp_over_tcp(&self) -> bool;

    /// Check if this connector supports protocol-native UDP datagrams.
    fn supports_native_udp(&self) -> bool {
        false
    }

    /// Whether this protocol's UDP wire format requires the final destination
    /// to be projected to a literal IP before protocol setup.
    fn requires_literal_udp_target(&self) -> bool {
        false
    }

    /// Whether the final protocol has a write-triggered handshake in the Go
    /// implementation.  Composite handlers propagate this from their inner
    /// Trojan/VLESS handler.
    fn needs_handshake_for_write(&self) -> bool {
        false
    }

    /// Setup protocol on existing stream.
    ///
    /// # Arguments
    /// * `stream` - Existing transport stream
    /// * `target` - Where traffic should reach through this hop
    ///              (either the next proxy, or the final destination)
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Setup a final hop and return the equivalent sing-box
    /// `NeedHandshakeForWrite` timing boundary, when the protocol has one.
    ///
    /// Ordinary connections continue to use [`Self::setup_tcp_stream`].
    async fn setup_tcp_stream_with_write_handshake_boundary(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<(TcpClientSetupResult, Option<Instant>)> {
        if !self.needs_handshake_for_write() {
            return Ok((self.setup_tcp_stream(stream, target).await?, None));
        }

        let (result, started_at) =
            crate::tcp::write_handshake::observe(self.setup_tcp_stream(stream, target)).await;
        result.map(|setup| (setup, started_at))
    }

    /// Setup bidirectional UDP-over-TCP on existing stream.
    ///
    /// # Arguments
    /// * `stream` - Existing transport stream
    /// * `target` - The destination for all UDP packets
    ///              May include pre-resolved address to avoid duplicate DNS lookups.
    ///
    /// # Returns
    /// An AsyncMessageStream that sends/receives UDP packets to/from the target.
    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>>;

    /// Wrap a native UDP socket connected to this proxy server.
    async fn setup_native_udp(
        &self,
        _stream: Box<dyn AsyncMessageStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "connector does not support native UDP",
        ))
    }
}
