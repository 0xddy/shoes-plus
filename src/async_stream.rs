use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

#[cfg(target_family = "unix")]
use tokio::net::UnixStream;

use crate::address::{NetLocation, ResolvedLocation};

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    // Write a ping message to the stream, if supported.
    // This should end up calling the highest level stream abstraction that supports
    // pings, and should only result in a single message.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncReadMessage {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncWriteMessage {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncFlushMessage {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
}

pub trait AsyncShutdownMessage {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

/// Extension trait that provides an async `shutdown_message()` method for types
/// implementing `AsyncShutdownMessage`. Similar to `AsyncWriteExt::shutdown()`.
pub trait AsyncShutdownMessageExt: AsyncShutdownMessage {
    /// Shuts down the message stream, signaling that no more messages will be sent.
    fn shutdown_message(&mut self) -> ShutdownMessageFuture<'_, Self>
    where
        Self: Unpin,
    {
        ShutdownMessageFuture { stream: self }
    }
}

/// Future returned by `AsyncShutdownMessageExt::shutdown_message()`.
pub struct ShutdownMessageFuture<'a, T: ?Sized> {
    stream: &'a mut T,
}

impl<T: AsyncShutdownMessage + Unpin + ?Sized> Future for ShutdownMessageFuture<'_, T> {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_shutdown_message(cx)
    }
}

// Blanket implementation for all types that implement AsyncShutdownMessage
impl<T: AsyncShutdownMessage + ?Sized> AsyncShutdownMessageExt for T {}

pub trait AsyncReadTargetedMessage {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>>;
}

pub trait AsyncWriteTargetedMessage {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncReadSourcedMessage {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>>;
}

pub trait AsyncWriteSourcedMessage {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

/// A session-based datagram target carried across an inbound protocol boundary.
///
/// `destination` preserves the peer's original hostname together with every
/// ordered address returned by policy DNS. `response_address` is deliberately
/// separate: it is the literal source address to put on response frames and
/// must not replace the original destination used by routing rules.
#[derive(Debug, Clone)]
pub struct SessionMessageTarget {
    destination: ResolvedLocation,
    response_address: Option<SocketAddr>,
}

impl SessionMessageTarget {
    pub fn new(destination: ResolvedLocation, response_address: SocketAddr) -> Self {
        Self {
            destination,
            response_address: Some(response_address),
        }
    }

    /// Build a parsed target whose DNS resolution is intentionally deferred to
    /// the routing layer. This keeps multiplexed protocol codecs free of
    /// per-destination I/O and head-of-line blocking.
    pub fn unresolved(destination: NetLocation) -> Self {
        Self {
            destination: destination.into(),
            response_address: None,
        }
    }

    pub fn destination(&self) -> &ResolvedLocation {
        &self.destination
    }

    pub fn into_destination(self) -> ResolvedLocation {
        self.destination
    }

    pub fn response_address(&self) -> SocketAddr {
        self.response_address
            .expect("resolved session target must have a response address")
    }

    pub fn response_address_opt(&self) -> Option<SocketAddr> {
        self.response_address
    }
}

/// One event read from a session-multiplexed datagram stream.
///
/// Session closure is a protocol event, not byte-stream EOF. Keeping it explicit
/// lets a router retire exactly one UDP association while the surrounding XUDP
/// connection continues carrying other sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMessageStatus {
    New,
    Keep,
}

#[derive(Debug, Clone)]
pub enum SessionMessage {
    Data {
        session_id: u16,
        status: SessionMessageStatus,
        target: SessionMessageTarget,
    },
    End {
        session_id: u16,
    },
    /// The peer sent `Keep` for a session the protocol codec no longer knows.
    ///
    /// This is deliberately an event rather than a stream error: the router can
    /// reject only this session while preserving the surrounding multiplexed
    /// connection.
    UnknownKeep {
        session_id: u16,
    },
    /// The peer reused an active session ID without an intervening End.
    /// This is rejected at session scope so other multiplexed sessions survive.
    Rejected {
        session_id: u16,
    },
}

/// Session-based message reading trait. Used by protocols like XUDP that have session IDs.
/// Returns either one datagram or the explicit end of one protocol session.
pub trait AsyncReadSessionMessage {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>>;
}

/// Session-based message writing trait. Used by protocols like XUDP that have session IDs.
/// Writes data for a specific session ID to a target address.
pub trait AsyncWriteSessionMessage {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SessionMessageTarget,
    ) -> Poll<std::io::Result<()>>;

    /// Write an End frame for one session without shutting down the surrounding
    /// multiplexed stream.
    fn poll_write_session_end(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>>;
}

impl AsyncReadMessage for UdpSocket {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for UdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        // TODO: send back an error if the whole buf.len() wasn't sent?
        self.poll_send(cx, buf).map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {}

pub trait AsyncMessageStream:
    AsyncReadMessage
    + AsyncWriteMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
    /// The actual fixed peer selected by a direct connected datagram socket.
    ///
    /// Proxy-backed streams leave this as `None`: their transport peer is the
    /// proxy, not the final response address. A direct `UdpSocket` overrides it so
    /// fallback across resolved candidates is reflected in response metadata.
    fn connected_remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Server stream trait connected to proxy clients, where received messages have a target address,
/// and we write forwarded messages along with the source address we received them from.
pub trait AsyncTargetedMessageStream:
    AsyncReadTargetedMessage
    + AsyncWriteSourcedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Client stream trait connected directly to targets or to proxy servers, where received messages
/// come with a source address, and we write where we want messages to be sent.
pub trait AsyncSourcedMessageStream:
    AsyncReadSourcedMessage
    + AsyncWriteTargetedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Session-based stream trait for protocols like XUDP that multiplex sessions over a single connection.
/// Reads return (session_id, data, source_addr) and writes target (session_id, data, target_addr).
pub trait AsyncSessionMessageStream:
    AsyncReadSessionMessage
    + AsyncWriteSessionMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

impl AsyncPing for TcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncStream for TcpStream {}

#[cfg(target_family = "unix")]
impl AsyncPing for UnixStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

#[cfg(target_family = "unix")]
impl AsyncStream for UnixStream {}

impl AsyncPing for UdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncMessageStream for UdpSocket {
    fn connected_remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

// pattern copied from deref_async_read macro: https://docs.rs/tokio/latest/src/tokio/io/async_read.rs.html#60
impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for &mut T {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for Box<T> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for &mut T {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for Box<T> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for &mut T {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for Box<T> {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for &mut T {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for Box<T> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for &mut T {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for Box<T> {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for &mut T {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for Box<T> {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for &mut T {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for Box<T> {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for &mut T {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for Box<T> {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for &mut T {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for Box<T> {}
impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for &mut T {}

impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for Box<T> {
    fn connected_remote_addr(&self) -> Option<SocketAddr> {
        (**self).connected_remote_addr()
    }
}
impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for &mut T {
    fn connected_remote_addr(&self) -> Option<SocketAddr> {
        (**self).connected_remote_addr()
    }
}

impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for &mut T {}

impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for &mut T {}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for Box<T> {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for &mut T {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for Box<T> {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SessionMessageTarget,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }

    fn poll_write_session_end(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_end(cx, session_id, has_error)
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for &mut T {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SessionMessageTarget,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }

    fn poll_write_session_end(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_end(cx, session_id, has_error)
    }
}

impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for &mut T {}
