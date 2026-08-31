// XUDP message stream - protocol-agnostic UDP session multiplexing
// Wraps any AsyncStream and provides XUDP frame encoding/decoding with session management
// Used by both VLESS and VMess protocols

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadSessionMessage,
    AsyncSessionMessageStream, AsyncShutdownMessage, AsyncStream, AsyncWriteMessage,
    AsyncWriteSessionMessage, SessionMessage, SessionMessageStatus, SessionMessageTarget,
};
use crate::resolver::Resolver;

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};

type IncomingMessage = (Vec<u8>, u16, SessionMessageStatus, NetLocation);

enum DecodedSessionMessage {
    Ignored,
    Data {
        data: Vec<u8>,
        session_id: u16,
        status: SessionMessageStatus,
        destination: NetLocation,
    },
    End {
        session_id: u16,
    },
    UnknownKeep {
        session_id: u16,
    },
    Rejected {
        session_id: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncomingFrameStatus {
    Data(SessionMessageStatus),
    End,
    KeepAlive,
    UnknownKeep,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteState {
    Idle,
    Buffered,
}

pub struct XudpMessageStream {
    /// Underlying byte stream (VLESS VisionStream, VMess stream, or any TLS stream) that reads/writes raw XUDP frame bytes
    inner_stream: Box<dyn AsyncStream>,

    /// Read buffer for incoming XUDP frames
    read_buffer: BytesMut,

    /// Write buffer for outgoing XUDP frames
    write_buffer: BytesMut,

    /// Whether one accepted frame still has bytes (or an inner flush) pending.
    /// A new message is never encoded until this state returns to `Idle`.
    write_state: WriteState,

    /// Maps session_id -> ORIGINAL destination (before resolution)
    /// This preserves hostnames for encoding in response frames
    session_to_original_destination: HashMap<u16, NetLocation>,

    /// Sessions for which the peer has already seen a New frame.  This is
    /// deliberately independent of the address maps: an outbound client must
    /// pre-register session 0 while still sending New on its first packet.
    peer_opened_sessions: HashSet<u16>,

    /// Buffered incoming message (if we read a complete frame)
    /// Stores one decoded datagram when the caller-provided buffer is too small.
    incoming_message: Option<IncomingMessage>,

    /// EOF flag
    is_eof: bool,
}

impl XudpMessageStream {
    /// Build an XUDP codec. Hostnames are preserved and resolved by the router.
    pub fn new(inner_stream: Box<dyn AsyncStream>) -> Self {
        Self::new_without_resolver(inner_stream)
    }

    /// Backward-compatible constructor. Resolution is intentionally deferred to
    /// the routing layer, so the resolver is no longer used by the codec.
    pub fn new_with_resolver(
        inner_stream: Box<dyn AsyncStream>,
        _resolver: std::sync::Arc<dyn Resolver>,
    ) -> Self {
        Self::new_without_resolver(inner_stream)
    }

    fn new_without_resolver(inner_stream: Box<dyn AsyncStream>) -> Self {
        Self {
            inner_stream,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::with_capacity(65536),
            write_state: WriteState::Idle,
            session_to_original_destination: HashMap::new(),
            peer_opened_sessions: HashSet::new(),
            incoming_message: None,
            is_eof: false,
        }
    }

    /// Feed initial unparsed data into the read buffer
    /// Used when protocol header parsing (VLESS/VMess) consumed data that belongs to XUDP frames
    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        log::debug!(
            "[XUDP] Feeding {} bytes of initial data to read buffer",
            data.len()
        );
        self.read_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Register the current target for the exact peer-provided session ID.
    /// Per-destination reverse state is intentionally not retained: a full-cone
    /// session may visit unbounded targets, while response frames carry their
    /// routed subflow target explicitly.
    fn register_session(&mut self, session_id: u16, original_destination: &NetLocation) {
        self.session_to_original_destination
            .insert(session_id, original_destination.clone());
        log::debug!(
            "[XUDP] Session {} registered for {}",
            session_id,
            original_destination
        );
    }

    fn validate_incoming_status(
        &mut self,
        metadata: &FrameMetadata,
    ) -> std::io::Result<IncomingFrameStatus> {
        match metadata.status {
            SessionStatus::New => {
                if !self.peer_opened_sessions.insert(metadata.session_id) {
                    return Ok(IncomingFrameStatus::Rejected);
                }
                Ok(IncomingFrameStatus::Data(SessionMessageStatus::New))
            }
            SessionStatus::Keep => {
                if self.peer_opened_sessions.contains(&metadata.session_id) {
                    Ok(IncomingFrameStatus::Data(SessionMessageStatus::Keep))
                } else {
                    Ok(IncomingFrameStatus::UnknownKeep)
                }
            }
            SessionStatus::End => Ok(IncomingFrameStatus::End),
            SessionStatus::KeepAlive => Ok(IncomingFrameStatus::KeepAlive),
        }
    }

    fn update_session_target(&mut self, metadata: &FrameMetadata) {
        if let Some(ref target) = metadata.target {
            log::debug!(
                "[XUDP READ] Updating session {} mapping to target {}",
                metadata.session_id,
                target
            );
            self.session_to_original_destination
                .insert(metadata.session_id, target.clone());
        }
    }

    fn forget_session(&mut self, session_id: u16) {
        self.session_to_original_destination.remove(&session_id);
        self.peer_opened_sessions.remove(&session_id);
    }

    /// Try to decode one complete XUDP frame from the read buffer.
    ///
    /// This function must NOT consume any bytes from the buffer unless
    /// it successfully decodes a complete frame. Otherwise, partial frames would
    /// be lost when the function is called again with more data.
    ///
    /// Returns:
    ///   Ok(Some(message)) - Successfully decoded a complete frame
    ///   Ok(None) - Buffer doesn't contain a complete frame yet (need more data)
    ///   Err(e) - Error during decoding
    fn try_decode_one_frame(&mut self) -> std::io::Result<Option<DecodedSessionMessage>> {
        log::debug!(
            "[XUDP READ] Attempting to decode frame, buffer len: {}",
            self.read_buffer.len()
        );

        // First, peek at the buffer to determine total frame size WITHOUT consuming anything.
        // We need to check: metadata_len (2 bytes) + metadata + data_len (2 bytes) + data

        // Need at least 2 bytes for metadata length
        if self.read_buffer.len() < 2 {
            log::debug!("[XUDP READ] Buffer too short for metadata length field");
            return Ok(None);
        }

        let metadata_len = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

        // Check if we have complete metadata
        if self.read_buffer.len() < 2 + metadata_len {
            log::debug!("[XUDP READ] Buffer too short for complete metadata");
            return Ok(None);
        }

        // Peek at metadata to check if frame has data
        if metadata_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("metadata too short: {}", metadata_len),
            ));
        }

        // Peek at the option byte after session_id and status.
        let option_byte = self.read_buffer[2 + 3]; // Skip metadata_len(2) + session_id(2) + status(1)

        let has_data = (option_byte & FrameOption::DATA) != 0;
        let data_len = if has_data {
            // DATA is framed the same way for every status. In particular, End
            // and KeepAlive payloads must be consumed even though they are not
            // delivered to the UDP router.
            let data_len_offset = 2 + metadata_len;
            if self.read_buffer.len() < data_len_offset + 2 {
                log::debug!("[XUDP READ] Buffer too short for data length field");
                return Ok(None);
            }

            let data_len = u16::from_be_bytes([
                self.read_buffer[data_len_offset],
                self.read_buffer[data_len_offset + 1],
            ]) as usize;
            let total_frame_len = data_len_offset + 2 + data_len;
            if self.read_buffer.len() < total_frame_len {
                log::debug!(
                    "[XUDP READ] Buffer too short for complete frame: have {}, need {}",
                    self.read_buffer.len(),
                    total_frame_len
                );
                return Ok(None);
            }
            Some(data_len)
        } else {
            None
        };

        // We have the complete metadata and, when present, the complete DATA
        // section. From this point the whole frame can be consumed atomically.
        // Decode metadata from exactly the peer-declared metadata extent.
        // Passing the shared read buffer would let a malformed short target
        // consume the following DATA length/payload as metadata.
        let mut metadata_buffer = BytesMut::from(&self.read_buffer[..2 + metadata_len]);
        let metadata = FrameMetadata::decode(&mut metadata_buffer)?
            .expect("metadata decode should succeed after length check");
        debug_assert!(metadata_buffer.is_empty());
        self.read_buffer.advance(2 + metadata_len);
        let incoming_status = self.validate_incoming_status(&metadata)?;

        log::debug!(
            "[XUDP READ] Decoded frame: session_id={}, status={:?}, has_data={}, target={:?}, network={:?}",
            metadata.session_id,
            metadata.status,
            metadata.option.has_data(),
            metadata.target,
            metadata.network
        );

        let data = if let Some(data_len) = data_len {
            self.read_buffer.advance(2);
            let data = self.read_buffer[..data_len].to_vec();
            self.read_buffer.advance(data_len);
            Some(data)
        } else {
            None
        };

        match incoming_status {
            IncomingFrameStatus::End => {
                // sing-vmess consumes but does not surface DATA attached to End.
                self.forget_session(metadata.session_id);
                return Ok(Some(DecodedSessionMessage::End {
                    session_id: metadata.session_id,
                }));
            }
            IncomingFrameStatus::KeepAlive => {
                // KeepAlive DATA is likewise consumed and ignored.
                return Ok(Some(DecodedSessionMessage::Ignored));
            }
            IncomingFrameStatus::UnknownKeep => {
                // Do not fail the multiplexed byte stream. The router will send
                // an error End for this ID and continue reading other sessions.
                return Ok(Some(DecodedSessionMessage::UnknownKeep {
                    session_id: metadata.session_id,
                }));
            }
            IncomingFrameStatus::Rejected => {
                self.forget_session(metadata.session_id);
                return Ok(Some(DecodedSessionMessage::Rejected {
                    session_id: metadata.session_id,
                }));
            }
            IncomingFrameStatus::Data(_) => {}
        }

        // Check for TCP destination - we don't support TCP over XUDP
        if let Some(TargetNetwork::Tcp) = metadata.network {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "XUDP with TCP destinations is not supported. Only UDP destinations are supported.",
            ));
        }

        // Check for ERROR option bit - remote side is signaling an error
        if metadata.option.has_error() {
            log::debug!(
                "[XUDP READ] Peer closed session {} with the ERROR option",
                metadata.session_id
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "XUDP session closed by remote with error",
            ));
        }

        // Store/update session mapping for session_id → destination.
        self.update_session_target(&metadata);

        let Some(data) = data else {
            // A New/Keep frame without DATA can still update the session target.
            return Ok(Some(DecodedSessionMessage::Ignored));
        };
        if data.is_empty() {
            return Ok(Some(DecodedSessionMessage::Ignored));
        }

        // Determine destination
        let destination = if let Some(ref target) = metadata.target {
            target.clone()
        } else {
            // Keep the original hostname at the session boundary. The literal
            // reverse map is only an implementation detail for UDP responses.
            self.session_to_original_destination
                .get(&metadata.session_id)
                .cloned()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown session ID: {}", metadata.session_id),
                    )
                })?
        };

        log::debug!(
            "[XUDP READ] Decoded complete frame with {} bytes for destination {}",
            data.len(),
            destination
        );
        Ok(Some(DecodedSessionMessage::Data {
            data,
            session_id: metadata.session_id,
            status: match incoming_status {
                IncomingFrameStatus::Data(status) => status,
                _ => unreachable!("control statuses returned before data delivery"),
            },
            destination,
        }))
    }
}

impl AsyncFlushMessage for XudpMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while !this.write_buffer.is_empty() {
            let n = ready!(Pin::new(&mut this.inner_stream).poll_write(cx, &this.write_buffer))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write buffered XUDP frame",
                )));
            }
            this.write_buffer.advance(n);
        }

        match Pin::new(&mut this.inner_stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.write_state = WriteState::Idle;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for XudpMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.get_mut().inner_stream).poll_shutdown(cx)
    }
}

impl AsyncPing for XudpMessageStream {
    fn supports_ping(&self) -> bool {
        self.inner_stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        if self.write_state == WriteState::Buffered {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }
        Pin::new(&mut self.get_mut().inner_stream).poll_write_ping(cx)
    }
}

impl AsyncReadSessionMessage for XudpMessageStream {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>> {
        let this = self.get_mut();

        // Return buffered message if available
        if let Some((data, session_id, status, original_destination)) = this.incoming_message.take()
        {
            if data.len() > buf.remaining() {
                // Re-buffer it
                this.incoming_message = Some((data, session_id, status, original_destination));
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "buffer too small for incoming message",
                )));
            }

            this.register_session(session_id, &original_destination);

            buf.put_slice(&data);
            return Poll::Ready(Ok(SessionMessage::Data {
                session_id,
                status,
                target: SessionMessageTarget::unresolved(original_destination),
            }));
        }

        if this.is_eof {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF reached",
            )));
        }

        const MAX_IGNORED_FRAMES_PER_POLL: usize = 64;
        let mut ignored_frames = 0;
        loop {
            // Try to decode a complete frame from the read buffer
            match this.try_decode_one_frame()? {
                Some(DecodedSessionMessage::Ignored) => {
                    ignored_frames += 1;
                    if ignored_frames >= MAX_IGNORED_FRAMES_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    continue;
                }
                Some(DecodedSessionMessage::End { session_id }) => {
                    return Poll::Ready(Ok(SessionMessage::End { session_id }));
                }
                Some(DecodedSessionMessage::UnknownKeep { session_id }) => {
                    return Poll::Ready(Ok(SessionMessage::UnknownKeep { session_id }));
                }
                Some(DecodedSessionMessage::Rejected { session_id }) => {
                    return Poll::Ready(Ok(SessionMessage::Rejected { session_id }));
                }
                Some(DecodedSessionMessage::Data {
                    data,
                    session_id,
                    status,
                    destination,
                }) => {
                    // Successfully decoded a frame
                    if data.len() > buf.remaining() {
                        this.incoming_message = Some((data, session_id, status, destination));
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "buffer too small for incoming message",
                        )));
                    }

                    this.register_session(session_id, &destination);
                    buf.put_slice(&data);
                    log::debug!(
                        "[XUDP SESSION READ] Returning {} bytes for session {} to {}",
                        data.len(),
                        session_id,
                        destination
                    );
                    return Poll::Ready(Ok(SessionMessage::Data {
                        session_id,
                        status,
                        target: SessionMessageTarget::unresolved(destination),
                    }));
                }
                None => {
                    // Buffer doesn't have a complete frame, need to read more data
                }
            }

            // Read more data from inner stream
            let original_filled = this.read_buffer.len();
            this.read_buffer.resize(original_filled + 8192, 0);
            let mut temp_buf = ReadBuf::new(&mut this.read_buffer[original_filled..]);

            log::debug!(
                "[XUDP SESSION READ] Reading from inner stream, current buffer has {} bytes",
                original_filled
            );
            let poll_result = Pin::new(&mut this.inner_stream).poll_read(cx, &mut temp_buf);

            let n = temp_buf.filled().len();
            this.read_buffer.truncate(original_filled + n);

            match ready!(poll_result) {
                Ok(()) => {
                    log::debug!(
                        "[XUDP SESSION READ] Got {} bytes from inner stream (total buffer: {})",
                        n,
                        this.read_buffer.len()
                    );

                    if n == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF reached",
                        )));
                    }

                    // Got new data, continue loop to try decoding again
                    continue;
                }
                Err(e) => {
                    log::debug!("[XUDP SESSION READ] Inner stream ended: {}", e);
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl AsyncWriteSessionMessage for XudpMessageStream {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SessionMessageTarget,
    ) -> Poll<std::io::Result<()>> {
        // Use the original destination (possibly a hostname) on the wire, not
        // merely the resolved socket address supplied by the UDP side.

        log::debug!(
            "[XUDP SESSION WRITE] Writing {} bytes for session {} from source {}",
            buf.len(),
            session_id,
            target.response_address()
        );

        if buf.len() > u16::MAX as usize {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XUDP datagram exceeds the 65535-byte wire limit",
            )));
        }

        // A Pending return must happen before this datagram is encoded. This
        // lets callers retry safely and lets the router discard a queued write
        // when its UDP association is retired.
        if self.write_state == WriteState::Buffered {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }
        debug_assert!(self.write_buffer.is_empty());

        // Check if this is a new session BEFORE looking up or creating entries.
        // XUDP protocol requires first frame for a session to be StatusNew.
        let is_new_session = !self.peer_opened_sessions.contains(&session_id);

        // Keep the destination on the individual routed subflow. One XUDP
        // session ID may concurrently carry A and B, so a session_id -> target
        // cache cannot safely label delayed responses.
        let target_location = target.destination().location().clone();

        log::debug!(
            "[XUDP SESSION WRITE] Using original destination {} for session {} (response came from {})",
            target_location,
            session_id,
            target.response_address()
        );

        // Build frame with appropriate status (New for first frame, Keep for subsequent)
        let status = if is_new_session {
            log::debug!(
                "[XUDP SESSION WRITE] Sending NEW frame for session {} (first write)",
                session_id
            );
            SessionStatus::New
        } else {
            SessionStatus::Keep
        };

        let metadata = FrameMetadata {
            session_id,
            status,
            option: FrameOption::new().with_data(),
            target: Some(target_location.clone()), // Use ORIGINAL (hostname), not resolved IP!
            network: Some(TargetNetwork::Udp),
        };

        log::debug!(
            "[XUDP SESSION WRITE] Encoding {:?} frame: session_id={}, target={}, data_len={}",
            status,
            session_id,
            target_location,
            buf.len()
        );

        // Encode into a temporary buffer so an encoding error cannot leave a
        // partial frame in the shared write buffer.
        let mut frame = BytesMut::new();
        metadata.encode(&mut frame)?;

        // Write data length
        frame.put_u16(buf.len() as u16);

        // Write data
        frame.extend_from_slice(buf);

        self.peer_opened_sessions.insert(session_id);
        self.write_buffer.extend_from_slice(&frame);
        self.write_state = WriteState::Buffered;

        // The frame has been accepted. `poll_flush_message` owns any subsequent
        // transport backpressure, matching the other message-stream traits.
        Poll::Ready(Ok(()))
    }

    fn poll_write_session_end(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>> {
        if self.write_state == WriteState::Buffered {
            ready!(self.as_mut().poll_flush_message(cx))?;
        }
        debug_assert!(self.write_buffer.is_empty());

        let option = if has_error {
            FrameOption::from(FrameOption::ERROR)
        } else {
            FrameOption::new()
        };
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status: SessionStatus::End,
            option,
            target: None,
            network: None,
        }
        .encode(&mut frame)?;

        self.forget_session(session_id);
        self.write_buffer.extend_from_slice(&frame);
        self.write_state = WriteState::Buffered;
        Poll::Ready(Ok(()))
    }
}

impl AsyncSessionMessageStream for XudpMessageStream {}

/// Single-destination client view of an XUDP session.
///
/// VLESS XUDP assigns session ID 0 to the packet connection.  Keeping this
/// adapter here lets VLESS reuse the generic XUDP codec without teaching the
/// rest of the outbound stack about session identifiers.
pub struct XudpClientMessageStream {
    inner: XudpMessageStream,
    original_target: NetLocation,
    target: SocketAddr,
}

impl XudpClientMessageStream {
    pub fn new(
        inner_stream: Box<dyn AsyncStream>,
        original_target: NetLocation,
        resolved_target: SocketAddr,
    ) -> Self {
        let mut inner = XudpMessageStream::new(inner_stream);
        inner
            .session_to_original_destination
            .insert(0, original_target.clone());

        Self {
            inner,
            original_target,
            target: resolved_target,
        }
    }
}

impl AsyncReadMessage for XudpClientMessageStream {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let (session_id, response_target) =
            match ready!(Pin::new(&mut self.inner).poll_read_session_message(cx, buf))? {
                SessionMessage::Data {
                    session_id, target, ..
                } => (session_id, target),
                SessionMessage::End { session_id: 0 } => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "XUDP session 0 ended by remote",
                    )));
                }
                SessionMessage::End { session_id } => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unexpected XUDP session ID {session_id}, expected 0"),
                    )));
                }
                SessionMessage::UnknownKeep { session_id } => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("XUDP Keep for unknown session {session_id}"),
                    )));
                }
                SessionMessage::Rejected { session_id } => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("XUDP rejected session {session_id}"),
                    )));
                }
            };
        if session_id != 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected XUDP session ID {session_id}, expected 0"),
            )));
        }
        let response_location = response_target.destination().location();
        let matches_original = response_location.port() == self.original_target.port()
            && match (response_location.address(), self.original_target.address()) {
                (Address::Hostname(actual), Address::Hostname(expected)) => {
                    actual.eq_ignore_ascii_case(expected)
                }
                (actual, expected) => actual == expected,
            };
        let literal_target = response_location.to_socket_addr_nonblocking();
        if !matches_original && literal_target.is_none() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected XUDP response target {response_location}"),
            )));
        }
        if literal_target.is_some_and(|address| address != self.target) {
            log::debug!(
                "[XUDP CLIENT READ] Session 0 response used literal {} instead of first candidate {}",
                literal_target.unwrap(),
                self.target
            );
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteMessage for XudpClientMessageStream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let target = SessionMessageTarget::new(
            ResolvedLocation::with_resolved(self.original_target.clone(), self.target),
            self.target,
        );
        Pin::new(&mut self.inner).poll_write_session_message(cx, 0, buf, &target)
    }
}

impl AsyncFlushMessage for XudpClientMessageStream {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for XudpClientMessageStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}

impl AsyncPing for XudpClientMessageStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for XudpClientMessageStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct CountingWaker(AtomicUsize);

    impl futures::task::ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Default)]
    struct UnusedStream;

    impl AsyncRead for UnusedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for UnusedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for UnusedStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for UnusedStream {}

    #[derive(Debug)]
    struct PendingFlushStream {
        written: Arc<Mutex<Vec<u8>>>,
        flush_count: Arc<AtomicUsize>,
    }

    impl AsyncRead for PendingFlushStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingFlushStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.flush_count.fetch_add(1, Ordering::SeqCst) == 0 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for PendingFlushStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for PendingFlushStream {}

    #[derive(Debug)]
    struct InjectedResolver {
        calls: Arc<AtomicUsize>,
        addresses: Vec<SocketAddr>,
    }

    impl Resolver for InjectedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addresses = self.addresses.clone();
            Box::pin(async move {
                // Exercise XudpMessageStream's buffered/pending lookup path.
                tokio::task::yield_now().await;
                Ok(addresses)
            })
        }

        fn result_cache_ttl(&self) -> Option<Duration> {
            None
        }
    }

    #[tokio::test]
    async fn frame_hostname_is_left_unresolved_by_codec() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolved_address: SocketAddr = "203.0.113.9:5353".parse().unwrap();
        let fallback_address: SocketAddr = "203.0.113.10:5353".parse().unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(InjectedResolver {
            calls: calls.clone(),
            addresses: vec![resolved_address, fallback_address],
        });
        let mut stream = XudpMessageStream::new_with_resolver(Box::new(UnusedStream), resolver);

        let target = NetLocation::new(
            Address::Hostname("must-use-inbound-resolver.invalid".to_string()),
            5353,
        );
        let payload = b"dns-policy";
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id: 7,
            status: SessionStatus::New,
            option: FrameOption::new().with_data(),
            target: Some(target.clone()),
            network: Some(TargetNetwork::Udp),
        }
        .encode(&mut frame)
        .unwrap();
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        stream.feed_initial_read_data(&frame).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        let message = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buf)
        })
        .await
        .unwrap();
        let SessionMessage::Data {
            session_id,
            status,
            target: session_target,
        } = message
        else {
            panic!("expected an XUDP data frame");
        };

        assert_eq!(session_id, 7);
        assert_eq!(status, SessionMessageStatus::New);
        assert_eq!(session_target.destination().location(), &target);
        assert_eq!(session_target.destination().resolved_addrs(), None);
        assert_eq!(session_target.response_address_opt(), None);
        assert_eq!(read_buf.filled(), payload);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn xudp_data_frame_with_status(
        session_id: u16,
        status: SessionStatus,
        target: NetLocation,
        payload: &[u8],
    ) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::new().with_data(),
            target: Some(target),
            network: Some(TargetNetwork::Udp),
        }
        .encode(&mut frame)
        .unwrap();
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        frame
    }

    fn xudp_data_frame(session_id: u16, target: NetLocation, payload: &[u8]) -> BytesMut {
        xudp_data_frame_with_status(session_id, SessionStatus::New, target, payload)
    }

    fn xudp_end_frame(session_id: u16) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status: SessionStatus::End,
            option: FrameOption::new(),
            target: None,
            network: None,
        }
        .encode(&mut frame)
        .unwrap();
        frame
    }

    fn xudp_control_frame_with_data(
        session_id: u16,
        status: SessionStatus,
        payload: &[u8],
    ) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::new().with_data(),
            target: None,
            network: None,
        }
        .encode(&mut frame)
        .unwrap();
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        frame
    }

    #[test]
    fn short_new_metadata_cannot_consume_data_as_its_target() {
        // metadata_len=5: session/new/data/network, but no target. The following
        // DATA length and payload happen to form a complete IPv4 target if the
        // decoder is allowed to read past the declared metadata boundary.
        let malformed = [
            0x00, 0x05, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x05, 0x01, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&malformed).unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stream.try_decode_one_frame()
        }))
        .expect("malformed metadata must return an error instead of panicking");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed metadata unexpectedly decoded"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(stream.read_buffer.as_ref(), malformed.as_slice());
    }

    #[test]
    fn short_new_without_data_returns_invalid_data_instead_of_panicking() {
        // metadata_len=5: session/new/no-options/network, with neither port nor
        // address. Every byte promised by metadata_len is present.
        let malformed = [0x00, 0x05, 0x00, 0x02, 0x01, 0x00, 0x02];
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&malformed).unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stream.try_decode_one_frame()
        }))
        .expect("short New metadata must return an error instead of panicking");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("short New metadata unexpectedly decoded"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(stream.read_buffer.as_ref(), malformed.as_slice());
    }

    #[test]
    fn unique_targets_do_not_accumulate_per_destination_codec_state() {
        let session_id = 53;
        let mut frames = xudp_data_frame(
            session_id,
            NetLocation::new(Address::Ipv4("10.0.0.1".parse().unwrap()), 53),
            b"first",
        );
        for index in 2_u32..=2_049 {
            let octets = index.to_be_bytes();
            let address = std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]);
            frames.extend_from_slice(&xudp_data_frame_with_status(
                session_id,
                SessionStatus::Keep,
                NetLocation::new(Address::Ipv4(address), 53),
                b"keep",
            ));
        }

        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&frames).unwrap();
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        for _ in 0..=2_048 {
            let mut storage = [0_u8; 8];
            let mut read_buf = ReadBuf::new(&mut storage);
            assert!(matches!(
                Pin::new(&mut stream).poll_read_session_message(&mut context, &mut read_buf),
                Poll::Ready(Ok(SessionMessage::Data { session_id: 53, .. }))
            ));
        }

        assert_eq!(stream.peer_opened_sessions.len(), 1);
        assert_eq!(stream.session_to_original_destination.len(), 1);
    }

    #[test]
    fn pending_previous_flush_does_not_encode_the_retried_datagram_twice() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let flush_count = Arc::new(AtomicUsize::new(0));
        let inner = PendingFlushStream {
            written: Arc::clone(&written),
            flush_count,
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let response_address: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let target_location = NetLocation::new(
            Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            response_address.port(),
        );
        let target = SessionMessageTarget::new(
            ResolvedLocation::with_resolved(target_location, response_address),
            response_address,
        );
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_message(&mut context, 12, b"first", &target),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_message(&mut context, 12, b"second", &target),
            Poll::Pending
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_message(&mut context, 12, b"second", &target),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_flush_message(&mut context),
            Poll::Ready(Ok(()))
        ));

        let encoded = written.lock().unwrap().clone();
        let mut decoder = XudpMessageStream::new(Box::new(UnusedStream));
        decoder.feed_initial_read_data(&encoded).unwrap();
        assert!(matches!(
            decoder.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::Data {
                ref data,
                session_id: 12,
                status: SessionMessageStatus::New,
                ..
            }) if data == b"first"
        ));
        assert!(matches!(
            decoder.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::Data {
                ref data,
                session_id: 12,
                status: SessionMessageStatus::Keep,
                ..
            }) if data == b"second"
        ));
        assert!(decoder.read_buffer.is_empty());
    }

    #[test]
    fn error_end_is_encoded_for_only_the_requested_session() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let inner = PendingFlushStream {
            written: Arc::clone(&written),
            flush_count: Arc::new(AtomicUsize::new(1)),
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        assert!(matches!(
            Pin::new(&mut stream).poll_write_session_end(&mut context, 77, true),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_flush_message(&mut context),
            Poll::Ready(Ok(()))
        ));

        let mut encoded = BytesMut::from(written.lock().unwrap().as_slice());
        let metadata = FrameMetadata::decode(&mut encoded).unwrap().unwrap();
        assert_eq!(metadata.session_id, 77);
        assert_eq!(metadata.status, SessionStatus::End);
        assert!(metadata.option.has_error());
        assert!(!metadata.option.has_data());
        assert!(encoded.is_empty());
    }

    #[test]
    fn one_session_encodes_each_destination_on_its_own_response_frame() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let inner = PendingFlushStream {
            written: Arc::clone(&written),
            flush_count: Arc::new(AtomicUsize::new(1)),
        };
        let mut stream = XudpMessageStream::new(Box::new(inner));
        let session_id = 78;
        stream.peer_opened_sessions.insert(session_id);
        let address_a: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let address_b: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let destination_a = NetLocation::new(Address::Hostname("a.example".to_string()), 53);
        let destination_b = NetLocation::new(Address::Hostname("b.example".to_string()), 53);
        let target_a = SessionMessageTarget::new(
            ResolvedLocation::with_resolved(destination_a.clone(), address_a),
            address_a,
        );
        let target_b = SessionMessageTarget::new(
            ResolvedLocation::with_resolved(destination_b.clone(), address_b),
            address_b,
        );
        let waker = futures::task::noop_waker_ref();
        let mut context = Context::from_waker(waker);

        for (target, payload) in [
            (&target_a, b"from-a".as_slice()),
            (&target_b, b"from-b".as_slice()),
            (&target_a, b"from-a-delayed".as_slice()),
        ] {
            assert!(matches!(
                Pin::new(&mut stream).poll_write_session_message(
                    &mut context,
                    session_id,
                    payload,
                    target,
                ),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_flush_message(&mut context),
                Poll::Ready(Ok(()))
            ));
        }

        let mut encoded = BytesMut::from(written.lock().unwrap().as_slice());
        for (expected_target, expected_payload) in [
            (destination_a.clone(), b"from-a".as_slice()),
            (destination_b, b"from-b".as_slice()),
            (destination_a, b"from-a-delayed".as_slice()),
        ] {
            let metadata = FrameMetadata::decode(&mut encoded).unwrap().unwrap();
            assert_eq!(metadata.session_id, session_id);
            assert_eq!(metadata.status, SessionStatus::Keep);
            assert_eq!(metadata.target, Some(expected_target));
            assert!(metadata.option.has_data());
            let payload_len = encoded.get_u16() as usize;
            assert_eq!(&encoded[..payload_len], expected_payload);
            encoded.advance(payload_len);
        }
        assert!(encoded.is_empty());
    }

    #[test]
    fn end_data_is_consumed_before_the_following_frame() {
        let target = NetLocation::new(Address::Ipv4("203.0.113.40".parse().unwrap()), 53);
        let mut frames = xudp_control_frame_with_data(5, SessionStatus::End, b"discard-end");
        frames.extend_from_slice(&xudp_data_frame(6, target, b"after-end"));
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&frames).unwrap();

        assert!(matches!(
            stream.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::End { session_id: 5 })
        ));
        assert!(matches!(
            stream.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::Data {
                ref data,
                session_id: 6,
                ..
            }) if data == b"after-end"
        ));
        assert!(stream.read_buffer.is_empty());
    }

    #[test]
    fn keepalive_data_is_consumed_before_the_following_frame() {
        let target = NetLocation::new(Address::Ipv4("203.0.113.41".parse().unwrap()), 53);
        let mut frames =
            xudp_control_frame_with_data(0, SessionStatus::KeepAlive, b"discard-keepalive");
        frames.extend_from_slice(&xudp_data_frame(7, target, b"after-keepalive"));
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&frames).unwrap();

        assert!(matches!(
            stream.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::Ignored)
        ));
        assert!(matches!(
            stream.try_decode_one_frame().unwrap(),
            Some(DecodedSessionMessage::Data {
                ref data,
                session_id: 7,
                ..
            }) if data == b"after-keepalive"
        ));
        assert!(stream.read_buffer.is_empty());
    }

    #[test]
    fn many_keepalives_yield_between_bounded_decode_batches() {
        let mut frames = BytesMut::new();
        for _ in 0..10_000 {
            FrameMetadata {
                session_id: 0,
                status: SessionStatus::KeepAlive,
                option: FrameOption::new(),
                target: None,
                network: None,
            }
            .encode(&mut frames)
            .unwrap();
        }
        let target = NetLocation::new(Address::Ipv4("203.0.113.42".parse().unwrap()), 53);
        frames.extend_from_slice(&xudp_data_frame(8, target, b"after-many-keepalives"));
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&frames).unwrap();

        let wake_counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = futures::task::waker(Arc::clone(&wake_counter));
        let mut context = Context::from_waker(&waker);
        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        let mut pending_polls = 0;
        loop {
            match Pin::new(&mut stream).poll_read_session_message(&mut context, &mut read_buf) {
                Poll::Pending => pending_polls += 1,
                Poll::Ready(Ok(SessionMessage::Data { session_id: 8, .. })) => break,
                other => panic!("unexpected poll result: {other:?}"),
            }
        }
        assert!(pending_polls > 1);
        assert_eq!(wake_counter.0.load(Ordering::SeqCst), pending_polls);
        assert_eq!(read_buf.filled(), b"after-many-keepalives");
        assert!(stream.read_buffer.is_empty());
    }

    #[tokio::test]
    async fn keep_for_unknown_session_is_reported_without_ending_the_stream() {
        let resolver: Arc<dyn Resolver> = Arc::new(InjectedResolver {
            calls: Arc::new(AtomicUsize::new(0)),
            addresses: vec!["203.0.113.30:53".parse().unwrap()],
        });
        let mut stream = XudpMessageStream::new_with_resolver(Box::new(UnusedStream), resolver);
        let target = NetLocation::new(Address::Hostname("unknown.example".to_string()), 53);
        let mut frames = xudp_data_frame_with_status(44, SessionStatus::Keep, target, b"payload");
        let following_target =
            NetLocation::new(Address::Hostname("following.example".to_string()), 53);
        frames.extend_from_slice(&xudp_data_frame(45, following_target.clone(), b"following"));
        stream.feed_initial_read_data(&frames).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        let message = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buf)
        })
        .await
        .unwrap();

        assert!(matches!(
            message,
            SessionMessage::UnknownKeep { session_id: 44 }
        ));
        assert!(read_buf.filled().is_empty());
        assert!(!stream.peer_opened_sessions.contains(&44));
        assert!(!stream.session_to_original_destination.contains_key(&44));

        let mut following_storage = [0_u8; 64];
        let mut following_buf = ReadBuf::new(&mut following_storage);
        let following = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut following_buf)
        })
        .await
        .unwrap();
        assert!(matches!(
            following,
            SessionMessage::Data {
                session_id: 45,
                status: SessionMessageStatus::New,
                ref target,
            } if target.destination().location() == &following_target
        ));
        assert_eq!(following_buf.filled(), b"following");
    }

    #[tokio::test]
    async fn duplicate_new_is_session_local_and_following_session_survives() {
        let first = NetLocation::new(Address::Ipv4("203.0.113.50".parse().unwrap()), 53);
        let replacement = NetLocation::new(Address::Ipv4("203.0.113.51".parse().unwrap()), 53);
        let following = NetLocation::new(Address::Ipv4("203.0.113.52".parse().unwrap()), 53);
        let mut frames = xudp_data_frame(70, first, b"first");
        frames.extend_from_slice(&xudp_data_frame(70, replacement, b"duplicate"));
        frames.extend_from_slice(&xudp_data_frame(71, following.clone(), b"following"));
        let mut stream = XudpMessageStream::new(Box::new(UnusedStream));
        stream.feed_initial_read_data(&frames).unwrap();

        let mut storage = [0_u8; 64];
        {
            let mut read_buf = ReadBuf::new(&mut storage);
            let first = futures::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buf)
            })
            .await
            .unwrap();
            assert!(matches!(first, SessionMessage::Data { session_id: 70, .. }));
        }

        {
            let mut control = ReadBuf::new(&mut storage);
            let rejected = futures::future::poll_fn(|cx| {
                Pin::new(&mut stream).poll_read_session_message(cx, &mut control)
            })
            .await
            .unwrap();
            assert!(matches!(
                rejected,
                SessionMessage::Rejected { session_id: 70 }
            ));
        }

        let mut following_buf = ReadBuf::new(&mut storage);
        let message = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut following_buf)
        })
        .await
        .unwrap();
        assert!(matches!(
            message,
            SessionMessage::Data {
                session_id: 71,
                ref target,
                ..
            } if target.destination().location() == &following
        ));
        assert_eq!(following_buf.filled(), b"following");
    }

    #[tokio::test]
    async fn end_is_reported_before_same_id_new_uses_the_new_target() {
        let resolver: Arc<dyn Resolver> = Arc::new(InjectedResolver {
            calls: Arc::new(AtomicUsize::new(0)),
            addresses: vec!["203.0.113.31:53".parse().unwrap()],
        });
        let mut stream = XudpMessageStream::new_with_resolver(Box::new(UnusedStream), resolver);
        let first_target = NetLocation::new(Address::Hostname("first.example".to_string()), 53);
        let second_target = NetLocation::new(Address::Hostname("second.example".to_string()), 53);
        stream
            .feed_initial_read_data(&xudp_data_frame(9, first_target.clone(), b"first"))
            .unwrap();

        let mut first_storage = [0_u8; 64];
        let mut first_buf = ReadBuf::new(&mut first_storage);
        let first = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut first_buf)
        })
        .await
        .unwrap();
        assert!(matches!(
            first,
            SessionMessage::Data {
                session_id: 9,
                status: SessionMessageStatus::New,
                ref target
            } if target.destination().location() == &first_target
        ));

        let mut replacement = xudp_end_frame(9);
        replacement.extend_from_slice(&xudp_data_frame(9, second_target.clone(), b"second"));
        stream.feed_initial_read_data(&replacement).unwrap();

        let mut end_storage = [0_u8; 1];
        let mut end_buf = ReadBuf::new(&mut end_storage);
        let end = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut end_buf)
        })
        .await
        .unwrap();
        assert!(matches!(end, SessionMessage::End { session_id: 9 }));
        assert!(!stream.peer_opened_sessions.contains(&9));
        assert!(!stream.session_to_original_destination.contains_key(&9));

        let mut second_storage = [0_u8; 64];
        let mut second_buf = ReadBuf::new(&mut second_storage);
        let second = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_session_message(cx, &mut second_buf)
        })
        .await
        .unwrap();
        assert!(matches!(
            second,
            SessionMessage::Data {
                session_id: 9,
                status: SessionMessageStatus::New,
                ref target
            } if target.destination().location() == &second_target
        ));
        assert_eq!(second_buf.filled(), b"second");
    }

    #[tokio::test]
    async fn client_response_hostname_reuses_the_pre_resolved_target() {
        let original_target = NetLocation::new(
            Address::Hostname("must-not-use-native-dns.invalid".to_string()),
            5353,
        );
        let resolved_target: SocketAddr = "203.0.113.19:5353".parse().unwrap();
        let payload = b"response";
        let mut stream = XudpClientMessageStream::new(
            Box::new(UnusedStream),
            original_target.clone(),
            resolved_target,
        );
        let frame = xudp_data_frame(0, original_target, payload);
        stream.inner.feed_initial_read_data(&frame).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .expect("the echoed hostname must use the already resolved target");

        assert_eq!(read_buf.filled(), payload);
    }

    #[tokio::test]
    async fn client_rejects_a_response_for_an_unexpected_hostname() {
        let original_target =
            NetLocation::new(Address::Hostname("expected.example".to_string()), 5353);
        let resolved_target: SocketAddr = "203.0.113.19:5353".parse().unwrap();
        let mut stream =
            XudpClientMessageStream::new(Box::new(UnusedStream), original_target, resolved_target);
        let frame = xudp_data_frame(
            0,
            NetLocation::new(Address::Hostname("unexpected.example".to_string()), 5353),
            b"response",
        );
        stream.inner.feed_initial_read_data(&frame).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        let error = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
        })
        .await
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("unexpected XUDP response target")
        );
    }

    #[tokio::test]
    async fn client_rejects_a_response_for_an_unexpected_session_id() {
        let original_target =
            NetLocation::new(Address::Hostname("expected.example".to_string()), 5353);
        let resolved_target: SocketAddr = "203.0.113.19:5353".parse().unwrap();
        let mut stream = XudpClientMessageStream::new(
            Box::new(UnusedStream),
            original_target.clone(),
            resolved_target,
        );
        let frame = xudp_data_frame(1, original_target, b"response");
        stream.inner.feed_initial_read_data(&frame).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        let error = futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
        })
        .await
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unexpected XUDP session ID 1"));
    }

    #[tokio::test]
    async fn client_accepts_another_literal_response_target_for_session_zero() {
        let original_target =
            NetLocation::new(Address::Hostname("expected.example".to_string()), 5353);
        let first_candidate: SocketAddr = "203.0.113.19:5353".parse().unwrap();
        let response_candidate: SocketAddr = "203.0.113.20:5353".parse().unwrap();
        let mut stream =
            XudpClientMessageStream::new(Box::new(UnusedStream), original_target, first_candidate);
        let frame = xudp_data_frame(
            0,
            NetLocation::new(Address::Ipv4("203.0.113.20".parse().unwrap()), 5353),
            b"response",
        );
        stream.inner.feed_initial_read_data(&frame).unwrap();

        let mut storage = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut storage);
        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .expect("another literal response target on session 0 must be accepted");

        assert_eq!(read_buf.filled(), b"response");
        assert_eq!(
            stream.inner.session_to_original_destination.get(&0),
            Some(&NetLocation::new(
                Address::Ipv4("203.0.113.20".parse().unwrap()),
                response_candidate.port(),
            ))
        );
    }
}
