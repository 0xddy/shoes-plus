use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use log::debug;
use tokio::io::{AsyncWriteExt, ReadBuf};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
use crate::dynamic::{UserRegistry, bind_connection_user, current_connection};
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session_with_meter};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{
    ADDR_TYPE_DOMAIN_NAME, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, CMD_CONNECT, CMD_UDP_ASSOCIATE,
    read_location, write_location_to_vec,
};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    /// Authenticates incoming connections. `Some` exactly when this handler was built
    /// for server use; the client direction has nobody to authenticate.
    users: Option<Arc<dyn UserRegistry>>,
    /// The digest this handler presents when it is the client. `Some` exactly when this
    /// handler was built for client use, since a server never sends a credential.
    password_hash: Option<Box<[u8]>>,
    shadowsocks_data: Option<ShadowsocksData>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
    /// Whether this client may open Trojan UDP associate sessions. Server
    /// handlers keep this enabled because inbound command policy is separate.
    udp_enabled: bool,
}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        users: Arc<dyn UserRegistry>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_inner(
            Some(users),
            None,
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
            true,
        )
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_client_with_udp(password, shadowsocks_config, true)
    }

    /// Create a client handler with explicit network capability projection.
    pub fn new_client_with_udp(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        udp_enabled: bool,
    ) -> Self {
        Self::new_inner(
            None,
            Some(create_password_hash(password)),
            shadowsocks_config,
            None,
            None,
            udp_enabled,
        )
    }

    fn new_inner(
        users: Option<Arc<dyn UserRegistry>>,
        password_hash: Option<Box<[u8]>>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
        resolver: Option<Arc<dyn Resolver>>,
        udp_enabled: bool,
    ) -> Self {
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| match config {
            ShadowsocksConfig::Legacy {
                cipher,
                password: shadowsocks_password,
            } => {
                let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                    shadowsocks_password,
                    cipher.algorithm().key_len(),
                )));
                ShadowsocksData {
                    cipher: *cipher,
                    key,
                }
            }
            ShadowsocksConfig::Aead2022 { .. } => {
                panic!("Trojan does not support shadowsocks 2022 ciphers (checked during config validation)")
            }
        });

        Self {
            users,
            password_hash,
            shadowsocks_data,
            proxy_selector,
            resolver,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            server_stream = Box::new(ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        let users = self
            .users
            .as_ref()
            .expect("user registry required for server handler");

        // read the entire line rather than exactly 56 bytes, so that we can masquerade as an HTTP server
        // and handle the request as if it were a HTTP request.
        // TODO: implement http response
        let received_hash = stream_reader.read_line_bytes(&mut server_stream).await?;
        if received_hash.len() != PASSWORD_HASH_LEN {
            return Err(std::io::Error::other(format!(
                "Invalid password hash length, expected {}, got {}",
                PASSWORD_HASH_LEN,
                received_hash.len()
            )));
        }

        // The registry hashes to a bucket and finishes with a constant-time
        // comparison, so this is still not a timing oracle. On success the
        // connection's traffic is attributed to this user from here on, including
        // the handshake bytes already read.
        let user = match users.find_trojan_hash(received_hash) {
            Some(user) => user,
            None => return Err(std::io::Error::other("Invalid password hash")),
        };
        if !bind_connection_user(&user) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "user could not be admitted: removed, suspended, or at their connection limit",
            ));
        }

        let command_type = stream_reader.read_u8(&mut server_stream).await?;

        if command_type == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
        }

        if command_type != CMD_CONNECT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {command_type}"),
            ));
        }

        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        let request_suffix = stream_reader.read_u16_be(&mut server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {request_suffix}"
            )));
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");

            let initial_data = stream_reader.unparsed_data_owned();
            let meter = current_connection();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session_with_meter(
                    server_stream,
                    initial_data,
                    false,
                    proxy_selector,
                    resolver,
                    meter,
                )
                .await
                {
                    debug!("Trojan h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];
const MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize;
const MAX_SOCKS_ADDRESS_LEN: usize = 1 + 1 + u8::MAX as usize + 2;
const MAX_TROJAN_UDP_FRAME_LEN: usize = MAX_SOCKS_ADDRESS_LEN + 2 + 2 + MAX_UDP_PAYLOAD_LEN;

/// A fixed-target Trojan UDP association transported over one TCP stream.
///
/// Trojan repeats a SOCKS5 address in every UDP frame, even though shoes' client
/// chain exposes a bidirectional stream for one target. We still parse and validate
/// the response address so malformed peer data cannot desynchronise the byte stream;
/// the higher-level fixed-target API intentionally returns only the payload.
struct TrojanUdpMessageStream<S> {
    stream: S,
    target_address: Vec<u8>,
    read_buf: Box<[u8]>,
    read_end_index: usize,
    pending_write: Vec<u8>,
    write_offset: usize,
    is_eof: bool,
}

impl<S: AsyncStream> TrojanUdpMessageStream<S> {
    fn new(stream: S, target: &NetLocation) -> std::io::Result<Self> {
        let target_address = encode_trojan_address(target)?;
        Ok(Self {
            stream,
            target_address,
            read_buf: vec![0; MAX_TROJAN_UDP_FRAME_LEN].into_boxed_slice(),
            read_end_index: 0,
            pending_write: Vec::with_capacity(MAX_TROJAN_UDP_FRAME_LEN),
            write_offset: 0,
            is_eof: false,
        })
    }
}

fn encode_trojan_address(location: &NetLocation) -> std::io::Result<Vec<u8>> {
    if let Address::Hostname(hostname) = location.address()
        && hostname.len() > u8::MAX as usize
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Trojan UDP destination hostname exceeds 255 bytes",
        ));
    }
    Ok(write_location_to_vec(location))
}

/// Return `(address_len, payload_len)` when a complete header is available.
fn parse_trojan_udp_header(data: &[u8]) -> std::io::Result<Option<(usize, usize)>> {
    let Some(&address_type) = data.first() else {
        return Ok(None);
    };
    let address_len = match address_type {
        ADDR_TYPE_IPV4 => 1 + 4 + 2,
        ADDR_TYPE_IPV6 => 1 + 16 + 2,
        ADDR_TYPE_DOMAIN_NAME => {
            let Some(&domain_len) = data.get(1) else {
                return Ok(None);
            };
            1 + 1 + domain_len as usize + 2
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid Trojan UDP address type: {other}"),
            ));
        }
    };
    let header_len = address_len + 4;
    if data.len() < header_len {
        return Ok(None);
    }
    if address_type == ADDR_TYPE_DOMAIN_NAME {
        let domain_len = data[1] as usize;
        let domain = std::str::from_utf8(&data[2..2 + domain_len]).map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid Trojan UDP response domain: {error}"),
            )
        })?;
        Address::from(domain).map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("invalid Trojan UDP response domain: {error}"),
            )
        })?;
    }
    let payload_len = u16::from_be_bytes([data[address_len], data[address_len + 1]]) as usize;
    if data[address_len + 2..header_len] != CRLF_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid Trojan UDP frame suffix",
        ));
    }
    Ok(Some((header_len, payload_len)))
}

impl<S: AsyncStream> AsyncReadMessage for TrojanUdpMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if let Some((header_len, payload_len)) =
                parse_trojan_udp_header(&this.read_buf[..this.read_end_index])?
            {
                let total_len = header_len + payload_len;
                if this.read_end_index >= total_len {
                    if out_buf.remaining() < payload_len {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::InvalidInput,
                            "output buffer is too small for Trojan UDP message",
                        )));
                    }
                    out_buf.put_slice(&this.read_buf[header_len..total_len]);
                    if this.read_end_index > total_len {
                        this.read_buf.copy_within(total_len..this.read_end_index, 0);
                        this.read_end_index -= total_len;
                    } else {
                        this.read_end_index = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
            }

            let read_slice = &mut this.read_buf[this.read_end_index..];
            if read_slice.is_empty() {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::InvalidData,
                    "Trojan UDP frame exceeds protocol maximum",
                )));
            }
            let mut read_buf = ReadBuf::new(read_slice);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let read_len = read_buf.filled().len();
                    if read_len == 0 {
                        this.is_eof = true;
                        if this.read_end_index == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "EOF reached in the middle of a Trojan UDP frame",
                        )));
                    }
                    this.read_end_index += read_len;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for TrojanUdpMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        if !this.pending_write.is_empty() {
            if let Poll::Ready(Err(error)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(error));
            }
            if !this.pending_write.is_empty() {
                return Poll::Pending;
            }
        }
        if buf.len() > MAX_UDP_PAYLOAD_LEN {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "Trojan UDP message exceeds 65535 bytes",
            )));
        }

        let TrojanUdpMessageStream {
            target_address,
            pending_write,
            ..
        } = &mut *this;
        pending_write.extend_from_slice(target_address);
        pending_write.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        pending_write.extend_from_slice(&CRLF_BYTES);
        pending_write.extend_from_slice(buf);
        this.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for TrojanUdpMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.write_offset < this.pending_write.len() {
            match Pin::new(&mut this.stream)
                .poll_write(cx, &this.pending_write[this.write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to write Trojan UDP frame",
                    )));
                }
                Poll::Ready(Ok(written)) => this.write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_offset = 0;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for TrojanUdpMessageStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match <Self as AsyncFlushMessage>::poll_flush_message(Pin::new(this), cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for TrojanUdpMessageStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncMessageStream for TrojanUdpMessageStream<S> {}

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        crate::tcp::write_handshake::mark_started();

        let password_hash = self
            .password_hash
            .as_ref()
            .expect("password hash required for client handler");
        write_all(&mut client_stream, password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_CONNECT]).await?;
        let location_bytes = write_location_to_vec(remote_location.location());
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn needs_handshake_for_write(&self) -> bool {
        self.password_hash.is_some()
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Trojan UDP is disabled by client configuration",
            ));
        }
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let target_address = encode_trojan_address(target.location())?;
        let password_hash = self
            .password_hash
            .as_ref()
            .expect("password hash required for client handler");
        write_all(&mut client_stream, password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_UDP_ASSOCIATE]).await?;
        write_all(&mut client_stream, &target_address).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;

        Ok(Box::new(TrojanUdpMessageStream::new(
            client_stream,
            target.location(),
        )?))
    }
}

/// Length of a Trojan credential on the wire: SHA-224 rendered as lowercase hex.
pub(crate) const PASSWORD_HASH_LEN: usize = 56;

pub(crate) fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{b:02x}"));
    }
    let hex_bytes = hex_str.into_bytes().into_boxed_slice();
    if hex_bytes.len() != PASSWORD_HASH_LEN {
        panic!(
            "Invalid password hash length, expected {}, got {}",
            PASSWORD_HASH_LEN,
            hex_bytes.len()
        );
    }
    hex_bytes
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
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

    impl AsyncStream for TestStream {}

    fn ipv4_target() -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::new(203, 0, 113, 8)), 53)
    }

    fn encode_frame(target: &NetLocation, payload: &[u8]) -> Vec<u8> {
        let mut frame = write_location_to_vec(target);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&CRLF_BYTES);
        frame.extend_from_slice(payload);
        frame
    }

    async fn write_message(
        stream: &mut dyn AsyncMessageStream,
        payload: &[u8],
    ) -> std::io::Result<()> {
        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, payload)).await
    }

    async fn flush_message(stream: &mut dyn AsyncMessageStream) -> std::io::Result<()> {
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
    }

    #[test]
    fn client_reports_go_write_handshake_semantics() {
        let client = TrojanTcpHandler::new_client("secret", &None);
        assert!(client.needs_handshake_for_write());
    }

    #[tokio::test]
    async fn udp_client_writes_handshake_and_framed_packet() {
        let (client, mut peer) = duplex(128 * 1024);
        let handler = TrojanTcpHandler::new_client("secret", &None);
        assert!(handler.supports_udp_over_tcp());
        let target = ipv4_target();
        let mut message_stream = handler
            .setup_client_udp_bidirectional(Box::new(TestStream(client)), (&target).into())
            .await
            .unwrap();

        let mut expected_handshake = create_password_hash("secret").into_vec();
        expected_handshake.extend_from_slice(&CRLF_BYTES);
        expected_handshake.push(CMD_UDP_ASSOCIATE);
        expected_handshake.extend_from_slice(&write_location_to_vec(&target));
        expected_handshake.extend_from_slice(&CRLF_BYTES);
        let mut actual_handshake = vec![0; expected_handshake.len()];
        peer.read_exact(&mut actual_handshake).await.unwrap();
        assert_eq!(actual_handshake, expected_handshake);

        let payload = b"query";
        write_message(&mut *message_stream, payload).await.unwrap();
        flush_message(&mut *message_stream).await.unwrap();
        let expected_frame = encode_frame(&target, payload);
        let mut actual_frame = vec![0; expected_frame.len()];
        peer.read_exact(&mut actual_frame).await.unwrap();
        assert_eq!(actual_frame, expected_frame);
    }

    #[tokio::test]
    async fn tcp_only_client_rejects_udp_before_writing_a_handshake() {
        let (client, mut peer) = duplex(1024);
        let handler = TrojanTcpHandler::new_client_with_udp("secret", &None, false);
        assert!(!handler.supports_udp_over_tcp());
        let error = handler
            .setup_client_udp_bidirectional(Box::new(TestStream(client)), (&ipv4_target()).into())
            .await
            .err()
            .expect("TCP-only Trojan must reject UDP");
        assert_eq!(error.kind(), ErrorKind::Unsupported);

        let mut byte = [0_u8; 1];
        peer.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reads_fragmented_reverse_response_and_coalesced_followup() {
        let (client, mut peer) = duplex(128 * 1024);
        let target = ipv4_target();
        let mut stream = TrojanUdpMessageStream::new(TestStream(client), &target).unwrap();
        let response_source = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 5353);
        let first_payload = b"fragmented response";
        let second_payload = b"coalesced response";
        let first = encode_frame(&response_source, first_payload);
        let second = encode_frame(&target, second_payload);

        let writer = tokio::spawn(async move {
            for chunk in first.chunks(3) {
                peer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            peer.write_all(&second).await.unwrap();
        });

        let mut output = [0_u8; 64];
        let read = {
            let mut read_buf = ReadBuf::new(&mut output);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
                .await
                .unwrap();
            read_buf.filled().len()
        };
        assert_eq!(&output[..read], first_payload);
        let read = {
            let mut read_buf = ReadBuf::new(&mut output);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
                .await
                .unwrap();
            read_buf.filled().len()
        };
        assert_eq!(&output[..read], second_payload);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn small_output_error_does_not_consume_response() {
        let (client, mut peer) = duplex(1024);
        let target = ipv4_target();
        let mut stream = TrojanUdpMessageStream::new(TestStream(client), &target).unwrap();
        let payload = b"too large for the first buffer";
        peer.write_all(&encode_frame(&target, payload))
            .await
            .unwrap();

        let mut small = [0_u8; 4];
        let error = {
            let mut read_buf = ReadBuf::new(&mut small);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
                .await
                .unwrap_err()
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        let mut full = [0_u8; 64];
        let read = {
            let mut read_buf = ReadBuf::new(&mut full);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
                .await
                .unwrap();
            read_buf.filled().len()
        };
        assert_eq!(&full[..read], payload);
    }

    async fn assert_read_error(bytes: &[u8], expected: ErrorKind) {
        let (client, mut peer) = duplex(1024);
        let target = ipv4_target();
        let mut stream = TrojanUdpMessageStream::new(TestStream(client), &target).unwrap();
        peer.write_all(bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut output = [0_u8; 64];
        let mut read_buf = ReadBuf::new(&mut output);
        let error = poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut read_buf))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), expected, "unexpected error: {error}");
    }

    #[tokio::test]
    async fn malformed_and_truncated_frames_fail_loudly() {
        assert_read_error(&[0xff], ErrorKind::InvalidData).await;

        let mut bad_suffix = encode_frame(&ipv4_target(), b"x");
        let address_len = write_location_to_vec(&ipv4_target()).len();
        bad_suffix[address_len + 2] = b'!';
        assert_read_error(&bad_suffix, ErrorKind::InvalidData).await;

        let invalid_domain = [ADDR_TYPE_DOMAIN_NAME, 1, 0xff, 0, 53, 0, 0, b'\r', b'\n'];
        assert_read_error(&invalid_domain, ErrorKind::InvalidData).await;

        let complete = encode_frame(&ipv4_target(), b"truncated");
        assert_read_error(&complete[..complete.len() - 1], ErrorKind::UnexpectedEof).await;
    }

    #[tokio::test]
    async fn write_handles_fragmented_transport_and_payload_length_boundaries() {
        let target = NetLocation::new(Address::Hostname("dns.example".to_string()), 53);
        let max_payload = vec![0x5a; MAX_UDP_PAYLOAD_LEN];
        let expected = encode_frame(&target, &max_payload);
        let (client, mut peer) = duplex(3);
        let mut stream = TrojanUdpMessageStream::new(TestStream(client), &target).unwrap();
        let expected_len = expected.len();
        let reader = tokio::spawn(async move {
            let mut actual = vec![0; expected_len];
            peer.read_exact(&mut actual).await.unwrap();
            actual
        });

        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &max_payload))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();
        assert_eq!(reader.await.unwrap(), expected);

        let (client, _peer) = duplex(1024);
        let mut stream = TrojanUdpMessageStream::new(TestStream(client), &target).unwrap();
        let oversized = vec![0; MAX_UDP_PAYLOAD_LEN + 1];
        let error = poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &oversized))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &[]))
            .await
            .unwrap();
        assert_eq!(
            stream.pending_write,
            encode_frame(&target, &[]),
            "zero-length datagrams retain a complete frame"
        );
    }

    #[test]
    fn destination_hostname_length_is_bounded() {
        let target = NetLocation::new(Address::Hostname("a".repeat(256)), 53);
        let (client, _peer) = duplex(1024);
        let error = TrojanUdpMessageStream::new(TestStream(client), &target)
            .err()
            .expect("overlong hostname should fail");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
