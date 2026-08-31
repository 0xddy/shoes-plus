use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::VlessPacketEncoding;
use crate::crypto::CryptoTlsStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::uot::VlessPacketAddrClientStream;
use crate::util::{allocate_vec, write_all};
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpClientMessageStream;

use super::vision_stream::VisionStream;
use super::vless_message_stream::VlessMessageStream;
use super::vless_response_stream::VlessResponseStream;
use super::vless_util::{COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, vision_flow_addon_data};

const PACKET_ADDR_MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

pub struct VlessTcpClientHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
    packet_encoding: Option<VlessPacketEncoding>,
}

impl std::fmt::Debug for VlessTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpClientHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .field("packet_encoding", &self.packet_encoding)
            .finish()
    }
}

impl VlessTcpClientHandler {
    pub fn new(
        user_id: &str,
        udp_enabled: bool,
        packet_encoding: Option<VlessPacketEncoding>,
    ) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
            udp_enabled,
            packet_encoding,
        }
    }
}

#[async_trait]
impl TcpClientHandler for VlessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        write_vless_header(
            &mut client_stream,
            &self.user_id,
            &[],
            remote_location.location(),
        )
        .await?;
        client_stream.flush().await?;
        let client_stream = Box::new(VlessResponseStream::new(client_stream));

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn needs_handshake_for_write(&self) -> bool {
        true
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled // VLESS supports XUDP for UDP-over-TCP when enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        setup_vless_udp_stream(client_stream, &self.user_id, target, self.packet_encoding).await
    }
}

/// Helper function for setup_client_udp_bidirectional that can be called from TlsClientHandler
/// for Vision VLESS or regular VLESS over TLS.
pub async fn setup_vless_udp_bidirectional<IO>(
    mut stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    target: ResolvedLocation,
    packet_encoding: Option<VlessPacketEncoding>,
) -> std::io::Result<Box<dyn AsyncMessageStream>>
where
    IO: crate::async_stream::AsyncStream + 'static,
{
    if packet_encoding != Some(VlessPacketEncoding::Xudp) {
        return setup_vless_udp_stream(Box::new(stream), user_id, target, packet_encoding).await;
    }

    let resolved_target = require_resolved_target(&target)?;
    write_vless_mux_header(&mut stream, user_id, vision_flow_addon_data()).await?;
    stream.flush().await?;

    // sing-vmess applies Vision framing to CommandMux, unlike CommandUdp.
    let (io, connection) = stream.into_inner();
    let mut user_uuid = [0_u8; 16];
    user_uuid.copy_from_slice(user_id);
    let vision_stream = VisionStream::new_client(io, connection, user_uuid);
    Ok(Box::new(XudpClientMessageStream::new(
        Box::new(vision_stream),
        target.into_location(),
        resolved_target,
    )))
}

async fn setup_vless_udp_stream(
    mut stream: Box<dyn AsyncStream>,
    user_id: &[u8],
    target: ResolvedLocation,
    packet_encoding: Option<VlessPacketEncoding>,
) -> std::io::Result<Box<dyn AsyncMessageStream>> {
    match packet_encoding {
        None => {
            write_vless_udp_header(&mut stream, user_id, target.location()).await?;
            stream.flush().await?;
            let response_stream = Box::new(VlessResponseStream::new(stream));
            Ok(Box::new(VlessMessageStream::new(response_stream)))
        }
        Some(VlessPacketEncoding::Xudp) => {
            let resolved_target = require_resolved_target(&target)?;
            write_vless_mux_header(&mut stream, user_id, &[]).await?;
            stream.flush().await?;
            let response_stream = Box::new(VlessResponseStream::new(stream));
            Ok(Box::new(XudpClientMessageStream::new(
                response_stream,
                target.into_location(),
                resolved_target,
            )))
        }
        Some(VlessPacketEncoding::Packetaddr) => {
            if matches!(target.address(), Address::Hostname(_)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "VLESS packetaddr only supports IP destinations",
                ));
            }
            let resolved_target = require_resolved_target(&target)?;
            let magic_target =
                NetLocation::new(Address::Hostname(PACKET_ADDR_MAGIC_ADDRESS.to_owned()), 0);
            write_vless_udp_header(&mut stream, user_id, &magic_target).await?;
            stream.flush().await?;
            let response_stream = Box::new(VlessResponseStream::new(stream));
            Ok(Box::new(VlessPacketAddrClientStream::new(
                response_stream,
                resolved_target,
            )))
        }
    }
}

fn require_resolved_target(target: &ResolvedLocation) -> std::io::Result<std::net::SocketAddr> {
    target
        .resolved_addr()
        .or_else(|| target.location().to_socket_addr_nonblocking())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("VLESS packet encoding requires a resolved destination: {target}"),
            )
        })
}

pub async fn setup_custom_tls_vision_vless_client_stream<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<TcpClientSetupResult>
where
    IO: crate::async_stream::AsyncStream + 'static,
{
    write_vless_header(
        &mut tls_stream,
        user_id,
        vision_flow_addon_data(),
        remote_location,
    )
    .await?;
    tls_stream.flush().await?;

    let (io, connection) = tls_stream.into_inner();
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(user_id);
    let vision_stream = VisionStream::new_client(io, connection, user_uuid);

    Ok(TcpClientSetupResult {
        client_stream: Box::new(vision_stream),
        early_data: None,
    })
}

/// Write VLESS UDP header for single-target bidirectional UDP (COMMAND_UDP = 2).
/// Same format as TCP header but with command=2.
async fn write_vless_udp_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<()> {
    // VLESS UDP header format (same as TCP but command=2):
    // version (1 byte) + user_id (16 bytes) + addon_length (1 byte) + command (1 byte) + port (2 bytes) + address_type (1 byte) + address

    // Calculate base header size: version + user_id + addon_length + command + port + address_type
    let base_header_size = 1 + 16 + 1 + 1 + 2 + 1;
    let mut header_bytes = allocate_vec(base_header_size);

    // version 0
    header_bytes[0] = 0;
    // Copy user_id
    header_bytes[1..17].copy_from_slice(user_id);
    // addon length = 0
    header_bytes[17] = 0;
    // command = UDP (2)
    header_bytes[18] = COMMAND_UDP;

    // port (2 bytes, big-endian)
    let remote_port = remote_location.port();
    header_bytes[19] = (remote_port >> 8) as u8;
    header_bytes[20] = (remote_port & 0xff) as u8;

    // address_type
    let address_type_offset = 21;

    match remote_location.address() {
        Address::Ipv4(v4addr) => {
            header_bytes[address_type_offset] = 1;
            header_bytes.extend_from_slice(&v4addr.octets());
        }
        Address::Ipv6(v6addr) => {
            header_bytes[address_type_offset] = 3;
            header_bytes.extend_from_slice(&v6addr.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Hostname is too long: {hostname}"),
                ));
            }

            header_bytes[address_type_offset] = 2;
            header_bytes.push(hostname.len() as u8);
            header_bytes.extend_from_slice(hostname.as_bytes());
        }
    }

    write_all(stream, &header_bytes).await?;

    Ok(())
}

/// Write a VLESS CommandMux request.  Per the VLESS wire format, Mux has no
/// request destination; XUDP carries it in its first New frame instead.
async fn write_vless_mux_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    addon_data: &[u8],
) -> std::io::Result<()> {
    if addon_data.len() > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS addon data is too long",
        ));
    }
    let mut header_bytes = allocate_vec(1 + 16 + 1 + addon_data.len() + 1);
    header_bytes[0] = 0;
    header_bytes[1..17].copy_from_slice(user_id);
    header_bytes[17] = addon_data.len() as u8;
    if !addon_data.is_empty() {
        header_bytes[18..18 + addon_data.len()].copy_from_slice(addon_data);
    }
    header_bytes[18 + addon_data.len()] = COMMAND_MUX;
    write_all(stream, &header_bytes).await
}

async fn write_vless_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    addon_data: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<()> {
    crate::tcp::write_handshake::mark_started();

    // VLESS header format:
    // version (1 byte) + user_id (16 bytes) + addon_length (1 byte) + addon_data + command (1 byte) + port (2 bytes) + address_type (1 byte) + address

    // Calculate base header size: version + user_id + addon_length + addon_data + command + port + address_type
    let base_header_size = 1 + 16 + 1 + addon_data.len() + 1 + 2 + 1;
    let mut header_bytes = allocate_vec(base_header_size);

    // version 0, we need to write since it's uninitialized
    header_bytes[0] = 0;
    // Copy user_id
    header_bytes[1..17].copy_from_slice(user_id);

    // addon length
    header_bytes[17] = addon_data.len() as u8;

    // Copy addon data if present
    if !addon_data.is_empty() {
        header_bytes[18..18 + addon_data.len()].copy_from_slice(addon_data);
    }

    let addon_end = 18 + addon_data.len();

    // command (1 = tcp)
    header_bytes[addon_end] = COMMAND_TCP;

    // port (2 bytes, big-endian)
    let remote_port = remote_location.port();
    header_bytes[addon_end + 1] = (remote_port >> 8) as u8;
    header_bytes[addon_end + 2] = (remote_port & 0xff) as u8;

    // address_type
    let address_type_offset = addon_end + 3;

    match remote_location.address() {
        Address::Ipv4(v4addr) => {
            header_bytes[address_type_offset] = 1;
            header_bytes.extend_from_slice(&v4addr.octets());
        }
        Address::Ipv6(v6addr) => {
            header_bytes[address_type_offset] = 3;
            header_bytes.extend_from_slice(&v6addr.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Hostname is too long: {hostname}"),
                ));
            }

            header_bytes[address_type_offset] = 2;
            header_bytes.push(hostname.len() as u8);
            header_bytes.extend_from_slice(hostname.as_bytes());
        }
    }

    write_all(stream, &header_bytes).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };

    use crate::async_stream::{AsyncPing, AsyncStream};

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

    fn target() -> ResolvedLocation {
        let address = SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 53));
        ResolvedLocation::with_resolved(
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53),
            address,
        )
    }

    async fn write_message(stream: &mut Box<dyn AsyncMessageStream>, payload: &[u8]) {
        poll_fn(|cx| Pin::new(&mut **stream).poll_write_message(cx, payload))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut **stream).poll_flush_message(cx))
            .await
            .unwrap();
    }

    #[test]
    fn client_reports_go_write_handshake_semantics() {
        let client =
            VlessTcpClientHandler::new("11111111-1111-4111-8111-111111111111", false, None);
        assert!(client.needs_handshake_for_write());
    }

    #[tokio::test]
    async fn xudp_wire_uses_mux_session_zero_new_then_keep() {
        let (client, mut server) = duplex(4096);
        let mut stream = setup_vless_udp_stream(
            Box::new(TestStream(client)),
            &[0x11; 16],
            target(),
            Some(VlessPacketEncoding::Xudp),
        )
        .await
        .unwrap();

        write_message(&mut stream, b"abc").await;
        write_message(&mut stream, b"de").await;

        let first_frame = [
            0x00, 0x0c, // metadata length
            0x00, 0x00, // session 0
            0x01, 0x01, 0x02, // New, Data, UDP
            0x00, 0x35, 0x01, 1, 2, 3, 4, // target
            0x00, 0x03, b'a', b'b', b'c',
        ];
        let second_frame = [
            0x00, 0x0c, 0x00, 0x00, 0x02, 0x01, 0x02, // Keep, Data, UDP
            0x00, 0x35, 0x01, 1, 2, 3, 4, 0x00, 0x02, b'd', b'e',
        ];
        let mut expected = vec![0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
        expected.extend_from_slice(&[0x11; 8]);
        expected.extend_from_slice(&[0, COMMAND_MUX]);
        expected.extend_from_slice(&first_frame);
        expected.extend_from_slice(&second_frame);

        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        // VLESS response header followed by sing-vmess' compact Keep frame
        // (metadata length 4, therefore reusing the session-0 destination).
        server
            .write_all(&[
                0, 0, // VLESS response
                0, 4, 0, 0, 2, 1, // XUDP Keep + Data
                0, 3, b'r', b'e', b's',
            ])
            .await
            .unwrap();
        let mut payload = [0_u8; 16];
        let mut read_buf = ReadBuf::new(&mut payload);
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf))
            .await
            .unwrap();
        assert_eq!(read_buf.filled(), b"res");
    }

    #[tokio::test]
    async fn xudp_new_frame_preserves_hostname_with_resolved_candidate() {
        let (client, mut server) = duplex(4096);
        let hostname = "dns.example";
        let target = ResolvedLocation::with_resolved(
            NetLocation::new(Address::Hostname(hostname.to_owned()), 53),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53)),
        );
        let mut stream = setup_vless_udp_stream(
            Box::new(TestStream(client)),
            &[0x12; 16],
            target,
            Some(VlessPacketEncoding::Xudp),
        )
        .await
        .unwrap();

        write_message(&mut stream, b"dns").await;

        let metadata_len = 9 + hostname.len();
        let mut frame = vec![0, metadata_len as u8, 0, 0, 1, 1, 2, 0, 53, 2];
        frame.push(hostname.len() as u8);
        frame.extend_from_slice(hostname.as_bytes());
        frame.extend_from_slice(&[0, 3, b'd', b'n', b's']);
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x12; 16]);
        expected.extend_from_slice(&[0, COMMAND_MUX]);
        expected.extend_from_slice(&frame);

        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn packetaddr_wire_uses_magic_request_and_v2fly_ip_frame() {
        let (client, mut server) = duplex(4096);
        let mut stream = setup_vless_udp_stream(
            Box::new(TestStream(client)),
            &[0x22; 16],
            target(),
            Some(VlessPacketEncoding::Packetaddr),
        )
        .await
        .unwrap();
        write_message(&mut stream, b"dns").await;

        let mut expected = vec![0];
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&[0, COMMAND_UDP, 0, 0, 2]);
        expected.push(PACKET_ADDR_MAGIC_ADDRESS.len() as u8);
        expected.extend_from_slice(PACKET_ADDR_MAGIC_ADDRESS.as_bytes());
        expected.extend_from_slice(&[1, 1, 2, 3, 4, 0, 53, 0, 3, b'd', b'n', b's']);

        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn vision_xudp_mux_header_carries_flow_and_has_no_destination() {
        let (client, mut server) = duplex(512);
        let mut client = TestStream(client);
        write_vless_mux_header(&mut client, &[0x55; 16], vision_flow_addon_data())
            .await
            .unwrap();
        client.flush().await.unwrap();

        let addon = vision_flow_addon_data();
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x55; 16]);
        expected.push(addon.len() as u8);
        expected.extend_from_slice(addon);
        expected.push(COMMAND_MUX);
        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn packetaddr_rejects_domain_destination() {
        let (client, _server) = duplex(256);
        let target = ResolvedLocation::with_resolved(
            NetLocation::new(Address::Hostname("example.com".to_owned()), 53),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        );
        let result = setup_vless_udp_stream(
            Box::new(TestStream(client)),
            &[0x33; 16],
            target,
            Some(VlessPacketEncoding::Packetaddr),
        )
        .await;
        assert_eq!(
            result.err().expect("domain packetaddr must fail").kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn legacy_udp_wire_is_unchanged_when_encoding_is_omitted() {
        let (client, mut server) = duplex(4096);
        let mut stream =
            setup_vless_udp_stream(Box::new(TestStream(client)), &[0x44; 16], target(), None)
                .await
                .unwrap();
        write_message(&mut stream, b"old").await;

        let mut expected = vec![0];
        expected.extend_from_slice(&[0x44; 16]);
        expected.extend_from_slice(&[0, COMMAND_UDP, 0, 53, 1, 1, 2, 3, 4]);
        expected.extend_from_slice(&[0, 3, b'o', b'l', b'd']);
        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }
}
