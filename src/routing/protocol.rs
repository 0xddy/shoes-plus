//! Bounded, replay-safe TCP application protocol sniffing.
//!
//! The node-agent control plane models sing-box's unconditional `sniff` action before
//! `protocol` route rules.  This module keeps that concern outside individual proxy
//! protocols: callers give us any payload bytes already consumed while parsing the
//! inbound header, and every extra byte read here is appended to the same buffer for
//! forwarding to the destination unchanged.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::routing::predicate::RouteProtocol;

/// sing-box's default timeout for the `sniff` route action.
pub(crate) const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
/// A ClientHello or HTTP header larger than this is treated as unclassified.
const MAX_SNIFF_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SniffedTcpMetadata {
    pub protocol: RouteProtocol,
    /// HTTP Host or TLS SNI.  Empty/missing values leave this as `None`.
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TcpPrefixClassification {
    Matched(SniffedTcpMetadata),
    NeedMore,
    NoMatch,
}

/// Sniff HTTP/TLS from a TCP payload without consuming bytes from the relay.
///
/// `replay` may already contain early data extracted by an inbound handshake. Any
/// bytes read from `stream` are appended to it and must later be written upstream.
/// Timeout, EOF, malformed input and the size limit simply mean "unclassified";
/// transport errors other than EOF are returned to the caller.
pub(crate) async fn sniff_tcp<S>(
    stream: &mut S,
    replay: &mut Vec<u8>,
) -> io::Result<Option<SniffedTcpMetadata>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    match classify_tcp_prefix(replay) {
        TcpPrefixClassification::Matched(metadata) => return Ok(Some(metadata)),
        TcpPrefixClassification::NoMatch => return Ok(None),
        TcpPrefixClassification::NeedMore => {}
    }

    let sniff = async {
        let mut chunk = [0u8; 2048];
        loop {
            if replay.len() >= MAX_SNIFF_BYTES {
                return Ok(None);
            }
            let remaining = MAX_SNIFF_BYTES - replay.len();
            let read_len = chunk.len().min(remaining);
            let read = stream.read(&mut chunk[..read_len]).await;
            match read {
                Ok(0) => return Ok(None),
                Ok(count) => replay.extend_from_slice(&chunk[..count]),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            }
            match classify_tcp_prefix(replay) {
                TcpPrefixClassification::Matched(metadata) => return Ok(Some(metadata)),
                TcpPrefixClassification::NeedMore => {}
                TcpPrefixClassification::NoMatch => return Ok(None),
            }
        }
    };

    match timeout(DEFAULT_SNIFF_TIMEOUT, sniff).await {
        Ok(result) => result,
        Err(_) => Ok(None),
    }
}

pub(crate) fn classify_tcp_prefix(bytes: &[u8]) -> TcpPrefixClassification {
    let tls = classify_tls(bytes);
    if matches!(tls, TcpPrefixClassification::Matched(_)) {
        return tls;
    }
    let http = classify_http(bytes);
    if matches!(http, TcpPrefixClassification::Matched(_)) {
        return http;
    }
    if matches!(tls, TcpPrefixClassification::NeedMore)
        || matches!(http, TcpPrefixClassification::NeedMore)
    {
        TcpPrefixClassification::NeedMore
    } else {
        TcpPrefixClassification::NoMatch
    }
}

fn classify_http(bytes: &[u8]) -> TcpPrefixClassification {
    const METHODS: &[&[u8]] = &[
        b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
        b"PRI",
    ];
    let Some(space) = bytes.iter().position(|byte| *byte == b' ') else {
        return if METHODS.iter().any(|method| method.starts_with(bytes)) {
            TcpPrefixClassification::NeedMore
        } else {
            TcpPrefixClassification::NoMatch
        };
    };
    if !METHODS.iter().any(|method| *method == &bytes[..space]) {
        return TcpPrefixClassification::NoMatch;
    }
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if bytes.len() < MAX_SNIFF_BYTES {
            TcpPrefixClassification::NeedMore
        } else {
            TcpPrefixClassification::NoMatch
        };
    };
    let header = &bytes[..header_end + 4];
    let Ok(text) = std::str::from_utf8(header) else {
        return TcpPrefixClassification::NoMatch;
    };
    let mut lines = text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return TcpPrefixClassification::NoMatch;
    };
    let mut request_parts = request_line.split(' ');
    let (Some(_method), Some(target), Some(version), None) = (
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
        request_parts.next(),
    ) else {
        return TcpPrefixClassification::NoMatch;
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1" | "HTTP/2.0") {
        return TcpPrefixClassification::NoMatch;
    }

    let header_host = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then(|| value.trim())
    });
    let target_host = if target.starts_with("http://") || target.starts_with("https://") {
        target
            .parse::<http::Uri>()
            .ok()
            .and_then(|uri| uri.host().map(str::to_owned))
    } else if request_line.starts_with("CONNECT ") {
        Some(target.to_owned())
    } else {
        None
    };
    let domain = header_host
        .map(str::to_owned)
        .or(target_host)
        .and_then(|host| normalize_authority_host(&host));
    TcpPrefixClassification::Matched(SniffedTcpMetadata {
        protocol: RouteProtocol::Http,
        domain,
    })
}

fn classify_tls(bytes: &[u8]) -> TcpPrefixClassification {
    if bytes.is_empty() {
        return TcpPrefixClassification::NeedMore;
    }
    if bytes[0] != 0x16 {
        return TcpPrefixClassification::NoMatch;
    }

    let mut record_offset = 0usize;
    let mut handshake = Vec::new();
    loop {
        if bytes.len() < record_offset + 5 {
            return TcpPrefixClassification::NeedMore;
        }
        if bytes[record_offset] != 0x16 || bytes[record_offset + 1] != 0x03 {
            return TcpPrefixClassification::NoMatch;
        }
        let record_len =
            u16::from_be_bytes([bytes[record_offset + 3], bytes[record_offset + 4]]) as usize;
        if record_len == 0 || record_len > 18_432 {
            return TcpPrefixClassification::NoMatch;
        }
        let record_end = record_offset + 5 + record_len;
        if bytes.len() < record_end {
            return TcpPrefixClassification::NeedMore;
        }
        handshake.extend_from_slice(&bytes[record_offset + 5..record_end]);
        if handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return TcpPrefixClassification::NoMatch;
            }
            let hello_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if hello_len > MAX_SNIFF_BYTES - 4 {
                return TcpPrefixClassification::NoMatch;
            }
            if handshake.len() >= hello_len + 4 {
                let domain = parse_client_hello_sni(&handshake[4..hello_len + 4]);
                return TcpPrefixClassification::Matched(SniffedTcpMetadata {
                    protocol: RouteProtocol::Tls,
                    domain,
                });
            }
        }
        record_offset = record_end;
        if record_offset >= MAX_SNIFF_BYTES {
            return TcpPrefixClassification::NoMatch;
        }
    }
}

fn parse_client_hello_sni(hello: &[u8]) -> Option<String> {
    // legacy_version + random
    let mut offset = 34usize;
    offset = skip_u8_vector(hello, offset)?;
    offset = skip_u16_vector(hello, offset)?;
    offset = skip_u8_vector(hello, offset)?;
    if offset == hello.len() {
        return None;
    }
    let extensions_len = read_u16(hello, offset)?;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > hello.len() {
        return None;
    }
    while offset + 4 <= extensions_end {
        let extension_type = read_u16(hello, offset)?;
        let extension_len = read_u16(hello, offset + 2)?;
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == 0 {
            let list_len = read_u16(hello, offset)?;
            let mut name_offset = offset + 2;
            let list_end = name_offset.checked_add(list_len)?;
            if list_end > extension_end {
                return None;
            }
            while name_offset + 3 <= list_end {
                let name_type = hello[name_offset];
                let name_len = read_u16(hello, name_offset + 1)?;
                name_offset += 3;
                let name_end = name_offset.checked_add(name_len)?;
                if name_end > list_end {
                    return None;
                }
                if name_type == 0 {
                    let name = std::str::from_utf8(&hello[name_offset..name_end]).ok()?;
                    return normalize_authority_host(name);
                }
                name_offset = name_end;
            }
            return None;
        }
        offset = extension_end;
    }
    None
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]) as usize)
}

fn skip_u8_vector(bytes: &[u8], offset: usize) -> Option<usize> {
    let len = *bytes.get(offset)? as usize;
    let end = offset.checked_add(1)?.checked_add(len)?;
    (end <= bytes.len()).then_some(end)
}

fn skip_u16_vector(bytes: &[u8], offset: usize) -> Option<usize> {
    let len = read_u16(bytes, offset)?;
    let end = offset.checked_add(2)?.checked_add(len)?;
    (end <= bytes.len()).then_some(end)
}

fn normalize_authority_host(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            host
        } else {
            authority
        }
    } else {
        authority
    };
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use crate::async_stream::{AsyncPing, AsyncStream};

    struct TestStream {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let count = buffer
                .remaining()
                .min(self.bytes.len().saturating_sub(self.offset));
            buffer.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn tls_client_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&((sni.len() + 4) as u16).to_be_bytes());
        hello.extend_from_slice(&0u16.to_be_bytes());
        hello.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hello.extend_from_slice(&sni);

        let mut handshake = vec![
            1,
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn classifies_complete_http_and_host() {
        let result = classify_tcp_prefix(b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\n\r\nbody");
        assert_eq!(
            result,
            TcpPrefixClassification::Matched(SniffedTcpMetadata {
                protocol: RouteProtocol::Http,
                domain: Some("example.com".into()),
            })
        );
    }

    #[test]
    fn waits_for_partial_http_without_guessing() {
        assert_eq!(
            classify_tcp_prefix(b"GE"),
            TcpPrefixClassification::NeedMore
        );
        assert_eq!(
            classify_tcp_prefix(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            TcpPrefixClassification::NeedMore
        );
        assert_eq!(
            classify_tcp_prefix(b"GARBAGE\0"),
            TcpPrefixClassification::NoMatch
        );
    }

    #[test]
    fn classifies_tls_client_hello_and_sni() {
        let hello = tls_client_hello("TLS.Example.COM");
        assert_eq!(
            classify_tcp_prefix(&hello),
            TcpPrefixClassification::Matched(SniffedTcpMetadata {
                protocol: RouteProtocol::Tls,
                domain: Some("tls.example.com".into()),
            })
        );
        assert_eq!(
            classify_tcp_prefix(&hello[..5]),
            TcpPrefixClassification::NeedMore
        );
    }

    #[test]
    fn rejects_non_client_tls_handshake() {
        let mut hello = tls_client_hello("example.com");
        hello[5] = 2;
        assert_eq!(
            classify_tcp_prefix(&hello),
            TcpPrefixClassification::NoMatch
        );
    }

    #[tokio::test]
    async fn every_peeked_byte_is_retained_for_upstream_replay() {
        let tail = b"T / HTTP/1.1\r\nHost: replay.example\r\n\r\npayload";
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream {
            bytes: tail.to_vec(),
            offset: 0,
        });
        let mut replay = b"GE".to_vec();
        let metadata = sniff_tcp(&mut stream, &mut replay).await.unwrap().unwrap();

        assert_eq!(metadata.protocol, RouteProtocol::Http);
        assert_eq!(metadata.domain.as_deref(), Some("replay.example"));
        assert_eq!(replay, [b"GE".as_slice(), tail].concat());
    }
}
