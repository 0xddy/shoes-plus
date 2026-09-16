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
    /// The visible HTTP host or TLS SNI, preserving its original spelling.
    /// This is an observation, including an ECH outer name or GREASE ECH.
    pub analysis_domain: Option<String>,
    /// An encrypted_client_hello extension was present; this does not confirm
    /// ECH negotiation or identify the encrypted inner destination.
    pub ech_present: bool,
    /// False when the payload contains an unrepresentable or incomplete
    /// observation. Such traffic must not become a missing-domain report.
    pub analysis_valid: bool,
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
    let authority = header_host.map(str::to_owned).or(target_host);
    let domain = authority.as_deref().and_then(normalize_authority_host);
    let analysis_domain = authority.as_deref().map(authority_host).map(str::to_owned);
    TcpPrefixClassification::Matched(SniffedTcpMetadata {
        protocol: RouteProtocol::Http,
        analysis_domain,
        domain,
        ech_present: false,
        analysis_valid: true,
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
                let names = parse_client_hello_server_names(&handshake[4..hello_len + 4]);
                return TcpPrefixClassification::Matched(SniffedTcpMetadata {
                    protocol: RouteProtocol::Tls,
                    domain: names.domain,
                    analysis_domain: names.analysis_domain,
                    ech_present: names.ech_present,
                    analysis_valid: names.analysis_valid,
                });
            }
        }
        record_offset = record_end;
        if record_offset >= MAX_SNIFF_BYTES {
            return TcpPrefixClassification::NoMatch;
        }
    }
}

pub(crate) struct ClientHelloServerNames {
    pub domain: Option<String>,
    pub analysis_domain: Option<String>,
    pub ech_present: bool,
    pub analysis_valid: bool,
}

pub(crate) fn parse_client_hello_server_names(hello: &[u8]) -> ClientHelloServerNames {
    let mut names = ClientHelloServerNames {
        domain: None,
        analysis_domain: None,
        ech_present: false,
        analysis_valid: true,
    };
    // Only report observations from a complete extension vector. Routing keeps
    // its existing first-SNI behavior even if a later extension is malformed.
    if let Some(ech_present) = client_hello_has_ech(hello, &mut names) {
        names.ech_present = ech_present;
    } else {
        names.analysis_domain = None;
        names.analysis_valid = false;
    }
    names
}

fn client_hello_has_ech(hello: &[u8], names: &mut ClientHelloServerNames) -> Option<bool> {
    const ENCRYPTED_CLIENT_HELLO: usize = 0xfe0d;
    // legacy_version + random
    let mut offset = 34usize;
    offset = skip_u8_vector(hello, offset)?;
    offset = skip_u16_vector(hello, offset)?;
    offset = skip_u8_vector(hello, offset)?;
    if offset == hello.len() {
        return Some(false);
    }
    let extensions_len = read_u16(hello, offset)?;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > hello.len() {
        return None;
    }
    let mut has_ech = false;
    let mut saw_server_name = false;
    while offset < extensions_end {
        if extensions_end - offset < 4 {
            return None;
        }
        let extension_type = read_u16(hello, offset)?;
        let extension_len = read_u16(hello, offset + 2)?;
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        has_ech |= extension_type == ENCRYPTED_CLIENT_HELLO;
        if extension_type == 0 && !saw_server_name {
            // Retain the first SNI extension, as the routing parser did before
            // analytics needed the rest of the extension list.
            saw_server_name = true;
            let mut raw = None;
            if parse_server_name_extension(&hello[offset..extension_end], &mut raw).is_none() {
                names.analysis_valid = false;
            }
            if let Some(raw) = raw {
                if let Ok(name) = std::str::from_utf8(raw) {
                    names.domain = normalize_authority_host(name);
                    // The bounded sniffer owns the raw observation; the collector
                    // rejects invalid lengths/NUL rather than recording an empty name.
                    names.analysis_domain = Some(name.to_owned());
                } else {
                    names.analysis_valid = false;
                }
            }
        }
        offset = extension_end;
    }
    // A ClientHello ends with the extension vector. Preserve routing SNI from
    // the declared block, but do not trust it for analytics if bytes follow it.
    (extensions_end == hello.len()).then_some(has_ech)
}

fn parse_server_name_extension<'a>(extension: &'a [u8], name: &mut Option<&'a [u8]>) -> Option<()> {
    let list_len = read_u16(extension, 0)?;
    let mut offset = 2usize;
    let list_end = offset.checked_add(list_len)?;
    if list_end > extension.len() {
        return None;
    }
    while offset + 3 <= list_end {
        let name_type = extension[offset];
        let name_len = read_u16(extension, offset + 1)?;
        offset += 3;
        let name_end = offset.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 && name.is_none() {
            *name = Some(&extension[offset..name_end]);
        }
        offset = name_end;
    }
    (offset == list_end && list_end == extension.len()).then_some(())
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

/// Keep the same bounded UTF-8 observation contract as the analysis collector.
/// Domain spelling and interpretation belong to the receiver, not the core.
pub(crate) fn valid_analysis_domain(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && !name.contains('\0')
}

fn authority_host(authority: &str) -> &str {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            host
        } else {
            authority
        }
    } else {
        authority
    }
}

fn normalize_authority_host(authority: &str) -> Option<String> {
    let host = authority_host(authority);
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

#[cfg(test)]
pub(crate) mod test_vectors {
    /// The same ClientHello is used by both TCP and encrypted QUIC tests.
    pub(crate) fn tls_client_hello(
        server_name: &str,
        extra: &[(u16, &[u8])],
        sni_first: bool,
    ) -> Vec<u8> {
        let name = server_name.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        let mut extensions = Vec::new();
        let mut append = |kind: u16, body: &[u8]| {
            extensions.extend_from_slice(&kind.to_be_bytes());
            extensions.extend_from_slice(&(body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(body);
        };
        if sni_first {
            append(0, &sni);
        }
        for (kind, body) in extra {
            append(*kind, body);
        }
        if !sni_first {
            append(0, &sni);
        }

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0u8; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
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

    pub(crate) fn ech_outer_payload(grease: bool) -> Vec<u8> {
        // outer, KDF/AEAD IDs, config ID, encapsulated key, ciphertext. The
        // passive parser must not try to decrypt or distinguish GREASE here.
        let mut payload = vec![0, 0, 1, 0, 1, if grease { 0xff } else { 7 }, 0, 32];
        payload.extend_from_slice(&[if grease { 0xa5 } else { 0x12 }; 32]);
        payload.extend_from_slice(&64u16.to_be_bytes());
        payload.extend_from_slice(&[if grease { 0x5a } else { 0x34 }; 64]);
        payload
    }
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
        test_vectors::tls_client_hello(server_name, &[], true)
    }

    #[tokio::test(start_paused = true)]
    async fn slow_partial_reads_share_one_deadline_and_preserve_replay() {
        use tokio::io::AsyncWriteExt;
        let (mut stream, mut writer) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            writer.write_all(b"G").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            writer.write_all(b"E").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = writer
                .write_all(b"T / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await;
        });
        let start = tokio::time::Instant::now();
        let mut replay = Vec::new();
        assert!(
            super::sniff_tcp(&mut stream, &mut replay)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(start.elapsed(), std::time::Duration::from_millis(300));
        assert_eq!(replay, b"GE");
        task.abort();
    }

    #[test]
    fn classifies_complete_http_and_host() {
        let result = classify_tcp_prefix(b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\n\r\nbody");
        assert_eq!(
            result,
            TcpPrefixClassification::Matched(SniffedTcpMetadata {
                protocol: RouteProtocol::Http,
                domain: Some("example.com".into()),
                analysis_domain: Some("Example.COM".into()),
                ech_present: false,
                analysis_valid: true,
            })
        );
    }

    #[test]
    fn http_observations_preserve_host_spelling_without_the_authority_port() {
        for (authority, expected) in [
            ("MiXeD.Example.:443", "MiXeD.Example."),
            ("例子.测试:8080", "例子.测试"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            let TcpPrefixClassification::Matched(metadata) =
                classify_tcp_prefix(request.as_bytes())
            else {
                panic!("HTTP fixture must classify");
            };
            assert_eq!(metadata.analysis_domain.as_deref(), Some(expected));
            assert!(metadata.analysis_valid);
            assert!(!metadata.ech_present);
        }
    }

    #[test]
    fn raw_observation_boundaries_are_preserved_for_collector_validation() {
        for name in ["a".repeat(253), "a".repeat(254), "nul\0name".to_owned()] {
            let hello = tls_client_hello(&name);
            let TcpPrefixClassification::Matched(metadata) = classify_tcp_prefix(&hello) else {
                panic!("bounded TLS fixture must classify");
            };
            assert_eq!(metadata.analysis_domain.as_deref(), Some(name.as_str()));
            assert!(metadata.analysis_valid);
            let request = format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n");
            let TcpPrefixClassification::Matched(metadata) =
                classify_tcp_prefix(request.as_bytes())
            else {
                panic!("bounded HTTP fixture must classify");
            };
            assert_eq!(metadata.analysis_domain.as_deref(), Some(name.as_str()));
        }
        assert!(valid_analysis_domain(&"é".repeat(126)));
        assert!(!valid_analysis_domain(&"é".repeat(127)));
        assert!(!valid_analysis_domain("nul\0name"));
    }

    #[test]
    fn invalid_utf8_sni_is_not_a_missing_domain_observation() {
        let mut hello = tls_client_hello("example.com");
        *hello.last_mut().unwrap() = 0xff;
        let TcpPrefixClassification::Matched(metadata) = classify_tcp_prefix(&hello) else {
            panic!("routing classification must remain TLS");
        };
        assert_eq!(metadata.protocol, RouteProtocol::Tls);
        assert_eq!(metadata.domain, None);
        assert_eq!(metadata.analysis_domain, None);
        assert!(!metadata.analysis_valid);
    }

    #[test]
    fn malformed_server_name_vector_is_not_a_missing_domain_observation() {
        let mut hello = tls_client_hello("example.com");
        // TLS record + handshake + fixed ClientHello fields + extension header.
        hello[56..58].copy_from_slice(&u16::MAX.to_be_bytes());
        let TcpPrefixClassification::Matched(metadata) = classify_tcp_prefix(&hello) else {
            panic!("routing classification must remain TLS");
        };
        assert_eq!(metadata.domain, None);
        assert_eq!(metadata.analysis_domain, None);
        assert!(!metadata.analysis_valid);
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
                analysis_domain: Some("TLS.Example.COM".into()),
                ech_present: false,
                analysis_valid: true,
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

    #[test]
    fn ech_before_or_after_sni_preserves_raw_name_and_presence() {
        for grease in [false, true] {
            let ech = test_vectors::ech_outer_payload(grease);
            for sni_first in [false, true] {
                let hello = test_vectors::tls_client_hello(
                    "Public.Example.COM",
                    &[(0x2a2a, &[]), (0xfe0d, &ech)],
                    sni_first,
                );
                assert_eq!(
                    classify_tcp_prefix(&hello),
                    TcpPrefixClassification::Matched(SniffedTcpMetadata {
                        protocol: RouteProtocol::Tls,
                        domain: Some("public.example.com".into()),
                        analysis_domain: Some("Public.Example.COM".into()),
                        ech_present: true,
                        analysis_valid: true,
                    }),
                    "ECH/GREASE {grease}, SNI first {sni_first}",
                );
            }
        }
        for sni_first in [false, true] {
            let hello = test_vectors::tls_client_hello(
                "Public.Example.COM",
                &[(0x2a2a, &[]), (43, &[2, 3, 4])],
                sni_first,
            );
            let TcpPrefixClassification::Matched(metadata) = classify_tcp_prefix(&hello) else {
                panic!("non-ECH ClientHello must remain classified");
            };
            assert_eq!(metadata.domain.as_deref(), Some("public.example.com"));
            assert_eq!(
                metadata.analysis_domain.as_deref(),
                Some("Public.Example.COM")
            );
            assert!(!metadata.ech_present);
        }
    }

    #[test]
    fn malformed_extensions_do_not_report_unverified_observations() {
        let record = test_vectors::tls_client_hello("public.example.com", &[(0xfe0d, &[])], true);
        let body = &record[9..];
        for len in 0..body.len() {
            // Truncation at every byte, including inside vector lengths, must
            // terminate without an out-of-bounds read or a guessed domain.
            assert!(
                parse_client_hello_server_names(&body[..len])
                    .analysis_domain
                    .is_none()
            );
        }
        let mut malformed = body.to_vec();
        let length_offset = malformed.len() - 2;
        malformed[length_offset..].copy_from_slice(&u16::MAX.to_be_bytes());
        let names = parse_client_hello_server_names(&malformed);
        assert_eq!(names.domain.as_deref(), Some("public.example.com"));
        assert!(names.analysis_domain.is_none());
        assert!(!names.analysis_valid);

        let mut partial_header = body.to_vec();
        partial_header.pop();
        let extension_len = partial_header.len() - 43;
        partial_header[41..43].copy_from_slice(&(extension_len as u16).to_be_bytes());
        let names = parse_client_hello_server_names(&partial_header);
        assert_eq!(names.domain.as_deref(), Some("public.example.com"));
        assert!(names.analysis_domain.is_none());

        let normal_record = tls_client_hello("public.example.com");
        let mut trailing = normal_record[9..].to_vec();
        trailing.extend_from_slice(&[0xfe, 0x0d, 0, 0]);
        let names = parse_client_hello_server_names(&trailing);
        assert_eq!(names.domain.as_deref(), Some("public.example.com"));
        assert!(names.analysis_domain.is_none());
    }

    #[tokio::test]
    async fn fragmented_tcp_ech_keeps_routing_and_replays_the_complete_hello() {
        let ech = test_vectors::ech_outer_payload(false);
        let hello = test_vectors::tls_client_hello("public.example.com", &[(0xfe0d, &ech)], true);
        let split = hello.len() - ech.len() - 4;
        let mut stream = TestStream {
            bytes: hello[split..].to_vec(),
            offset: 0,
        };
        let mut replay = hello[..split].to_vec();
        let metadata = sniff_tcp(&mut stream, &mut replay).await.unwrap().unwrap();
        assert_eq!(metadata.domain.as_deref(), Some("public.example.com"));
        assert_eq!(
            metadata.analysis_domain.as_deref(),
            Some("public.example.com")
        );
        assert!(metadata.ech_present);
        assert_eq!(replay, hello);
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
