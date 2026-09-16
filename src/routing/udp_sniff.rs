//! Bounded passive UDP classification. Packets are never retained for replay or
//! delayed: callers continue forwarding the original datagram immediately.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::protocol::ClientHelloServerNames;

const MAX_BYTES: usize = 64 * 1024;
const MAX_CRYPTO: usize = 16 * 1024;
const MAX_FRAGMENTS: usize = 64;
const CRYPTO_COST: usize = 32 * 1024;

pub(crate) struct UdpSniffer {
    flow: Arc<dyn crate::dynamic::analysis::AnalysisFlow>,
    deadline: Instant,
    packets: usize,
    bytes: usize,
    crypto: Option<Crypto>,
    done: bool,
}

struct Crypto {
    dcid: Vec<u8>,
    data: Vec<u8>,
    seen: Vec<u64>,
    contiguous: usize,
    fragments: usize,
    largest_packet: u64,
    keys: rustls::quic::Keys,
    flow: Arc<dyn crate::dynamic::analysis::AnalysisFlow>,
}

impl Drop for Crypto {
    fn drop(&mut self) {
        self.flow.release_sniff(CRYPTO_COST);
    }
}

impl UdpSniffer {
    pub(crate) fn new(flow: Arc<dyn crate::dynamic::analysis::AnalysisFlow>) -> Self {
        Self {
            flow,
            deadline: Instant::now() + Duration::from_millis(300),
            packets: 0,
            bytes: 0,
            crypto: None,
            done: false,
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.done || Instant::now() >= self.deadline
    }

    pub(crate) fn observe(
        &mut self,
        datagram: &[u8],
    ) -> Option<(&'static str, Option<String>, bool)> {
        if self.expired() || self.packets >= 8 || datagram.len() > MAX_BYTES - self.bytes {
            self.crypto = None;
            self.done = true;
            return None;
        }
        self.packets += 1;
        self.bytes += datagram.len();
        if dns_question(datagram).is_some() {
            self.done = true;
            self.crypto = None;
            // A resolver association carries questions for many unrelated
            // domains. A question name is not this target's visited hostname.
            return Some(("dns", None, false));
        }
        match self.quic(datagram) {
            Ok(Some(names)) => {
                self.done = true;
                self.crypto = None;
                names
                    .analysis_valid
                    .then_some(("quic", names.analysis_domain, names.ech_present))
            }
            Ok(None) => None,
            Err(()) => {
                self.done = true;
                self.crypto = None;
                None
            }
        }
    }

    fn quic(&mut self, bytes: &[u8]) -> Result<Option<ClientHelloServerNames>, ()> {
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= self.deadline {
                return Err(());
            }
            let packet = &bytes[offset..];
            if packet.len() < 7 || packet[0] & 0xc0 != 0xc0 {
                return Err(());
            }
            let version = u32::from_be_bytes(packet[1..5].try_into().map_err(|_| ())?);
            let version = match version {
                1 if packet[0] & 0x30 == 0 => rustls::quic::Version::V1,
                0x6b3343cf if packet[0] & 0x30 == 0x10 => rustls::quic::Version::V2,
                _ => return Err(()),
            };
            let dcid_len = usize::from(packet[5]);
            if dcid_len > 20 {
                return Err(());
            }
            let dcid = packet.get(6..6 + dcid_len).ok_or(())?;
            let mut cursor = 6 + dcid_len;
            let scid_len = usize::from(*packet.get(cursor).ok_or(())?);
            if scid_len > 20 {
                return Err(());
            }
            cursor = cursor.checked_add(1 + scid_len).ok_or(())?;
            let token_len = varint(packet, &mut cursor)?;
            cursor = cursor
                .checked_add(usize::try_from(token_len).map_err(|_| ())?)
                .ok_or(())?;
            let payload_len = usize::try_from(varint(packet, &mut cursor)?).map_err(|_| ())?;
            let packet_end = cursor.checked_add(payload_len).ok_or(())?;
            if payload_len < 20 || packet_end > packet.len() {
                return Err(());
            }
            if self.crypto.is_none() {
                let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
                    .tls13()
                    .and_then(|suite| suite.quic_suite())
                    .ok_or(())?;
                if !self.flow.try_reserve_sniff(CRYPTO_COST) {
                    return Err(());
                }
                self.crypto = Some(Crypto {
                    dcid: dcid.to_vec(),
                    data: Vec::with_capacity(MAX_CRYPTO),
                    seen: vec![0; MAX_CRYPTO / 64],
                    contiguous: 0,
                    fragments: 0,
                    largest_packet: 0,
                    flow: self.flow.clone(),
                    keys: suite.keys(dcid, rustls::Side::Server, version),
                });
            }
            let crypto = self.crypto.as_mut().ok_or(())?;
            if crypto.dcid != dcid {
                return Err(());
            }
            let scratch_size = packet_end.checked_add(cursor + 4).ok_or(())?;
            if !self.flow.try_reserve_sniff(scratch_size) {
                return Err(());
            }
            let _scratch = Scratch {
                flow: self.flow.clone(),
                bytes: scratch_size,
            };
            let mut header = packet[..cursor + 4].to_vec();
            let sample = packet.get(cursor + 4..cursor + 20).ok_or(())?;
            let (first, rest) = header.split_at_mut(1);
            crypto
                .keys
                .remote
                .header
                .decrypt_in_place(sample, &mut first[0], &mut rest[cursor - 1..])
                .map_err(|_| ())?;
            let pn_len = usize::from((header[0] & 3) + 1);
            let truncated = header[cursor..cursor + pn_len]
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            let window = 1u64 << (pn_len * 8);
            let expected = crypto.largest_packet.saturating_add(1);
            let mut pn = (expected & !(window - 1)) | truncated;
            if pn + window / 2 <= expected {
                pn += window;
            } else if pn > expected + window / 2 && pn >= window {
                pn -= window;
            }
            header.truncate(cursor + pn_len);
            let mut payload = packet[cursor + pn_len..packet_end].to_vec();
            let payload = crypto
                .keys
                .remote
                .packet
                .decrypt_in_place(pn, &header, &mut payload)
                .map_err(|_| ())?;
            crypto.largest_packet = crypto.largest_packet.max(pn);
            if let Some(domain) = crypto.frames(payload, self.deadline)? {
                return Ok(Some(domain));
            }
            offset = offset.checked_add(packet_end).ok_or(())?;
        }
        Ok(None)
    }
}

struct Scratch {
    flow: Arc<dyn crate::dynamic::analysis::AnalysisFlow>,
    bytes: usize,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        self.flow.release_sniff(self.bytes);
    }
}

impl Crypto {
    fn frames(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<Option<ClientHelloServerNames>, ()> {
        let mut cursor = 0;
        while cursor < payload.len() {
            if Instant::now() >= deadline {
                return Err(());
            }
            match varint(payload, &mut cursor)? {
                0 | 1 => {} // PADDING / PING
                kind @ (2 | 3) => {
                    varint(payload, &mut cursor)?;
                    varint(payload, &mut cursor)?;
                    let ranges = varint(payload, &mut cursor)?;
                    if ranges > MAX_FRAGMENTS as u64 {
                        return Err(());
                    }
                    varint(payload, &mut cursor)?;
                    for _ in 0..ranges {
                        varint(payload, &mut cursor)?;
                        varint(payload, &mut cursor)?;
                    }
                    if kind == 3 {
                        for _ in 0..3 {
                            varint(payload, &mut cursor)?;
                        }
                    }
                }
                6 => {
                    let offset = usize::try_from(varint(payload, &mut cursor)?).map_err(|_| ())?;
                    let len = usize::try_from(varint(payload, &mut cursor)?).map_err(|_| ())?;
                    let end = offset
                        .checked_add(len)
                        .filter(|end| *end <= MAX_CRYPTO)
                        .ok_or(())?;
                    let frame_end = cursor.checked_add(len).ok_or(())?;
                    let fragment = payload.get(cursor..frame_end).ok_or(())?;
                    cursor = frame_end;
                    self.fragments += 1;
                    if self.fragments > MAX_FRAGMENTS || len == 0 {
                        return Err(());
                    }
                    self.data.resize(self.data.len().max(end), 0);
                    let mut progress = false;
                    for (i, byte) in fragment.iter().enumerate() {
                        let pos = offset + i;
                        let mask = 1u64 << (pos % 64);
                        if self.seen[pos / 64] & mask != 0 {
                            if self.data[pos] != *byte {
                                return Err(());
                            }
                        } else {
                            self.seen[pos / 64] |= mask;
                            self.data[pos] = *byte;
                            progress = true;
                        }
                    }
                    // Duplicate frames cannot keep extending the sniff lifetime.
                    if !progress && self.fragments == MAX_FRAGMENTS {
                        return Err(());
                    }
                    while self.contiguous < self.data.len()
                        && self.seen[self.contiguous / 64] & (1 << (self.contiguous % 64)) != 0
                    {
                        self.contiguous += 1;
                    }
                    if self.contiguous >= 4 {
                        if self.data[0] != 1 {
                            return Err(());
                        }
                        let len = ((self.data[1] as usize) << 16)
                            | ((self.data[2] as usize) << 8)
                            | self.data[3] as usize;
                        if len > MAX_CRYPTO - 4 {
                            return Err(());
                        }
                        if self.contiguous >= len + 4 {
                            return Ok(Some(super::protocol::parse_client_hello_server_names(
                                &self.data[4..len + 4],
                            )));
                        }
                    }
                }
                _ => return Err(()),
            }
        }
        Ok(None)
    }
}

fn varint(bytes: &[u8], offset: &mut usize) -> Result<u64, ()> {
    let first = *bytes.get(*offset).ok_or(())?;
    let len = 1usize << (first >> 6);
    let end = offset.checked_add(len).ok_or(())?;
    let encoded = bytes.get(*offset..end).ok_or(())?;
    let value = encoded[1..]
        .iter()
        .fold(u64::from(first & 63), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    *offset = end;
    Ok(value)
}

fn dns_question(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 17 || bytes[2] & 0xf8 != 0 || bytes[4..6] != [0, 1] {
        return None;
    }
    let mut offset = 12;
    let mut domain = String::new();
    loop {
        let len = usize::from(*bytes.get(offset)?);
        offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = bytes.get(offset..offset.checked_add(len)?)?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(std::str::from_utf8(label).ok()?);
        if domain.len() > 253 {
            return None;
        }
        offset += len;
    }
    bytes.get(offset..offset + 4)?;
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::analysis::{AnalysisFlow, AnalysisTarget};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Flow {
        bytes: AtomicUsize,
    }
    impl AnalysisFlow for Flow {
        fn begin(&self) -> u64 {
            1
        }
        fn finish(&self, _: u64, _: u64, _: u64, _: Option<&AnalysisTarget>) {}
        fn cancel(&self, _: u64) {}
        fn close(&self) {}
        fn try_reserve_sniff(&self, bytes: usize) -> bool {
            self.bytes.fetch_add(bytes, Ordering::Relaxed);
            true
        }
        fn release_sniff(&self, bytes: usize) {
            self.bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    fn encode_varint(value: usize, bytes: &mut Vec<u8>) {
        assert!(value < 16384);
        if value < 64 {
            bytes.push(value as u8);
        } else {
            bytes.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        }
    }

    fn initial(dcid: &[u8], packet_number: u32, offset: usize, fragment: &[u8]) -> Vec<u8> {
        let mut payload = vec![6];
        encode_varint(offset, &mut payload);
        encode_varint(fragment.len(), &mut payload);
        payload.extend_from_slice(fragment);
        payload.resize(payload.len().max(32), 0);
        let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let keys = suite.keys(dcid, rustls::Side::Client, rustls::quic::Version::V1);
        let mut header = vec![0xc3, 0, 0, 0, 1, dcid.len() as u8];
        header.extend_from_slice(dcid);
        header.extend_from_slice(&[0, 0]); // SCID, token
        encode_varint(4 + payload.len() + 16, &mut header);
        let pn_offset = header.len();
        header.extend_from_slice(&packet_number.to_be_bytes());
        let tag = keys
            .local
            .packet
            .encrypt_in_place(u64::from(packet_number), &header, &mut payload)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        let (first, rest) = header.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(&payload[..16], &mut first[0], &mut rest[pn_offset - 1..])
            .unwrap();
        header.extend_from_slice(&payload);
        header
    }

    fn hello(name: &str) -> Vec<u8> {
        super::super::protocol::test_vectors::tls_client_hello(name, &[], true)[5..].to_vec()
    }

    #[test]
    fn quic_initial_fragments_reassemble_without_mutating_datagrams() {
        let flow = Arc::new(Flow::default());
        let mut sniff = UdpSniffer::new(flow.clone());
        let hello = hello("www.youtube.com");
        let second = initial(b"samecid1", 1, 32, &hello[32..]);
        let original = second.clone();
        assert!(sniff.observe(&second).is_none());
        assert_eq!(second, original);
        assert!(flow.bytes.load(Ordering::Relaxed) >= CRYPTO_COST);
        assert_eq!(
            sniff.observe(&initial(b"samecid1", 2, 0, &hello[..32])),
            Some(("quic", Some("www.youtube.com".into()), false))
        );
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn quic_ech_and_grease_preserve_raw_outer_name_for_either_extension_order() {
        use super::super::protocol::test_vectors;
        for grease in [false, true] {
            let ech = test_vectors::ech_outer_payload(grease);
            for sni_first in [false, true] {
                let record = test_vectors::tls_client_hello(
                    "Public.Example.COM.",
                    &[(0xfe0d, &ech)],
                    sni_first,
                );
                let handshake = &record[5..];
                let flow = Arc::new(Flow::default());
                let mut sniff = UdpSniffer::new(flow.clone());
                let split = handshake.len() - 16;
                let first = initial(b"echcid01", 0, 0, &handshake[..split]);
                let final_packet = initial(b"echcid01", 1, split, &handshake[split..]);
                let original = final_packet.clone();
                assert!(sniff.observe(&first).is_none());
                assert_eq!(
                    sniff.observe(&final_packet),
                    Some(("quic", Some("Public.Example.COM.".into()), true)),
                );
                assert_eq!(final_packet, original);
                assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
                assert!(sniff.expired());
            }
        }
    }

    #[test]
    fn quic_malformed_extension_after_sni_does_not_report_the_cover_name() {
        let mut handshake = super::super::protocol::test_vectors::tls_client_hello(
            "public.example.com",
            &[(0xfe0d, &[])],
            true,
        )[5..]
            .to_vec();
        let length_offset = handshake.len() - 2;
        handshake[length_offset..].copy_from_slice(&u16::MAX.to_be_bytes());
        let flow = Arc::new(Flow::default());
        let mut sniff = UdpSniffer::new(flow.clone());
        assert_eq!(sniff.observe(&initial(b"echcid01", 0, 0, &handshake)), None,);
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
        assert!(sniff.expired());
    }

    #[test]
    fn quic_invalid_utf8_sni_is_terminal_without_a_missing_domain_report() {
        let mut handshake = hello("example.com");
        *handshake.last_mut().unwrap() = 0xff;
        let flow = Arc::new(Flow::default());
        let mut sniff = UdpSniffer::new(flow.clone());
        assert!(
            sniff
                .observe(&initial(b"badutf01", 0, 0, &handshake))
                .is_none()
        );
        assert!(sniff.expired());
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn quic_different_connection_ids_never_share_fragments() {
        let flow = Arc::new(Flow::default());
        let mut sniff = UdpSniffer::new(flow.clone());
        let hello = hello("example.com");
        assert!(
            sniff
                .observe(&initial(b"targeta1", 0, 0, &hello[..32]))
                .is_none()
        );
        assert!(
            sniff
                .observe(&initial(b"targetb2", 1, 32, &hello[32..]))
                .is_none()
        );
        assert!(sniff.expired());
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_input_and_expired_budget_release_crypto() {
        let flow = Arc::new(Flow::default());
        let mut sniff = UdpSniffer::new(flow.clone());
        let packet = initial(b"targeta1", 0, MAX_CRYPTO - 1, &[1, 2]);
        assert!(sniff.observe(&packet).is_none());
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
        let mut sniff = UdpSniffer::new(flow.clone());
        assert!(
            sniff
                .observe(&initial(b"targeta1", 0, 0, &[1, 0]))
                .is_none()
        );
        sniff.deadline = Instant::now();
        assert!(sniff.observe(&packet).is_none());
        assert_eq!(flow.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dns_question_is_bounded_and_compression_is_not_followed() {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend_from_slice(b"\x03www\x07youtube\x03com\x00\x00\x01\x00\x01");
        assert_eq!(dns_question(&packet).as_deref(), Some("www.youtube.com"));
        let mut sniff = UdpSniffer::new(Arc::new(Flow::default()));
        assert_eq!(sniff.observe(&packet), Some(("dns", None, false)));
        packet[12] = 0xc0;
        assert_eq!(dns_question(&packet), None);
    }
}
