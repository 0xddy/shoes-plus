//! Client-side Shadowsocks native UDP (SIP003 and Shadowsocks 2022).
//!
//! Each UDP datagram is an independent Shadowsocks packet. This is deliberately
//! separate from UoT: the underlying stream here is a UDP socket connected to the
//! Shadowsocks server, not a TCP byte stream with length-prefixed messages.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{
    AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, RngExt};
use tokio::io::ReadBuf;

use super::aead_util::TAG_LEN;
use super::eih::psk_hash;
use super::{ShadowsocksCipher, ShadowsocksKey};
use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};
use crate::replay_filter::ReplayFilter;

const MAX_UDP_PACKET_SIZE: usize = 65_507;
const RECEIVE_BUFFER_SIZE: usize = 65_535;
const AEAD_NONCE_SIZE: usize = 12;
const XCHACHA_NONCE_SIZE: usize = 24;
const UDP_2022_HEADER_SIZE: usize = 16;
const MAX_PADDING_LENGTH: usize = 900;
const TIMESTAMP_TOLERANCE: u64 = 30;
const SERVER_SESSION_CHANGE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub enum ShadowsocksUdpCodecConfig {
    Legacy {
        cipher: ShadowsocksCipher,
        key: Arc<Box<dyn ShadowsocksKey>>,
    },
    Aead2022 {
        cipher: ShadowsocksCipher,
        /// Outermost identity PSK first, client's own PSK last.
        psk_chain: Box<[Box<[u8]>]>,
    },
}

impl fmt::Debug for ShadowsocksUdpCodecConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy { cipher, .. } => formatter
                .debug_struct("Legacy")
                .field("cipher", &cipher.name())
                .finish(),
            Self::Aead2022 {
                cipher, psk_chain, ..
            } => formatter
                .debug_struct("Aead2022")
                .field("cipher", &cipher.name())
                .field("identity_chain_len", &psk_chain.len())
                .finish(),
        }
    }
}

impl ShadowsocksUdpCodecConfig {
    pub fn legacy(cipher: ShadowsocksCipher, key: Arc<Box<dyn ShadowsocksKey>>) -> Self {
        Self::Legacy { cipher, key }
    }

    pub fn aead2022(
        cipher: ShadowsocksCipher,
        psk_chain: Box<[Box<[u8]>]>,
    ) -> std::io::Result<Self> {
        if psk_chain.is_empty() {
            return Err(invalid_input("Shadowsocks 2022 UDP requires a client PSK"));
        }
        for key in &psk_chain {
            if key.len() != cipher.key_len() {
                return Err(invalid_input(format!(
                    "Shadowsocks 2022 cipher {} requires {} byte PSKs, got {}",
                    cipher.name(),
                    cipher.key_len(),
                    key.len()
                )));
            }
        }
        if is_2022_chacha(&cipher) && psk_chain.len() != 1 {
            return Err(invalid_input(
                "2022-blake3-chacha20-poly1305 does not support identity PSKs",
            ));
        }
        Ok(Self::Aead2022 { cipher, psk_chain })
    }

    pub fn wrap(
        &self,
        inner: Box<dyn AsyncMessageStream>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // Fail at setup rather than on the first application datagram.
        encode_location(&target)?;
        let codec = match self {
            Self::Legacy { cipher, key } => ShadowsocksUdpCodec::Legacy {
                cipher: *cipher,
                key: key.clone(),
                replay_filter: ReplayFilter::new(Duration::from_secs(60)),
            },
            Self::Aead2022 { cipher, psk_chain } => ShadowsocksUdpCodec::Aead2022(Box::new(
                Shadowsocks2022UdpSession::new(*cipher, psk_chain.clone())?,
            )),
        };
        Ok(Box::new(ShadowsocksUdpMessageStream {
            inner,
            target,
            codec,
            pending_write: None,
            receive_buffer: vec![0; RECEIVE_BUFFER_SIZE].into_boxed_slice(),
        }))
    }
}

enum ShadowsocksUdpCodec {
    Legacy {
        cipher: ShadowsocksCipher,
        key: Arc<Box<dyn ShadowsocksKey>>,
        replay_filter: ReplayFilter,
    },
    Aead2022(Box<Shadowsocks2022UdpSession>),
}

impl ShadowsocksUdpCodec {
    fn encode(&mut self, target: &NetLocation, payload: &[u8]) -> std::io::Result<Box<[u8]>> {
        match self {
            Self::Legacy { cipher, key, .. } => encode_legacy_packet(*cipher, key, target, payload),
            Self::Aead2022(session) => session.encode_packet(target, payload),
        }
    }

    fn decode(&mut self, packet: &[u8]) -> std::io::Result<Box<[u8]>> {
        match self {
            Self::Legacy {
                cipher,
                key,
                replay_filter,
            } => decode_legacy_packet(*cipher, key, replay_filter, packet),
            Self::Aead2022(session) => session.decode_packet(packet),
        }
    }
}

struct ShadowsocksUdpMessageStream {
    inner: Box<dyn AsyncMessageStream>,
    target: NetLocation,
    codec: ShadowsocksUdpCodec,
    /// A datagram must be stable across `Poll::Pending`; in particular a new
    /// random salt/nonce and packet id must not be generated on every poll.
    pending_write: Option<Box<[u8]>>,
    receive_buffer: Box<[u8]>,
}

impl fmt::Debug for ShadowsocksUdpMessageStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShadowsocksUdpMessageStream")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl AsyncReadMessage for ShadowsocksUdpMessageStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Invalid authenticated packets are association-local noise, not EOF and
        // not a reason to kill every later DNS/QUIC response on this UDP mapping.
        // Bound the loop so a flood cannot monopolize one executor poll.
        for _ in 0..8 {
            let mut encrypted = ReadBuf::new(&mut this.receive_buffer);
            match Pin::new(&mut this.inner).poll_read_message(cx, &mut encrypted) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }

            let packet = encrypted.filled().to_vec();
            match this.codec.decode(&packet) {
                Ok(plaintext) => {
                    if plaintext.len() > output.remaining() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Shadowsocks UDP payload is {} bytes but caller buffer has {} bytes",
                                plaintext.len(),
                                output.remaining()
                            ),
                        )));
                    }
                    output.put_slice(&plaintext);
                    return Poll::Ready(Ok(()));
                }
                Err(error) => {
                    log::debug!("dropping invalid Shadowsocks UDP packet: {error}");
                }
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWriteMessage for ShadowsocksUdpMessageStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_write.is_none() {
            match this.codec.encode(&this.target, payload) {
                Ok(packet) => this.pending_write = Some(packet),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }

        let result = Pin::new(&mut this.inner)
            .poll_write_message(cx, this.pending_write.as_deref().unwrap());
        if result.is_ready() {
            this.pending_write = None;
        }
        result
    }
}

impl AsyncFlushMessage for ShadowsocksUdpMessageStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for ShadowsocksUdpMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown_message(cx)
    }
}

impl AsyncPing for ShadowsocksUdpMessageStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for ShadowsocksUdpMessageStream {}

fn encode_legacy_packet(
    cipher: ShadowsocksCipher,
    key: &Arc<Box<dyn ShadowsocksKey>>,
    target: &NetLocation,
    payload: &[u8],
) -> std::io::Result<Box<[u8]>> {
    let salt_len = cipher.salt_len();
    let mut salt = vec![0; salt_len];
    rand::rng().fill_bytes(&mut salt);

    let mut plaintext = encode_location(target)?;
    plaintext.extend_from_slice(payload);
    let session_key = key.create_session_key(&salt);
    seal_aead(cipher, &session_key, &[0; AEAD_NONCE_SIZE], &mut plaintext)?;

    let packet_len = salt_len
        .checked_add(plaintext.len())
        .ok_or_else(|| invalid_input("Shadowsocks UDP packet length overflow"))?;
    ensure_udp_packet_size(packet_len)?;
    let mut packet = Vec::with_capacity(packet_len);
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&plaintext);
    Ok(packet.into_boxed_slice())
}

fn decode_legacy_packet(
    cipher: ShadowsocksCipher,
    key: &Arc<Box<dyn ShadowsocksKey>>,
    replay_filter: &mut ReplayFilter,
    packet: &[u8],
) -> std::io::Result<Box<[u8]>> {
    let salt_len = cipher.salt_len();
    if packet.len() < salt_len + TAG_LEN + 1 {
        return Err(invalid_data("Shadowsocks UDP packet is too short"));
    }
    let (salt, ciphertext) = packet.split_at(salt_len);
    let session_key = key.create_session_key(salt);
    let mut plaintext = ciphertext.to_vec();
    open_aead(cipher, &session_key, &[0; AEAD_NONCE_SIZE], &mut plaintext)?;
    if !replay_filter.check_and_insert(salt) {
        return Err(invalid_data("replayed Shadowsocks UDP salt"));
    }
    let (_, payload) = decode_location(&plaintext)?;
    Ok(payload.to_vec().into_boxed_slice())
}

struct Shadowsocks2022UdpSession {
    cipher: ShadowsocksCipher,
    psk_chain: Box<[Box<[u8]>]>,
    client_session_id: u64,
    next_packet_id: u64,
    client_aes_cipher: Option<LessSafeKey>,
    remote_current: Option<RemoteSession>,
    remote_last: Option<RemoteSession>,
    last_remote_seen: Option<Instant>,
}

impl fmt::Debug for Shadowsocks2022UdpSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Shadowsocks2022UdpSession")
            .field("cipher", &self.cipher.name())
            .field("identity_chain_len", &self.psk_chain.len())
            .finish_non_exhaustive()
    }
}

struct RemoteSession {
    id: u64,
    cipher: Option<LessSafeKey>,
    window: SlidingWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteSlot {
    Current,
    Last,
    New,
}

impl Shadowsocks2022UdpSession {
    fn new(cipher: ShadowsocksCipher, psk_chain: Box<[Box<[u8]>]>) -> std::io::Result<Self> {
        // Keep this validation here as well as on the public config constructor:
        // handlers are a security boundary and should never build a malformed key.
        ShadowsocksUdpCodecConfig::aead2022(cipher, psk_chain.clone())?;
        let client_session_id = rand::rng().random::<u64>();
        let client_aes_cipher = if is_2022_chacha(&cipher) {
            None
        } else {
            let own_psk = psk_chain.last().unwrap();
            Some(new_2022_session_cipher(
                cipher,
                own_psk,
                &client_session_id.to_be_bytes(),
            )?)
        };

        Ok(Self {
            cipher,
            psk_chain,
            client_session_id,
            next_packet_id: 0,
            client_aes_cipher,
            remote_current: None,
            remote_last: None,
            last_remote_seen: None,
        })
    }

    fn encode_packet(
        &mut self,
        target: &NetLocation,
        payload: &[u8],
    ) -> std::io::Result<Box<[u8]>> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let padding_len = dns_padding_len(target, payload.len());
        let mut address = encode_location(target)?;
        let mut body =
            Vec::with_capacity(1 + 8 + 2 + padding_len + address.len() + payload.len() + TAG_LEN);
        body.push(0); // client packet header
        body.extend_from_slice(&unix_timestamp()?.to_be_bytes());
        body.extend_from_slice(&(padding_len as u16).to_be_bytes());
        let padding_start = body.len();
        body.resize(padding_start + padding_len, 0);
        rand::rng().fill_bytes(&mut body[padding_start..]);
        body.append(&mut address);
        body.extend_from_slice(payload);

        let mut header = [0u8; UDP_2022_HEADER_SIZE];
        header[..8].copy_from_slice(&self.client_session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());

        let packet = if is_2022_chacha(&self.cipher) {
            let mut plaintext = Vec::with_capacity(header.len() + body.len() + TAG_LEN);
            plaintext.extend_from_slice(&header);
            plaintext.extend_from_slice(&body);
            let mut nonce = [0u8; XCHACHA_NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce);
            xchacha_seal(self.psk_chain.last().unwrap(), &nonce, &mut plaintext)?;
            let mut packet = Vec::with_capacity(nonce.len() + plaintext.len());
            packet.extend_from_slice(&nonce);
            packet.extend_from_slice(&plaintext);
            packet
        } else {
            let mut encrypted_body = body;
            seal_with_key(
                self.client_aes_cipher
                    .as_ref()
                    .expect("AES mode has a session cipher"),
                nonce_from_2022_header(&header)?,
                &mut encrypted_body,
            )?;

            let identity_count = self.psk_chain.len().saturating_sub(1);
            let mut packet =
                Vec::with_capacity(header.len() + identity_count * 16 + encrypted_body.len());
            packet.extend_from_slice(&header);
            for pair in self.psk_chain.windows(2) {
                let mut identity = psk_hash(&pair[1]);
                for (byte, header_byte) in identity.iter_mut().zip(header) {
                    *byte ^= header_byte;
                }
                aes_ecb_encrypt(&pair[0], &mut identity)?;
                packet.extend_from_slice(&identity);
            }
            packet.extend_from_slice(&encrypted_body);
            let encrypted_header: &mut [u8; 16] = (&mut packet[..16]).try_into().unwrap();
            aes_ecb_encrypt(&self.psk_chain[0], encrypted_header)?;
            packet
        };

        ensure_udp_packet_size(packet.len())?;
        Ok(packet.into_boxed_slice())
    }

    fn decode_packet(&mut self, packet: &[u8]) -> std::io::Result<Box<[u8]>> {
        if is_2022_chacha(&self.cipher) {
            self.decode_chacha_packet(packet)
        } else {
            self.decode_aes_packet(packet)
        }
    }

    fn decode_chacha_packet(&mut self, packet: &[u8]) -> std::io::Result<Box<[u8]>> {
        if packet.len() < XCHACHA_NONCE_SIZE + UDP_2022_HEADER_SIZE + TAG_LEN {
            return Err(invalid_data("Shadowsocks 2022 UDP packet is too short"));
        }
        let (nonce, ciphertext) = packet.split_at(XCHACHA_NONCE_SIZE);
        let mut plaintext = ciphertext.to_vec();
        xchacha_open(self.psk_chain.last().unwrap(), nonce, &mut plaintext)?;
        self.finish_decoded_packet(plaintext, None)
    }

    fn decode_aes_packet(&mut self, packet: &[u8]) -> std::io::Result<Box<[u8]>> {
        if packet.len() < UDP_2022_HEADER_SIZE + TAG_LEN {
            return Err(invalid_data("Shadowsocks 2022 UDP packet is too short"));
        }
        let mut header: [u8; UDP_2022_HEADER_SIZE] = packet[..16].try_into().unwrap();
        aes_ecb_decrypt(self.psk_chain.last().unwrap(), &mut header)?;
        let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
        let slot = self.remote_slot(session_id, packet_id)?;

        let candidate_cipher = if slot == RemoteSlot::New {
            Some(new_2022_session_cipher(
                self.cipher,
                self.psk_chain.last().unwrap(),
                &header[..8],
            )?)
        } else {
            None
        };
        let cipher = match slot {
            RemoteSlot::Current => self
                .remote_current
                .as_ref()
                .and_then(|session| session.cipher.as_ref())
                .expect("known AES session has a cipher"),
            RemoteSlot::Last => self
                .remote_last
                .as_ref()
                .and_then(|session| session.cipher.as_ref())
                .expect("known AES session has a cipher"),
            RemoteSlot::New => candidate_cipher.as_ref().unwrap(),
        };

        let mut body = packet[16..].to_vec();
        open_with_key(cipher, nonce_from_2022_header(&header)?, &mut body)?;
        let mut plaintext = Vec::with_capacity(header.len() + body.len());
        plaintext.extend_from_slice(&header);
        plaintext.extend_from_slice(&body);
        self.finish_decoded_packet(plaintext, candidate_cipher)
    }

    fn finish_decoded_packet(
        &mut self,
        plaintext: Vec<u8>,
        candidate_cipher: Option<LessSafeKey>,
    ) -> std::io::Result<Box<[u8]>> {
        if plaintext.len() < UDP_2022_HEADER_SIZE {
            return Err(invalid_data("Shadowsocks 2022 UDP header is truncated"));
        }
        let session_id = u64::from_be_bytes(plaintext[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(plaintext[8..16].try_into().unwrap());
        let slot = self.remote_slot(session_id, packet_id)?;

        if slot == RemoteSlot::New
            && self.remote_current.is_some()
            && self
                .last_remote_seen
                .is_some_and(|seen| seen.elapsed() < SERVER_SESSION_CHANGE_WINDOW)
        {
            return Err(invalid_data(
                "Shadowsocks 2022 server session changed more than once in 60 seconds",
            ));
        }

        let mut cursor = &plaintext[16..];
        let header_type = take_u8(&mut cursor)?;
        if header_type != 1 {
            return Err(invalid_data(format!(
                "invalid Shadowsocks 2022 UDP response header type {header_type}"
            )));
        }
        let timestamp = take_u64(&mut cursor)?;
        let now = unix_timestamp()?;
        if timestamp.abs_diff(now) > TIMESTAMP_TOLERANCE {
            return Err(invalid_data(format!(
                "Shadowsocks 2022 UDP timestamp differs by more than {TIMESTAMP_TOLERANCE} seconds"
            )));
        }
        let client_session_id = take_u64(&mut cursor)?;
        if client_session_id != self.client_session_id {
            return Err(invalid_data("bad Shadowsocks 2022 client session id"));
        }
        let padding_len = take_u16(&mut cursor)? as usize;
        take(&mut cursor, padding_len)?;
        let (_, payload) = decode_location(cursor)?;
        let payload = payload.to_vec().into_boxed_slice();

        self.commit_remote_packet(slot, session_id, packet_id, candidate_cipher);
        Ok(payload)
    }

    fn remote_slot(&self, session_id: u64, packet_id: u64) -> std::io::Result<RemoteSlot> {
        if self
            .remote_current
            .as_ref()
            .is_some_and(|session| session.id == session_id)
        {
            if !self
                .remote_current
                .as_ref()
                .unwrap()
                .window
                .check(packet_id)
            {
                return Err(invalid_data("replayed Shadowsocks 2022 UDP packet id"));
            }
            Ok(RemoteSlot::Current)
        } else if self
            .remote_last
            .as_ref()
            .is_some_and(|session| session.id == session_id)
        {
            if !self.remote_last.as_ref().unwrap().window.check(packet_id) {
                return Err(invalid_data("replayed Shadowsocks 2022 UDP packet id"));
            }
            Ok(RemoteSlot::Last)
        } else {
            Ok(RemoteSlot::New)
        }
    }

    fn commit_remote_packet(
        &mut self,
        slot: RemoteSlot,
        session_id: u64,
        packet_id: u64,
        candidate_cipher: Option<LessSafeKey>,
    ) {
        match slot {
            RemoteSlot::Current => self.remote_current.as_mut().unwrap().window.add(packet_id),
            RemoteSlot::Last => {
                self.remote_last.as_mut().unwrap().window.add(packet_id);
                self.last_remote_seen = Some(Instant::now());
            }
            RemoteSlot::New => {
                let mut session = RemoteSession {
                    id: session_id,
                    cipher: candidate_cipher,
                    window: SlidingWindow::default(),
                };
                session.window.add(packet_id);
                if let Some(current) = self.remote_current.take() {
                    self.remote_last = Some(current);
                    self.last_remote_seen = Some(Instant::now());
                }
                self.remote_current = Some(session);
            }
        }
    }
}

struct SlidingWindow {
    last: u64,
    ring: [u64; 128],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0; 128],
        }
    }
}

impl SlidingWindow {
    const BLOCK_BIT_LOG: u32 = 6;
    const BLOCK_BITS: u64 = 1 << Self::BLOCK_BIT_LOG;
    const RING_BLOCKS: u64 = 128;
    const BLOCK_MASK: u64 = Self::RING_BLOCKS - 1;
    const BIT_MASK: u64 = Self::BLOCK_BITS - 1;
    const SIZE: u64 = (Self::RING_BLOCKS - 1) * Self::BLOCK_BITS;

    fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > Self::SIZE {
            return false;
        }
        let block_index = (counter >> Self::BLOCK_BIT_LOG) & Self::BLOCK_MASK;
        let bit_index = counter & Self::BIT_MASK;
        self.ring[block_index as usize] >> bit_index & 1 == 0
    }

    fn add(&mut self, counter: u64) {
        let mut block_index = counter >> Self::BLOCK_BIT_LOG;
        if counter > self.last {
            let mut last_block_index = self.last >> Self::BLOCK_BIT_LOG;
            let diff = (block_index - last_block_index).min(Self::RING_BLOCKS);
            for _ in 0..diff {
                last_block_index = (last_block_index + 1) & Self::BLOCK_MASK;
                self.ring[last_block_index as usize] = 0;
            }
            self.last = counter;
        }
        block_index &= Self::BLOCK_MASK;
        let bit_index = counter & Self::BIT_MASK;
        self.ring[block_index as usize] |= 1 << bit_index;
    }
}

fn dns_padding_len(target: &NetLocation, payload_len: usize) -> usize {
    if target.port() != 53 || payload_len >= MAX_PADDING_LENGTH {
        return 0;
    }
    rand::rng().random_range(1..=MAX_PADDING_LENGTH - payload_len)
}

fn new_2022_session_cipher(
    cipher: ShadowsocksCipher,
    psk: &[u8],
    session_id: &[u8],
) -> std::io::Result<LessSafeKey> {
    let mut material = Vec::with_capacity(psk.len() + session_id.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(session_id);
    let mut derived = vec![0; cipher.key_len()];
    let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hasher.update(&material);
    hasher.finalize_xof().fill(&mut derived);
    new_aead_key(cipher, &derived)
}

fn seal_aead(
    cipher: ShadowsocksCipher,
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    plaintext: &mut Vec<u8>,
) -> std::io::Result<()> {
    let key = new_aead_key(cipher, key)?;
    seal_with_key(&key, Nonce::assume_unique_for_key(*nonce), plaintext)
}

fn open_aead(
    cipher: ShadowsocksCipher,
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    ciphertext: &mut Vec<u8>,
) -> std::io::Result<()> {
    let key = new_aead_key(cipher, key)?;
    open_with_key(&key, Nonce::assume_unique_for_key(*nonce), ciphertext)
}

fn new_aead_key(cipher: ShadowsocksCipher, key: &[u8]) -> std::io::Result<LessSafeKey> {
    let key = UnboundKey::new(cipher.algorithm(), key)
        .map_err(|_| invalid_input("invalid Shadowsocks AEAD key"))?;
    Ok(LessSafeKey::new(key))
}

fn seal_with_key(key: &LessSafeKey, nonce: Nonce, plaintext: &mut Vec<u8>) -> std::io::Result<()> {
    key.seal_in_place_append_tag(nonce, Aad::empty(), plaintext)
        .map_err(|_| invalid_data("failed to encrypt Shadowsocks UDP packet"))
}

fn open_with_key(key: &LessSafeKey, nonce: Nonce, ciphertext: &mut Vec<u8>) -> std::io::Result<()> {
    let plaintext_len = key
        .open_in_place(nonce, Aad::empty(), ciphertext)
        .map_err(|_| invalid_data("failed to authenticate Shadowsocks UDP packet"))?
        .len();
    ciphertext.truncate(plaintext_len);
    Ok(())
}

fn nonce_from_2022_header(header: &[u8; 16]) -> std::io::Result<Nonce> {
    Nonce::try_assume_unique_for_key(&header[4..16])
        .map_err(|_| invalid_data("invalid Shadowsocks 2022 UDP nonce"))
}

fn xchacha_seal(key: &[u8], nonce: &[u8], plaintext: &mut Vec<u8>) -> std::io::Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_input("invalid Shadowsocks 2022 ChaCha20 key"))?;
    cipher
        .encrypt_in_place(XNonce::from_slice(nonce), b"", plaintext)
        .map_err(|_| invalid_data("failed to encrypt Shadowsocks 2022 UDP packet"))
}

fn xchacha_open(key: &[u8], nonce: &[u8], ciphertext: &mut Vec<u8>) -> std::io::Result<()> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_input("invalid Shadowsocks 2022 ChaCha20 key"))?;
    cipher
        .decrypt_in_place(XNonce::from_slice(nonce), b"", ciphertext)
        .map_err(|_| invalid_data("failed to authenticate Shadowsocks 2022 UDP packet"))
}

fn aes_ecb_encrypt(key: &[u8], block: &mut [u8; 16]) -> std::io::Result<()> {
    let key = EncryptingKey::ecb(unbound_aes_key(key)?)
        .map_err(|_| invalid_input("failed to initialize Shadowsocks UDP AES-ECB"))?;
    key.less_safe_encrypt(block, EncryptionContext::None)
        .map_err(|_| invalid_data("failed to encrypt Shadowsocks UDP AES header"))?;
    Ok(())
}

fn aes_ecb_decrypt(key: &[u8], block: &mut [u8; 16]) -> std::io::Result<()> {
    let key = DecryptingKey::ecb(unbound_aes_key(key)?)
        .map_err(|_| invalid_input("failed to initialize Shadowsocks UDP AES-ECB"))?;
    key.decrypt(block, DecryptionContext::None)
        .map_err(|_| invalid_data("failed to decrypt Shadowsocks UDP AES header"))?;
    Ok(())
}

fn unbound_aes_key(key: &[u8]) -> std::io::Result<UnboundCipherKey> {
    let algorithm = match key.len() {
        16 => &AES_128,
        32 => &AES_256,
        length => {
            return Err(invalid_input(format!(
                "Shadowsocks UDP AES key must be 16 or 32 bytes, got {length}"
            )));
        }
    };
    UnboundCipherKey::new(algorithm, key)
        .map_err(|_| invalid_input("invalid Shadowsocks UDP AES key"))
}

fn is_2022_chacha(cipher: &ShadowsocksCipher) -> bool {
    cipher.name() == "chacha20-ietf-poly1305"
}

fn encode_location(location: &NetLocation) -> std::io::Result<Vec<u8>> {
    let (address, port) = location.components();
    let mut output = Vec::with_capacity(19);
    match address {
        Address::Ipv4(address) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Address::Ipv6(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        Address::Hostname(hostname) => {
            let length = hostname.len();
            if length == 0 || length > u8::MAX as usize {
                return Err(invalid_input(format!(
                    "Shadowsocks UDP hostname length must be 1..=255 bytes, got {length}"
                )));
            }
            output.push(3);
            output.push(length as u8);
            output.extend_from_slice(hostname.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(output)
}

fn decode_location(input: &[u8]) -> std::io::Result<(NetLocation, &[u8])> {
    let mut cursor = input;
    let address_type = take_u8(&mut cursor)?;
    let address = match address_type {
        1 => {
            let bytes = take(&mut cursor, 4)?;
            Address::Ipv4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ))
        }
        4 => {
            let bytes: [u8; 16] = take(&mut cursor, 16)?.try_into().unwrap();
            Address::Ipv6(std::net::Ipv6Addr::from(bytes))
        }
        3 => {
            let length = take_u8(&mut cursor)? as usize;
            if length == 0 {
                return Err(invalid_data("Shadowsocks UDP hostname is empty"));
            }
            let hostname = std::str::from_utf8(take(&mut cursor, length)?)
                .map_err(|_| invalid_data("Shadowsocks UDP hostname is not UTF-8"))?;
            Address::from(hostname)?
        }
        other => {
            return Err(invalid_data(format!(
                "unknown Shadowsocks UDP address type {other}"
            )));
        }
    };
    let port = take_u16(&mut cursor)?;
    Ok((NetLocation::new(address, port), cursor))
}

fn take<'a>(cursor: &mut &'a [u8], length: usize) -> std::io::Result<&'a [u8]> {
    if cursor.len() < length {
        return Err(invalid_data("truncated Shadowsocks UDP packet"));
    }
    let (value, rest) = cursor.split_at(length);
    *cursor = rest;
    Ok(value)
}

fn take_u8(cursor: &mut &[u8]) -> std::io::Result<u8> {
    Ok(take(cursor, 1)?[0])
}

fn take_u16(cursor: &mut &[u8]) -> std::io::Result<u16> {
    Ok(u16::from_be_bytes(take(cursor, 2)?.try_into().unwrap()))
}

fn take_u64(cursor: &mut &[u8]) -> std::io::Result<u64> {
    Ok(u64::from_be_bytes(take(cursor, 8)?.try_into().unwrap()))
}

fn unix_timestamp() -> std::io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_data("system clock is before the Unix epoch"))
}

fn ensure_udp_packet_size(length: usize) -> std::io::Result<()> {
    if length > MAX_UDP_PACKET_SIZE {
        return Err(invalid_input(format!(
            "encrypted Shadowsocks UDP packet is {length} bytes; maximum is {MAX_UDP_PACKET_SIZE}"
        )));
    }
    Ok(())
}

fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::DefaultKey;

    fn location() -> NetLocation {
        NetLocation::new(Address::Hostname("dns.example".into()), 5353)
    }

    fn response_body(client_session_id: u64, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![1];
        body.extend_from_slice(&unix_timestamp().unwrap().to_be_bytes());
        body.extend_from_slice(&client_session_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&encode_location(&location()).unwrap());
        body.extend_from_slice(payload);
        body
    }

    fn aes_response(
        cipher: ShadowsocksCipher,
        psk: &[u8],
        server_session_id: u64,
        packet_id: u64,
        client_session_id: u64,
        payload: &[u8],
    ) -> Box<[u8]> {
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&server_session_id.to_be_bytes());
        header[8..].copy_from_slice(&packet_id.to_be_bytes());
        let key = new_2022_session_cipher(cipher, psk, &header[..8]).unwrap();
        let mut body = response_body(client_session_id, payload);
        seal_with_key(&key, nonce_from_2022_header(&header).unwrap(), &mut body).unwrap();
        aes_ecb_encrypt(psk, &mut header).unwrap();
        [header.as_slice(), &body].concat().into_boxed_slice()
    }

    fn chacha_response(
        psk: &[u8],
        server_session_id: u64,
        packet_id: u64,
        client_session_id: u64,
        payload: &[u8],
    ) -> Box<[u8]> {
        let nonce = [9u8; XCHACHA_NONCE_SIZE];
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&server_session_id.to_be_bytes());
        plaintext.extend_from_slice(&packet_id.to_be_bytes());
        plaintext.extend_from_slice(&response_body(client_session_id, payload));
        xchacha_seal(psk, &nonce, &mut plaintext).unwrap();
        [nonce.as_slice(), &plaintext].concat().into_boxed_slice()
    }

    #[test]
    fn socks_addresses_reject_overlong_domains_and_truncation() {
        let long = NetLocation::new(Address::Hostname("x".repeat(256)), 53);
        assert!(encode_location(&long).is_err());
        assert!(decode_location(&[3, 4, b'a']).is_err());

        for location in [
            NetLocation::new(Address::Ipv4("192.0.2.1".parse().unwrap()), 53),
            NetLocation::new(Address::Ipv6("2001:db8::1".parse().unwrap()), 443),
            location(),
        ] {
            let encoded = encode_location(&location).unwrap();
            let (decoded, remainder) = decode_location(&encoded).unwrap();
            assert_eq!(decoded, location);
            assert!(remainder.is_empty());
        }
    }

    #[test]
    fn legacy_aead_packet_round_trip_and_replay_rejection() {
        for cipher_name in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let cipher = ShadowsocksCipher::try_from(cipher_name).unwrap();
            let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                "correct horse battery staple",
                cipher.key_len(),
            )));
            let packet = encode_legacy_packet(cipher, &key, &location(), b"payload").unwrap();
            let mut replay = ReplayFilter::new(Duration::from_secs(60));
            assert_eq!(
                &*decode_legacy_packet(cipher, &key, &mut replay, &packet).unwrap(),
                b"payload",
                "{cipher_name}"
            );
            assert!(
                decode_legacy_packet(cipher, &key, &mut replay, &packet).is_err(),
                "{cipher_name}"
            );
        }
    }

    #[test]
    fn sliding_window_matches_sing_shadowsocks_boundaries() {
        let mut window = SlidingWindow::default();
        assert!(window.check(0));
        window.add(0);
        assert!(!window.check(0));
        window.add(10_000);
        assert!(!window.check(10_000));
        assert!(!window.check(10_000 - SlidingWindow::SIZE - 1));
        assert!(window.check(10_001));
    }

    #[test]
    fn aead_2022_aes_request_has_go_compatible_layout_and_identity_header() {
        let cipher = ShadowsocksCipher::try_from("aes-128-gcm").unwrap();
        let outer = vec![1; 16].into_boxed_slice();
        let own = vec![2; 16].into_boxed_slice();
        let mut session = Shadowsocks2022UdpSession::new(
            cipher,
            vec![outer.clone(), own.clone()].into_boxed_slice(),
        )
        .unwrap();
        let packet = session.encode_packet(&location(), b"hello").unwrap();

        let mut header: [u8; 16] = packet[..16].try_into().unwrap();
        aes_ecb_decrypt(&outer, &mut header).unwrap();
        assert_eq!(u64::from_be_bytes(header[8..].try_into().unwrap()), 0);

        let mut identity: [u8; 16] = packet[16..32].try_into().unwrap();
        aes_ecb_decrypt(&outer, &mut identity).unwrap();
        for (byte, header_byte) in identity.iter_mut().zip(header) {
            *byte ^= header_byte;
        }
        assert_eq!(identity, psk_hash(&own));

        let key = new_2022_session_cipher(cipher, &own, &header[..8]).unwrap();
        let mut body = packet[32..].to_vec();
        open_with_key(&key, nonce_from_2022_header(&header).unwrap(), &mut body).unwrap();
        assert_eq!(body[0], 0);
        let padding_len = u16::from_be_bytes(body[9..11].try_into().unwrap()) as usize;
        let (target, payload) = decode_location(&body[11 + padding_len..]).unwrap();
        assert_eq!(target, location());
        assert_eq!(payload, b"hello");

        let response = aes_response(cipher, &own, 41, 0, session.client_session_id, b"world");
        assert_eq!(&*session.decode_packet(&response).unwrap(), b"world");
        assert!(
            session.decode_packet(&response).is_err(),
            "the same authenticated packet id must be rejected as a replay"
        );
    }

    #[test]
    fn aead_2022_chacha_request_uses_xchacha_packet_nonce() {
        let cipher = ShadowsocksCipher::try_from("chacha20-ietf-poly1305").unwrap();
        let own = vec![7; 32].into_boxed_slice();
        let mut session =
            Shadowsocks2022UdpSession::new(cipher, vec![own.clone()].into_boxed_slice()).unwrap();
        let packet = session.encode_packet(&location(), b"hello").unwrap();
        let mut plaintext = packet[XCHACHA_NONCE_SIZE..].to_vec();
        xchacha_open(&own, &packet[..XCHACHA_NONCE_SIZE], &mut plaintext).unwrap();
        assert_eq!(plaintext[16], 0);
        let padding_len = u16::from_be_bytes(plaintext[25..27].try_into().unwrap()) as usize;
        let (target, payload) = decode_location(&plaintext[27 + padding_len..]).unwrap();
        assert_eq!(target, location());
        assert_eq!(payload, b"hello");

        let response = chacha_response(&own, 51, 7, session.client_session_id, b"world");
        assert_eq!(&*session.decode_packet(&response).unwrap(), b"world");
        assert!(session.decode_packet(&response).is_err());
    }

    #[test]
    fn aead_2022_response_binds_client_session_and_limits_server_session_churn() {
        let cipher = ShadowsocksCipher::try_from("aes-256-gcm").unwrap();
        let own = vec![3; 32].into_boxed_slice();
        let mut session =
            Shadowsocks2022UdpSession::new(cipher, vec![own.clone()].into_boxed_slice()).unwrap();

        let wrong_client = aes_response(
            cipher,
            &own,
            10,
            0,
            session.client_session_id.wrapping_add(1),
            b"bad",
        );
        assert!(session.decode_packet(&wrong_client).is_err());

        let first = aes_response(cipher, &own, 10, 0, session.client_session_id, b"one");
        let second = aes_response(cipher, &own, 11, 0, session.client_session_id, b"two");
        let third = aes_response(cipher, &own, 12, 0, session.client_session_id, b"three");
        assert_eq!(&*session.decode_packet(&first).unwrap(), b"one");
        assert_eq!(&*session.decode_packet(&second).unwrap(), b"two");
        assert!(session.decode_packet(&third).is_err());
    }
}
