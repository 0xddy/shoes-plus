//! Salamander, Hysteria2's UDP obfuscation.
//!
//! Every datagram leaving the socket gets an 8 byte random salt prepended and
//! its payload XORed with `BLAKE2b-256(password ‖ salt)`, a 32 byte keystream
//! that simply repeats for payloads longer than that.
//!
//! # What it is and is not
//!
//! This is **not** encryption and is not treated as a security boundary. The
//! salt travels in the clear, the keystream repeats every 32 bytes, and QUIC's
//! own TLS is what actually protects the traffic underneath. Salamander exists
//! to stop a middlebox recognising a QUIC handshake by its fixed header bits --
//! it buys unrecognisability, not confidentiality.
//!
//! Which is also why it sits *below* QUIC rather than inside it: quinn sees
//! ordinary datagrams and never knows this layer is here.
//!
//! # Compatibility
//!
//! The wire format is fixed by the clients already deployed against the Go
//! implementation (`sing-quic/hysteria2/salamander.go`). The tests at the bottom
//! check against bytes captured from that implementation over a real socket, not
//! against a second reading of the spec.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand::Rng as _;

type Blake2b256 = Blake2b<U32>;

/// Bytes of random salt prepended to every obfuscated datagram.
pub const SALT_LEN: usize = 8;

/// Length of the derived keystream, and therefore its repeat period.
const KEY_LEN: usize = 32;

/// Derives and applies the Salamander keystream for one password.
#[derive(Clone)]
pub struct Salamander {
    password: Box<[u8]>,
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The password is a shared secret. Printing its length rather than its
        // bytes keeps a stray `{:?}` in a log from leaking it.
        f.debug_struct("Salamander")
            .field("password_len", &self.password.len())
            .finish()
    }
}

impl Salamander {
    pub fn new(password: &str) -> Self {
        Self {
            password: password.as_bytes().into(),
        }
    }

    /// `BLAKE2b-256(password ‖ salt)`.
    fn keystream(&self, salt: &[u8]) -> [u8; KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.password);
        hasher.update(salt);
        hasher.finalize().into()
    }

    /// Writes `salt ‖ XOR(payload)` into `out`, which is cleared first.
    ///
    /// A fresh salt per datagram is what makes two identical payloads look
    /// unrelated on the wire; reusing one would expose the XOR immediately.
    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        self.obfuscate_with_salt(&salt, payload, out);
    }

    fn obfuscate_with_salt(&self, salt: &[u8; SALT_LEN], payload: &[u8], out: &mut Vec<u8>) {
        let key = self.keystream(salt);
        out.clear();
        out.reserve(SALT_LEN + payload.len());
        out.extend_from_slice(salt);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ key[index % KEY_LEN]),
        );
    }

    /// Strips the salt and un-XORs `packet` in place, returning the plaintext
    /// length. The plaintext ends up at the front of the buffer.
    ///
    /// A packet of `SALT_LEN` bytes or fewer is passed through untouched, which
    /// is what the Go implementation does. There is nothing sensible to decode
    /// there -- no salt, no payload -- and quinn discards it as a malformed QUIC
    /// packet a moment later either way.
    ///
    /// One consequence is worth stating, because it looks like a bug until it is
    /// named: an *empty* payload obfuscates to exactly `SALT_LEN` bytes, so it
    /// comes back as 8 bytes of raw salt rather than as nothing. The reference
    /// implementation behaves identically, and QUIC never emits a datagram
    /// anywhere near that small, so the round trip is deliberately left
    /// asymmetric at that one length rather than diverging from the wire format
    /// every deployed client already speaks.
    pub fn deobfuscate(&self, packet: &mut [u8]) -> usize {
        let len = packet.len();
        if len <= SALT_LEN {
            return len;
        }
        let key = self.keystream(&packet[..SALT_LEN]);
        for index in 0..len - SALT_LEN {
            packet[index] = packet[index + SALT_LEN] ^ key[index % KEY_LEN];
        }
        len - SALT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured by driving the real `sing-quic` `SalamanderPacketConn` over a
    /// live UDP socket pair and reading the raw bytes off the far end. The
    /// payload is 83 bytes, comfortably past the 32 byte keystream, so these
    /// vectors exercise the repeat -- which is the part a re-implementation is
    /// most likely to get wrong.
    const PASSWORD: &str = "s3cr3t-obfs";
    const PLAINTEXT: &[u8] =
        b"hysteria2 salamander vector: the quick brown fox jumps over the lazy dog 0123456789";
    const SALT: [u8; SALT_LEN] = [0x81, 0x87, 0x39, 0xa7, 0x89, 0xb7, 0x51, 0xb8];
    const WIRE_HEX: &str = "818739a789b751b817466449d642fe22ad8f0a5fb964cdb95fcca65a9c1559434\
6121a31efb6afa05f4e6254d05bb721edc00e50f563cfa011c2b645cc101c4f44181a2bbbaaa2e5135e6d449354f824bf\
9f480ce63195ee0690fa";
    const KEY_HEX: &str = "7f3f173db33097439faf793ed505a0d831a8c328bc633c20327d680bcfc2c7c5";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn blake2b_256_matches_its_published_vectors() {
        // Localises a failure: if these are wrong the hash is wrong, and nothing
        // about the obfuscation itself is worth reading yet.
        assert_eq!(
            hex(&Blake2b256::digest(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex(&Blake2b256::digest(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    #[test]
    fn the_keystream_matches_the_go_implementation() {
        let salamander = Salamander::new(PASSWORD);
        assert_eq!(hex(&salamander.keystream(&SALT)), KEY_HEX);
    }

    #[test]
    fn obfuscation_reproduces_the_captured_wire_bytes() {
        let salamander = Salamander::new(PASSWORD);
        let mut out = Vec::new();
        salamander.obfuscate_with_salt(&SALT, PLAINTEXT, &mut out);

        assert_eq!(out.len(), SALT_LEN + PLAINTEXT.len());
        assert_eq!(
            hex(&out),
            WIRE_HEX,
            "a deployed client would no longer be understood"
        );
    }

    #[test]
    fn deobfuscation_recovers_the_plaintext_from_captured_wire_bytes() {
        let salamander = Salamander::new(PASSWORD);
        let mut packet = unhex(WIRE_HEX);
        let len = salamander.deobfuscate(&mut packet);
        assert_eq!(&packet[..len], PLAINTEXT);
    }

    #[test]
    fn a_wrong_password_does_not_recover_the_plaintext() {
        let salamander = Salamander::new(PASSWORD);
        let mut packet = unhex(WIRE_HEX);
        let len = Salamander::new("wrong").deobfuscate(&mut packet);
        assert_ne!(&packet[..len], PLAINTEXT);

        // And the right password still works on a fresh copy, so the failure
        // above is the password and not a corrupted fixture.
        let mut packet = unhex(WIRE_HEX);
        let len = salamander.deobfuscate(&mut packet);
        assert_eq!(&packet[..len], PLAINTEXT);
    }

    #[test]
    fn round_trips_at_every_length_around_the_keystream_period() {
        let salamander = Salamander::new("round-trip");
        // 31/32/33 bracket the keystream repeat and 1500 is a realistic
        // MTU-sized datagram spanning many of them. Zero is excluded on
        // purpose -- see `an_empty_payload_is_the_one_length_that_cannot_round_trip`.
        for len in [1usize, 7, 8, 9, 31, 32, 33, 64, 65, 1500] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut wire = Vec::new();
            salamander.obfuscate(&payload, &mut wire);
            assert_eq!(wire.len(), SALT_LEN + len, "length {len}");

            let recovered_len = salamander.deobfuscate(&mut wire);
            assert_eq!(recovered_len, len, "length {len}");
            assert_eq!(&wire[..recovered_len], &payload[..], "length {len}");
        }
    }

    #[test]
    fn each_datagram_gets_a_fresh_salt() {
        // A reused salt would make identical payloads produce identical wire
        // bytes, which is precisely the pattern this layer exists to remove.
        let salamander = Salamander::new("fresh-salt");
        let payload = b"the same payload every time";
        let mut first = Vec::new();
        let mut second = Vec::new();
        salamander.obfuscate(payload, &mut first);
        salamander.obfuscate(payload, &mut second);

        assert_ne!(first, second, "two datagrams must not look alike");
        assert_ne!(&first[..SALT_LEN], &second[..SALT_LEN]);

        // Both still decode.
        assert_eq!(salamander.deobfuscate(&mut first), payload.len());
        assert_eq!(&first[..payload.len()], payload);
        assert_eq!(salamander.deobfuscate(&mut second), payload.len());
        assert_eq!(&second[..payload.len()], payload);
    }

    #[test]
    fn an_empty_payload_is_the_one_length_that_cannot_round_trip() {
        // Inherited from the reference implementation: an empty payload is
        // indistinguishable on the wire from a runt packet, because both are
        // exactly the salt. Pinned here so that if anyone "fixes" it, they find
        // out immediately that the fix breaks every deployed client instead of
        // discovering it in production.
        let salamander = Salamander::new(PASSWORD);
        let mut wire = Vec::new();
        salamander.obfuscate(b"", &mut wire);
        assert_eq!(wire.len(), SALT_LEN);
        assert_eq!(
            salamander.deobfuscate(&mut wire),
            SALT_LEN,
            "the salt is returned as-is, not decoded to an empty payload"
        );
    }

    #[test]
    fn a_runt_packet_is_passed_through_untouched() {
        let salamander = Salamander::new(PASSWORD);
        for len in 0..=SALT_LEN {
            let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut packet = original.clone();
            assert_eq!(salamander.deobfuscate(&mut packet), len);
            assert_eq!(packet, original, "length {len} must be left alone");
        }
    }

    #[test]
    fn the_debug_impl_does_not_leak_the_password() {
        let rendered = format!("{:?}", Salamander::new("hunter2"));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("password_len"));
    }
}

// ---------------------------------------------------------------------------
// quinn integration
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

thread_local! {
    /// Scratch space for one outgoing datagram, reused across sends.
    ///
    /// `try_send` takes `&self` and runs on the hot path, so the alternative is
    /// an allocation per datagram. Thread-local rather than a shared pool
    /// because quinn drives each endpoint from its own task and a lock here
    /// would serialise sends across the whole endpoint.
    static SEND_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Wraps a UDP socket so quinn sends and receives Salamander-obfuscated
/// datagrams without knowing it.
///
/// This decorates an existing [`AsyncUdpSocket`] rather than reimplementing one:
/// all the platform-specific work -- ECN, source addresses, readiness -- stays
/// with quinn's own socket, and this type only transforms bytes on the way past.
///
/// # GSO and GRO are disabled
///
/// Both offloads work by moving several datagrams through the kernel as one
/// buffer, but Salamander gives every datagram its own random salt and its own
/// length. A coalesced buffer therefore cannot be obfuscated or recovered as a
/// unit, so [`max_transmit_segments`] and [`max_receive_segments`] both report
/// `1` and the kernel hands us one datagram at a time. That costs throughput on
/// high-bandwidth links; it is the price of the obfuscation, and it applies only
/// to inbounds that switch it on.
///
/// [`max_transmit_segments`]: AsyncUdpSocket::max_transmit_segments
/// [`max_receive_segments`]: AsyncUdpSocket::max_receive_segments
#[derive(Debug)]
pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    salamander: Salamander,
}

impl ObfuscatedUdpSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, salamander: Salamander) -> Self {
        Self { inner, salamander }
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Write readiness is a property of the underlying socket; obfuscation
        // does not change when it can accept another datagram.
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // GSO is off, so a transmit is always exactly one datagram. A
        // `segment_size` smaller than the payload would mean the kernel was
        // asked to split it, which we cannot obfuscate segment-by-segment --
        // refuse loudly instead of putting unreadable bytes on the wire.
        if let Some(segment_size) = transmit.segment_size
            && segment_size < transmit.contents.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salamander cannot obfuscate a GSO batch; max_transmit_segments is 1",
            ));
        }

        SEND_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            self.salamander.obfuscate(transmit.contents, &mut buffer);
            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &buffer,
                // The obfuscated datagram is a single unit; carrying the
                // original segment size forward would describe it wrongly.
                segment_size: None,
                src_ip: transmit.src_ip,
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;

        for (buffer, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(count) {
            let len = meta.len.min(buffer.len());
            meta.len = self.salamander.deobfuscate(&mut buffer[..len]);
            // GRO is off, so one buffer is one datagram and the stride is simply
            // its new length. Leaving the pre-decode stride here would tell
            // quinn the buffer holds several datagrams that are no longer there.
            meta.stride = meta.len;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
