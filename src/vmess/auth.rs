//! The VMess auth id, seen from the server's side.
//!
//! # Why VMess cannot look a user up
//!
//! Every other protocol here sends something a server can index on: VLESS puts a
//! uuid on the wire in cleartext, Trojan sends a hex digest. VMess sends 16 bytes
//! that were AES-128-ECB *encrypted* under a key derived from the user's uuid, and
//! those bytes hold nothing but a timestamp and a CRC32C over it. There is no user
//! identifier anywhere in the clear and no keyed hash to look up, so the only way to
//! learn whose connection this is, is to decrypt with each known user's key and see
//! whose checksum comes out right.
//!
//! Every other implementation does the same thing for the same reason.
//!
//! # Why this is a separate type
//!
//! The derivation depends only on the uuid -- never on the connection, the
//! timestamp, or any salt -- so it can be done once when a user is registered and
//! reused for every connection afterwards. That is what makes the trial affordable:
//! a registry holding a thousand users does a thousand single-block AES decryptions
//! and a thousand CRC32s per connection, tens of microseconds, once, inside a
//! handshake that has usually just finished a TLS exchange.
//!
//! Keeping it here rather than in a registry also keeps VMess' key schedule in the
//! one module that owns VMess' wire format. A registry stores these; it does not
//! know what is in them.

use aws_lc_rs::cipher::{
    AES_128, DecryptingKey as CipherDecryptingKey, DecryptionContext, UnboundCipherKey,
};

use super::md5::compute_md5;

/// The suffix VMess mixes into a uuid before hashing it to the instruction key.
///
/// A protocol constant, not a secret: it is the same in every implementation.
const INSTRUCTION_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// One user's precomputed material for recognising their auth id.
pub struct VmessAuthKey {
    /// The per-user key the request header's AEAD keys are derived from. Needed by
    /// the handler as soon as the auth id is recognised, so it is handed back
    /// together with the match rather than re-derived.
    instruction_key: [u8; 16],
    ecb: CipherDecryptingKey,
}

impl std::fmt::Debug for VmessAuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither field may be printed: both are key material.
        f.write_str("VmessAuthKey")
    }
}

impl VmessAuthKey {
    /// Derive the auth material for a uuid, in the wire byte order VLESS and VMess
    /// both use.
    pub fn new(uuid: &[u8; 16]) -> Self {
        let mut seed = Vec::with_capacity(uuid.len() + INSTRUCTION_KEY_SUFFIX.len());
        seed.extend_from_slice(uuid);
        seed.extend_from_slice(INSTRUCTION_KEY_SUFFIX);
        let instruction_key: [u8; 16] = compute_md5(&seed);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        // Both `expect`s are unreachable: AES_128 takes any 16 bytes as a key, and
        // the kdf always yields 32.
        let unbound_key =
            UnboundCipherKey::new(&AES_128, &derived_key[0..16]).expect("16 byte AES-128 key");
        let ecb = CipherDecryptingKey::ecb(unbound_key).expect("ECB mode from a valid AES key");

        Self {
            instruction_key,
            ecb,
        }
    }

    /// Whether this user sealed `auth_id`, and if so the timestamp inside it.
    ///
    /// The checksum is a cryptographic statement, not a comparison against a stored
    /// secret: it can only come out right if the sender held the uuid this key was
    /// derived from. So there is no `subtle` comparison here and none is needed --
    /// there is no stored credential to leak a byte at a time.
    ///
    /// The timestamp is returned rather than judged. A recognised user whose clock
    /// is far off must be reported as exactly that, and folding the freshness check
    /// in here would instead let their connection fall through to the remaining
    /// users and be reported as an unknown credential.
    pub fn open(&self, auth_id: &[u8; 16]) -> Option<u64> {
        let mut plaintext = *auth_id;
        // Fails only on a bad block length, which is fixed at 16 here.
        self.ecb
            .decrypt(&mut plaintext, DecryptionContext::None)
            .ok()?;

        let expected = u32::from_be_bytes(plaintext[12..16].try_into().unwrap());
        if super::crc32::crc32c(&plaintext[0..12]) != expected {
            return None;
        }
        Some(u64::from_be_bytes(plaintext[0..8].try_into().unwrap()))
    }

    /// The key the rest of the request header is derived from.
    pub fn instruction_key(&self) -> &[u8; 16] {
        &self.instruction_key
    }

    /// Seal a timestamp into an auth id, the way a client does. The inverse of
    /// [`open`](Self::open).
    ///
    /// This exists because the registries are the interesting part and they cannot be
    /// tested without it. A recorded fixture would pass just as happily if both halves
    /// of the format were wrong together, and an out-of-crate
    /// [`UserRegistry`](crate::dynamic::UserRegistry) -- which is the whole reason this
    /// type is public -- has no other way to produce a valid auth id.
    ///
    /// `padding` is the four bytes a real client fills at random. It is a parameter
    /// rather than generated here so the output is reproducible; the checksum covers
    /// whatever is passed, so every value yields a valid auth id.
    ///
    /// Deliberately not on a hot path: it rebuilds its key schedule per call, where
    /// [`open`](Self::open) uses the one derived at construction. `VmessTcpClientHandler`
    /// keeps its own copy of this construction and is left alone -- it is upstream code
    /// on the client side of a server-side change, and rewriting it to call this would
    /// buy nothing but merge conflicts.
    // NOTE(shoes-engine): reached from this crate's own tests, from the engine's,
    // and by an out-of-crate registry through the `dynamic::credential` re-export --
    // but by nothing the binary links, which is the only target without a blanket
    // `dead_code` allow.
    #[allow(dead_code)]
    pub fn seal(&self, timestamp: u64, padding: [u8; 4]) -> [u8; 16] {
        use aws_lc_rs::cipher::{EncryptingKey as CipherEncryptingKey, EncryptionContext};

        let derived_key = super::sha2::kdf(&self.instruction_key, &[b"AES Auth ID Encryption"]);
        let unbound_key =
            UnboundCipherKey::new(&AES_128, &derived_key[0..16]).expect("16 byte AES-128 key");
        let key = CipherEncryptingKey::ecb(unbound_key).expect("ECB mode from a valid AES key");

        let mut block = [0u8; 16];
        block[0..8].copy_from_slice(&timestamp.to_be_bytes());
        block[8..12].copy_from_slice(&padding);
        let checksum = super::crc32::crc32c(&block[0..12]);
        block[12..16].copy_from_slice(&checksum.to_be_bytes());

        key.less_safe_encrypt(&mut block, EncryptionContext::None)
            .expect("ECB encryption of one block");
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::credential::parse_uuid;

    const UUID_A: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
    const UUID_B: &str = "11111111-1111-4111-8111-111111111111";

    fn uuid_bytes(s: &str) -> [u8; 16] {
        parse_uuid(s).unwrap()
    }

    fn seal(uuid: &str, time_secs: u64) -> [u8; 16] {
        VmessAuthKey::new(&uuid_bytes(uuid)).seal(time_secs, [0xde, 0xad, 0xbe, 0xef])
    }

    #[test]
    fn recognises_an_auth_id_it_sealed_and_reports_its_timestamp() {
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        assert_eq!(key.open(&seal(UUID_A, 1_700_000_000)), Some(1_700_000_000));
    }

    #[test]
    fn recognises_it_whatever_the_padding_is() {
        // The padding is the client's to choose, so the same user's auth ids differ
        // from connection to connection and every one of them must open.
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        let mut seen = std::collections::HashSet::new();
        for n in 0u32..8 {
            let auth_id = key.seal(1_700_000_000, n.to_be_bytes());
            assert_eq!(key.open(&auth_id), Some(1_700_000_000));
            assert!(seen.insert(auth_id), "each auth id should be distinct");
        }
    }

    #[test]
    fn rejects_another_users_auth_id() {
        // The whole basis of the trial: exactly one user's key validates.
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        assert!(key.open(&seal(UUID_B, 1_700_000_000)).is_none());
    }

    #[test]
    fn rejects_random_bytes() {
        // A 2^-32 checksum collision is the false-accept rate, so a handful of
        // samples is a smoke test rather than a proof; what it does catch is the
        // checksum being skipped entirely.
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        for seed in 0u8..32 {
            let garbage = [seed; 16];
            assert!(key.open(&garbage).is_none());
        }
    }

    #[test]
    fn reports_a_stale_timestamp_rather_than_hiding_it() {
        // Freshness is the caller's decision; `open` must still recognise the user.
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        assert_eq!(key.open(&seal(UUID_A, 0)), Some(0));
    }

    #[test]
    fn derives_the_same_instruction_key_for_both_uuid_spellings() {
        let dashed = VmessAuthKey::new(&uuid_bytes(UUID_A));
        let bare = VmessAuthKey::new(&uuid_bytes(&UUID_A.replace('-', "")));
        assert_eq!(dashed.instruction_key(), bare.instruction_key());
    }

    #[test]
    fn keeps_key_material_out_of_its_debug_output() {
        let key = VmessAuthKey::new(&uuid_bytes(UUID_A));
        assert_eq!(format!("{key:?}"), "VmessAuthKey");
    }
}
