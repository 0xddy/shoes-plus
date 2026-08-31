//! Shadowsocks 2022 extensible identity headers.
//!
//! # The circularity a multi-user server has to break
//!
//! A 2022 server that serves one user needs no notion of identity at all: the PSK in
//! its config *is* the user, and a client who cannot derive the right session key
//! simply fails the first AEAD tag. Serving several users breaks that, because the
//! salt a client sends says nothing about who they are, and the session key -- the
//! very thing the server would need in order to decrypt something identifying -- is
//! derived from the PSK it is trying to find.
//!
//! The identity header names the PSK before any of it is in use. The inbound holds one
//! *identity* PSK that all of its clients know; a client prefixes one AES block whose
//! plaintext is the truncated blake3 hash of the PSK it actually wants to speak,
//! encrypted under a subkey of the identity PSK and the salt it just sent. The server
//! derives the same subkey, decrypts the block, and looks the hash up. One blake3 and
//! one AES block per connection, and the result is a real lookup -- unlike VMess,
//! which has nothing to index on and must try every user in turn.
//!
//! Binding the subkey to the salt is what keeps the block from being a stable per-user
//! fingerprint that an observer could follow from one connection to the next.
//!
//! # Layout
//!
//! ```text
//! salt (keySaltLength) | identity header (16) * n | AEAD chunks ...
//! ```
//!
//! The layers nest: with a chain of PSKs each header names the next one down, so a
//! relay can strip its own and pass the remainder along. `shoes` is not a relay, so a
//! server here reads exactly one header; the client half will write a chain of any
//! length, which is what lets it speak to a relay that expects one.
//!
//! # Ciphers
//!
//! Only `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. A header is a bare
//! AES block, so `2022-blake3-chacha20-poly1305` has no construction for one -- and
//! sing-box, which is what a multi-user 2022 client is in practice, refuses that
//! combination for the same reason.

use aws_lc_rs::cipher::{
    AES_128, AES_256, Algorithm, DecryptingKey, DecryptionContext, EncryptingKey,
    EncryptionContext, UnboundCipherKey,
};

use super::shadowsocks_cipher::ShadowsocksCipher;
use crate::util::allocate_vec;

/// One identity header: a single AES block.
pub const IDENTITY_HEADER_LEN: usize = 16;

/// The longest salt any supported cipher uses, for callers sizing a stack buffer.
pub const MAX_SALT_LEN: usize = 32;

/// blake3 derive-key context for an identity subkey. A protocol constant, not a
/// secret: it is the same string in every implementation.
const IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

/// Whether identity headers -- and so more than one user -- are defined for this
/// cipher.
///
/// Matched on the cipher's name because that is the discriminant
/// [`ShadowsocksCipher`] exposes; the key length alone would let chacha20 through,
/// since it shares aes-256-gcm's 32 bytes.
pub fn supports_identity_headers(cipher: &ShadowsocksCipher) -> bool {
    matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm")
}

/// The 16 bytes a client sends to name a PSK: blake3 of the key, truncated to one
/// block.
pub fn psk_hash(psk: &[u8]) -> [u8; IDENTITY_HEADER_LEN] {
    let mut out = [0u8; IDENTITY_HEADER_LEN];
    out.copy_from_slice(&blake3::hash(psk).as_bytes()[..IDENTITY_HEADER_LEN]);
    out
}

/// Recover the PSK hash a client sealed into `header`.
///
/// `salt` is the salt that preceded the header on the wire, and `identity_psk` is the
/// inbound's own key. A wrong identity PSK does not fail here -- ECB always produces
/// a block -- it produces 16 bytes that name nobody, which is the caller's cue that
/// this was not one of its clients.
pub fn open_identity_header(
    identity_psk: &[u8],
    salt: &[u8],
    header: &[u8; IDENTITY_HEADER_LEN],
) -> std::io::Result<[u8; IDENTITY_HEADER_LEN]> {
    let subkey = identity_subkey(identity_psk, salt)?;
    let key = DecryptingKey::ecb(unbound_ecb_key(&subkey)?)
        .map_err(|_| std::io::Error::other("failed to set up ECB for an identity header"))?;
    let mut block = *header;
    key.decrypt(&mut block, DecryptionContext::None)
        .map_err(|_| std::io::Error::other("failed to decrypt shadowsocks identity header"))?;
    Ok(block)
}

/// Seal the identity headers a client sends, as the raw bytes that follow the salt.
///
/// `chain` runs from the outermost identity PSK to the client's own, so a two element
/// chain yields one header and an n element chain yields n-1. A chain of one -- just
/// the client's own PSK -- yields nothing, which is the ordinary single-user case.
pub fn seal_identity_headers(chain: &[Box<[u8]>], salt: &[u8]) -> std::io::Result<Box<[u8]>> {
    let mut out = Vec::with_capacity(chain.len().saturating_sub(1) * IDENTITY_HEADER_LEN);
    for pair in chain.windows(2) {
        let subkey = identity_subkey(&pair[0], salt)?;
        let key = EncryptingKey::ecb(unbound_ecb_key(&subkey)?)
            .map_err(|_| std::io::Error::other("failed to set up ECB for an identity header"))?;
        let mut block = psk_hash(&pair[1]);
        key.less_safe_encrypt(&mut block, EncryptionContext::None)
            .map_err(|_| std::io::Error::other("failed to encrypt shadowsocks identity header"))?;
        out.extend_from_slice(&block);
    }
    Ok(out.into_boxed_slice())
}

/// The per-connection key an identity header is encrypted under.
///
/// Its length is the cipher's keySaltLength, which is also the length of both the
/// salt and every PSK -- hence the equality check, which catches a PSK of the wrong
/// size here rather than in the assertion inside `Blake3Key::create_session_key`.
fn identity_subkey(psk: &[u8], salt: &[u8]) -> std::io::Result<Box<[u8]>> {
    if psk.len() != salt.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "shadowsocks 2022 key must be {} bytes for this cipher, got {}",
                salt.len(),
                psk.len()
            ),
        ));
    }

    let mut material = allocate_vec(psk.len() + salt.len());
    material[..psk.len()].copy_from_slice(psk);
    material[psk.len()..].copy_from_slice(salt);

    let mut hasher = blake3::Hasher::new_derive_key(IDENTITY_SUBKEY_CONTEXT);
    hasher.update(&material);
    let mut subkey = allocate_vec(salt.len());
    hasher.finalize_xof().fill(&mut subkey);

    Ok(subkey.into_boxed_slice())
}

fn aes_algorithm(key_len: usize) -> Option<&'static Algorithm> {
    match key_len {
        16 => Some(&AES_128),
        32 => Some(&AES_256),
        _ => None,
    }
}

/// An unbound AES key over `subkey`, in whichever flavour its length calls for.
///
/// The flavour follows the key length rather than being named anywhere, matching Go's
/// `aes.NewCipher` -- which is what the reference implementations hand this subkey to.
fn unbound_ecb_key(subkey: &[u8]) -> std::io::Result<UnboundCipherKey> {
    let algorithm = aes_algorithm(subkey.len()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "shadowsocks identity headers need a 16 or 32 byte key, got {}",
                subkey.len()
            ),
        )
    })?;
    UnboundCipherKey::new(algorithm, subkey)
        .map_err(|_| std::io::Error::other("invalid AES key for shadowsocks identity header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ciphers that have identity headers, by their PSK length.
    const LENGTHS: [usize; 2] = [16, 32];

    fn psk(seed: u8, len: usize) -> Box<[u8]> {
        vec![seed; len].into_boxed_slice()
    }

    fn salt(len: usize) -> Box<[u8]> {
        (0..len as u8).collect::<Vec<u8>>().into_boxed_slice()
    }

    fn block(bytes: &[u8]) -> [u8; IDENTITY_HEADER_LEN] {
        bytes.try_into().unwrap()
    }

    #[test]
    fn a_sealed_header_names_the_next_psk() {
        for len in LENGTHS {
            let ipsk = psk(1, len);
            let upsk = psk(2, len);
            let salt = salt(len);

            let headers = seal_identity_headers(&[ipsk.clone(), upsk.clone()], &salt).unwrap();
            assert_eq!(headers.len(), IDENTITY_HEADER_LEN, "one link, one block");

            let opened = open_identity_header(&ipsk, &salt, &block(&headers)).unwrap();
            assert_eq!(opened, psk_hash(&upsk));
        }
    }

    #[test]
    fn a_chain_yields_one_header_per_link() {
        // What a relay would see. Each layer opens with its own PSK and names the next.
        let chain = [psk(1, 32), psk(2, 32), psk(3, 32)];
        let salt = salt(32);
        let headers = seal_identity_headers(&chain, &salt).unwrap();
        assert_eq!(headers.len(), 2 * IDENTITY_HEADER_LEN);

        assert_eq!(
            open_identity_header(&chain[0], &salt, &block(&headers[..16])).unwrap(),
            psk_hash(&chain[1])
        );
        assert_eq!(
            open_identity_header(&chain[1], &salt, &block(&headers[16..])).unwrap(),
            psk_hash(&chain[2])
        );
    }

    #[test]
    fn a_lone_psk_needs_no_header() {
        // The single-user case: nothing to name, so nothing on the wire.
        assert!(
            seal_identity_headers(&[psk(1, 32)], &salt(32))
                .unwrap()
                .is_empty()
        );
        assert!(seal_identity_headers(&[], &salt(32)).unwrap().is_empty());
    }

    #[test]
    fn the_header_changes_with_the_salt() {
        // The property that keeps the block from being a per-user fingerprint an
        // observer could follow between connections.
        let chain = [psk(1, 32), psk(2, 32)];
        let first = seal_identity_headers(&chain, &salt(32)).unwrap();
        let mut other = salt(32).to_vec();
        other[0] ^= 0xff;
        let second = seal_identity_headers(&chain, &other).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn the_wrong_identity_psk_names_nobody() {
        // ECB always produces a block, so this must not look like an error -- it looks
        // like a hash that is in no registry.
        let salt = salt(32);
        let headers = seal_identity_headers(&[psk(1, 32), psk(2, 32)], &salt).unwrap();
        let opened = open_identity_header(&psk(9, 32), &salt, &block(&headers)).unwrap();
        assert_ne!(opened, psk_hash(&psk(2, 32)));
    }

    #[test]
    fn distinct_users_get_distinct_names() {
        let hashes: Vec<_> = (0..8u8).map(|n| psk_hash(&psk(n, 32))).collect();
        for (i, a) in hashes.iter().enumerate() {
            for b in &hashes[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // Nor does the length of a key make it a different user's name.
        assert_ne!(psk_hash(&psk(1, 16)), psk_hash(&psk(1, 32)));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_loudly() {
        // Better here than in the assertion inside `Blake3Key::create_session_key`,
        // which would take the process down.
        assert!(open_identity_header(&psk(1, 16), &salt(32), &[0u8; 16]).is_err());
        assert!(seal_identity_headers(&[psk(1, 16), psk(2, 32)], &salt(32)).is_err());
        // A length no AES flavour covers, reached through a matching salt.
        assert!(open_identity_header(&psk(1, 24), &salt(24), &[0u8; 16]).is_err());
    }

    #[test]
    fn only_the_aes_ciphers_have_identity_headers() {
        for name in ["aes-128-gcm", "aes-256-gcm"] {
            let cipher = ShadowsocksCipher::try_from(name).unwrap();
            assert!(supports_identity_headers(&cipher), "{name}");
            // The salt is what a caller derives the subkey against, so the two lengths
            // agreeing is what makes a config's PSK the right size by construction.
            assert_eq!(cipher.salt_len(), cipher.key_len());
        }
        let chacha = ShadowsocksCipher::try_from("chacha20-ietf-poly1305").unwrap();
        assert!(!supports_identity_headers(&chacha));
    }
}
