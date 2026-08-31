//! Credential derivation for registries built outside this crate.
//!
//! A control plane receives credentials the way an operator writes them -- a uuid
//! in canonical form, a Trojan password in cleartext -- but the handlers look users
//! up by what arrives on the wire. These are the two conversions in between.
//!
//! They exist so that an out-of-crate registry indexes on exactly the same bytes
//! `StaticUserRegistry` does. Re-deriving either of them elsewhere would put a
//! second implementation of a wire format in the tree, and the two would drift.

/// A user's precomputed material for recognising their VMess auth id.
///
/// The odd one out here. The other two conversions turn a credential into an index
/// key, because those protocols put something identifying on the wire; VMess does
/// not, so this is a key a registry has to *try* rather than a value it can look up.
/// [`VmessAuthKey`]'s own documentation covers why, and why deriving it once per user
/// is what keeps the trial cheap.
pub use crate::vmess::VmessAuthKey;

/// Derive the 16 bytes a Shadowsocks 2022 client sends to name its PSK: blake3 of the
/// key, truncated to one AES block.
///
/// The index key for [`find_shadowsocks_psk_hash`](super::UserRegistry::find_shadowsocks_psk_hash).
/// Unlike the others this takes raw key bytes rather than something an operator typed,
/// because a 2022 PSK *is* raw bytes; [`decode_shadowsocks_psk`] is how a control plane
/// gets from the one to the other.
pub use crate::shadowsocks::psk_hash as shadowsocks_psk_hash;

/// Decode a Shadowsocks 2022 PSK from base64, the way a config file spells it.
///
/// Does not check the length: how many bytes a key must be depends on the inbound's
/// cipher, and refusing a mismatch with a message naming that cipher is the caller's
/// job.
pub fn decode_shadowsocks_psk(encoded: &str) -> std::io::Result<Box<[u8]>> {
    crate::config::ShadowsocksConfig::decode_key(encoded)
}

/// Encode a Shadowsocks 2022 PSK the way a config file spells it.
///
/// The inverse of [`decode_shadowsocks_psk`], for a control plane that mints a key
/// and has to hand it back for the client's own config.
pub fn encode_shadowsocks_psk(psk: &[u8]) -> String {
    crate::config::ShadowsocksConfig::encode_key(psk)
}

/// Whether a Shadowsocks cipher, named as it is in a config file, can serve more than
/// one user.
///
/// Only the AES ciphers have identity headers, so this is the check that decides
/// whether a shadowsocks inbound can be registry-backed at all.
pub use crate::shadowsocks::supports_identity_headers as shadowsocks_supports_multi_user;

/// Derive the 32 bytes an AnyTLS client sends as the first field of its header:
/// SHA-256 of the password, raw rather than hex.
///
/// The index key for
/// [`find_password_sha256`](super::UserRegistry::find_password_sha256). Note this is
/// a *different* derivation of the same cleartext password Trojan hashes -- Trojan
/// sends 56 hex characters of SHA-224, AnyTLS sends 32 raw bytes of SHA-256 -- so an
/// inbound speaking both indexes one password twice rather than sharing a key.
pub fn password_sha256(password: &str) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, password.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// The first 8 bytes of a password's SHA-256, which AnyTLS peeks at before it has
/// read the whole credential.
///
/// See [`has_password_sha256_prefix`](super::UserRegistry::has_password_sha256_prefix)
/// for what that probe is for and what it must not become.
pub fn password_sha256_prefix(hash: &[u8; 32]) -> [u8; 8] {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&hash[..8]);
    prefix
}

/// Build the credential a NaiveProxy client sends in its `proxy-authorization`
/// header: HTTP Basic, i.e. base64 of `username:password`, without the `Basic `
/// prefix.
///
/// The index key for [`find_naive_basic`](super::UserRegistry::find_naive_basic).
/// Deliberately the *encoded* form rather than the pair: it is what arrives on the
/// wire, so a registry can compare it in constant time without decoding attacker
/// controlled base64 first.
pub fn naive_basic_credential(username: &str, password: &str) -> Box<[u8]> {
    use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
    BASE64
        .encode(format!("{username}:{password}"))
        .into_bytes()
        .into_boxed_slice()
}

/// Parse a uuid into the 16 raw bytes VLESS and VMess put on the wire.
///
/// Dashes are optional and ignored, matching what `shoes` accepts in a config file.
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<[u8; 16]> {
    let bytes = crate::uuid_util::parse_uuid(uuid_str)?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    Ok(uuid)
}

/// Derive the credential a Trojan client sends: SHA-224 of the password, rendered
/// as lowercase hex, 56 bytes.
pub fn trojan_password_hash(password: &str) -> Box<[u8]> {
    crate::trojan_handler::create_password_hash(password)
}

/// A fresh random uuid v4, in canonical form.
///
/// Meant for filling a config field that a [`super::UserRegistry`] has taken over,
/// where the schema still demands a credential that will never be consulted. It is
/// random rather than a fixed constant so that if such a value ever did reach an
/// authentication path, it would not be a credential an attacker could guess.
pub fn random_uuid() -> String {
    crate::uuid_util::generate_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_uuid_spellings_to_the_same_bytes() {
        let dashed = parse_uuid("b85798ef-e9dc-46a4-9a87-8da4499d36d0").unwrap();
        let bare = parse_uuid("b85798efe9dc46a49a878da4499d36d0").unwrap();
        assert_eq!(dashed, bare);
        assert_eq!(dashed[0], 0xb8);
        assert_eq!(dashed[15], 0xd0);
    }

    #[test]
    fn rejects_a_malformed_uuid() {
        assert!(parse_uuid("nope").is_err());
        // Too short: parse_uuid must not leave the tail zeroed and call it a uuid.
        assert!(parse_uuid("b85798ef").is_err());
    }

    #[test]
    fn derives_the_trojan_wire_credential() {
        let hash = trojan_password_hash("hunter2");
        assert_eq!(hash.len(), 56);
        assert!(hash.iter().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(hash, trojan_password_hash("hunter3"));
    }

    #[test]
    fn generates_parseable_and_distinct_uuids() {
        let first = random_uuid();
        let second = random_uuid();
        assert_ne!(first, second);
        assert!(parse_uuid(&first).is_ok());
    }

    #[test]
    fn decodes_a_shadowsocks_psk_and_names_it() {
        // 16 bytes, standard base64 with padding -- an aes-128-gcm key.
        let psk = decode_shadowsocks_psk("MDEyMzQ1Njc4OWFiY2RlZg==").unwrap();
        assert_eq!(&*psk, b"0123456789abcdef");
        assert_eq!(encode_shadowsocks_psk(&psk), "MDEyMzQ1Njc4OWFiY2RlZg==");
        assert_eq!(shadowsocks_psk_hash(&psk).len(), 16);
        assert_ne!(shadowsocks_psk_hash(&psk), shadowsocks_psk_hash(&psk[1..]));
        assert!(decode_shadowsocks_psk("not base64!").is_err());
    }
}
