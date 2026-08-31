//! Shadowsocks configuration types.

use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use serde::Deserialize;

use crate::shadowsocks::ShadowsocksCipher;

#[derive(Debug, Clone)]
pub enum ShadowsocksConfig {
    Legacy {
        cipher: ShadowsocksCipher,
        password: String,
    },
    Aead2022 {
        cipher: ShadowsocksCipher,
        key_bytes: Box<[u8]>,
        /// Identity PSKs, outermost first, from a colon-joined password.
        ///
        /// A client's way of saying which server it is speaking to when that server
        /// holds many users: it seals one identity header per key here, each naming the
        /// next, ending with `key_bytes`. Empty in the ordinary single-user case, which
        /// is every config without a colon in its password.
        ///
        /// Outbound-only. An inbound's own `key_bytes` *is* its identity PSK, and whose
        /// connection it is comes from the header rather than from its config.
        identity_keys: Box<[Box<[u8]>]>,
    },
}

impl ShadowsocksConfig {
    /// Decode one base64 2022 key, the way a config file spells it.
    ///
    /// Exposed because a control plane receives keys in exactly this form, and
    /// `shoes::dynamic::credential` re-exports this rather than choosing an alphabet
    /// of its own -- two spellings of "base64" would mean a key that works in a config
    /// file and not through the API.
    pub fn decode_key(encoded: &str) -> std::io::Result<Box<[u8]>> {
        BASE64
            .decode(encoded)
            .map(Vec::into_boxed_slice)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Failed to base64 decode password for 2022-blake3 cipher: {}",
                        e
                    ),
                )
            })
    }

    /// Encode one 2022 key the way a config file spells it.
    ///
    /// The inverse of [`Self::decode_key`], for a control plane that mints a key and
    /// has to hand it back for a client's config.
    pub fn encode_key(key: &[u8]) -> String {
        BASE64.encode(key)
    }

    /// Create a ShadowsocksConfig from cipher and password strings.
    /// Handles both legacy ciphers and 2022-blake3-* ciphers.
    pub fn from_fields(cipher: &str, password: &str) -> std::io::Result<Self> {
        match cipher.strip_prefix("2022-blake3-") {
            Some(stripped) => {
                let cipher: ShadowsocksCipher = stripped.try_into()?;
                // A 2022 password is one base64 key, or several joined by colons when a
                // client speaks through identity keys. The last is always its own.
                let mut keys = Vec::new();
                for segment in password.split(':') {
                    keys.push(Self::decode_key(segment)?);
                }
                let key_bytes = keys.pop().expect("split always yields a segment");
                Ok(ShadowsocksConfig::Aead2022 {
                    cipher,
                    key_bytes,
                    identity_keys: keys.into_boxed_slice(),
                })
            }
            None => {
                let cipher: ShadowsocksCipher = cipher.try_into()?;
                Ok(ShadowsocksConfig::Legacy {
                    cipher,
                    password: password.to_string(),
                })
            }
        }
    }

    /// Serialize cipher and password fields to a SerializeStruct.
    /// Used by custom serializers to flatten ShadowsocksConfig fields.
    pub fn serialize_fields<S: serde::ser::SerializeStruct>(
        &self,
        state: &mut S,
    ) -> Result<(), S::Error> {
        match self {
            ShadowsocksConfig::Legacy { cipher, password } => {
                state.serialize_field("cipher", cipher.name())?;
                state.serialize_field("password", password)?;
            }
            ShadowsocksConfig::Aead2022 {
                cipher,
                key_bytes,
                identity_keys,
            } => {
                let cipher_name = format!("2022-blake3-{}", cipher.name());
                state.serialize_field("cipher", &cipher_name)?;
                let password = identity_keys
                    .iter()
                    .map(|key| Self::encode_key(key))
                    .chain(std::iter::once(Self::encode_key(key_bytes)))
                    .collect::<Vec<_>>()
                    .join(":");
                state.serialize_field("password", &password)?;
            }
        }
        Ok(())
    }
}

impl<'de> serde::de::Deserialize<'de> for ShadowsocksConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ShadowsocksConfigTemp {
            cipher: String,
            password: String,
        }

        let temp = ShadowsocksConfigTemp::deserialize(deserializer)?;
        Self::from_fields(&temp.cipher, &temp.password).map_err(serde::de::Error::custom)
    }
}

impl serde::ser::Serialize for ShadowsocksConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ShadowsocksConfig", 2)?;
        self.serialize_fields(&mut state)?;
        state.end()
    }
}
