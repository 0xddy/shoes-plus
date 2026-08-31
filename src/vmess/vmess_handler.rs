use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_lc_rs::aead::{
    AES_128_GCM, Aad, BoundKey, CHACHA20_POLY1305, OpeningKey, SealingKey, UnboundKey,
};
use aws_lc_rs::cipher::{
    AES_128, EncryptingKey as CipherEncryptingKey, EncryptionContext, UnboundCipherKey,
};
use bytes::BytesMut;
use rand::{Rng, RngExt};
use shake::Shake128;
use shake::digest::{ExtendableOutput, Update};
use tokio::io::AsyncWriteExt;

use super::fnv1a::Fnv1aHasher;
use super::md5::{compute_md5, create_chacha_key};
use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::vmess_stream::{ReadHeaderInfo, VmessStream};
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::dynamic::{UserRegistry, bind_connection_user, current_connection};
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session_with_meter};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::inbound_replay::{
    VMESS_AUTH_ID_WINDOW, VmessAuthIdFilter, new_vmess_auth_id_filter,
};
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::{allocate_vec, write_all};
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpMessageStream;

const TAG_LEN: usize = 16;

// VMess protocol command types
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3; // MUX/XUDP mode

#[derive(Debug, Clone, PartialEq, Eq)]
enum DataCipher {
    Any,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl From<&str> for DataCipher {
    fn from(name: &str) -> Self {
        match name {
            "" | "any" => DataCipher::Any,
            "aes-128-gcm" => DataCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => DataCipher::ChaCha20Poly1305,
            "none" => DataCipher::None,
            _ => {
                panic!("Unknown cipher: {name}");
            }
        }
    }
}

/// How far a VMess auth id's sealed timestamp may be from this server's clock.
/// 120 seconds either way, which is what the protocol's other implementations allow
/// and what this crate's own client assumes when it picks a timestamp.
const AUTH_ID_CLOCK_SKEW: Duration = Duration::from_secs(120);

/// How long an admitted auth id has to be remembered for the replay check to have no
/// gap.
///
/// Twice the skew, not once, and the difference is the whole point. An auth id
/// carrying timestamp `T` is admissible for as long as `T` is within the skew of the
/// clock -- that is, across the whole interval `[T - skew, T + skew]`, which is two
/// skews wide. An attacker who copies one presented at the start of that interval can
/// present it again at the end. Remembering for only one skew would forget it exactly
/// halfway through the period the timestamp check still admits it, which is a replay
/// window rather than a replay filter.
///
/// The cost of the wider window is small and bounded, because what lands in the
/// filter is one entry per *admitted* connection rather than one per packet off the
/// wire.
const _: () = assert!(
    VMESS_AUTH_ID_WINDOW.as_secs() == 2 * AUTH_ID_CLOCK_SKEW.as_secs(),
    "an auth id stays admissible for two skews, so it must be remembered for two"
);

pub struct VmessTcpServerHandler {
    data_cipher: DataCipher,
    users: Arc<dyn UserRegistry>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    /// Auth ids seen inside [`VMESS_AUTH_ID_WINDOW`], so a recorded one cannot be used
    /// twice.
    ///
    /// Shared by every connection to this inbound, because that is the scope a
    /// replay crosses: an attacker records one client's handshake and opens their
    /// own connection with it.
    ///
    /// # Why this is not a memory hazard
    ///
    /// It is fed only *after* `find_vmess_auth_id` has recognised the value and the
    /// timestamp inside it has been found fresh. Those sixteen bytes are a user's
    /// key applied to a timestamp and a checksum, so a value that gets this far was
    /// either produced by someone holding the uuid or copied from someone who did.
    /// Random bytes fail the checksum and never reach the filter, which is what
    /// separates this from a filter fed by anything off the wire.
    auth_ids: VmessAuthIdFilter,
}

impl std::fmt::Debug for VmessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessTcpServerHandler")
            .field("data_cipher", &self.data_cipher)
            .field("udp_enabled", &self.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl VmessTcpServerHandler {
    /// Create one standalone VMess inbound handler with a fresh replay namespace.
    ///
    /// Built-in multi-bind/reload listeners inject their inbound-scoped filter via
    /// the internal constructor; constructing multiple public handlers does not
    /// make them one logical replay-protection scope.
    pub fn new(
        cipher_name: &str,
        users: Arc<dyn UserRegistry>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_with_replay_filter(
            cipher_name,
            users,
            udp_enabled,
            proxy_selector,
            resolver,
            new_vmess_auth_id_filter(),
        )
    }

    pub(crate) fn new_with_replay_filter(
        cipher_name: &str,
        users: Arc<dyn UserRegistry>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        auth_ids: VmessAuthIdFilter,
    ) -> Self {
        Self {
            data_cipher: cipher_name.into(),
            users,
            udp_enabled,
            proxy_selector,
            resolver,
            auth_ids,
        }
    }
}

#[async_trait]
impl TcpServerHandler for VmessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut stream_reader = StreamReader::new_with_buffer_size(8192);

        let mut cert_hash = [0u8; 16];
        stream_reader
            .read_slice_into(&mut server_stream, &mut cert_hash)
            .await?;

        // VMess sends no identifier, so the only way to learn whose connection this is
        // is to try each known user's key. The registry owns that search; what comes
        // back is the user and the instruction key the rest of this header is derived
        // from. `cert_hash` itself stays untouched -- the AEAD below authenticates the
        // original ciphertext, not the plaintext inside it.
        let identity = self.users.find_vmess_auth_id(&cert_hash).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AEAD authentication failed: unknown auth ID",
            )
        })?;
        let instruction_key = identity.instruction_key;

        // Judged here rather than in the registry, so that a user we do recognise is
        // told their clock is wrong instead of being reported as a stranger.
        let time_secs = identity.timestamp;
        let current_time_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let time_delta = time_secs.abs_diff(current_time_secs);
        if time_delta > AUTH_ID_CLOCK_SKEW.as_secs() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Hash timestamp is too old ({time_secs} is {time_delta} seconds old)"),
            ));
        }

        // Ordered after the timestamp check on purpose. A stale auth id is refused
        // without being remembered, so a client with a wrong clock cannot fill the
        // filter, and nothing is held that the timestamp check would reject anyway.
        if !self.auth_ids.lock().check_and_insert(&cert_hash) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth id has already been used",
            ));
        }

        let mut encrypted_payload_length = [0u8; 18];
        stream_reader
            .read_slice_into(&mut server_stream, &mut encrypted_payload_length)
            .await?;

        let mut nonce = [0u8; 8];
        stream_reader
            .read_slice_into(&mut server_stream, &mut nonce)
            .await?;

        let header_length_aead_key = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        // TODO: don't unwrap
        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_payload_length)
            .is_err()
        {
            return Err(std::io::Error::other(
                "failed to open encrypted header length",
            ));
        }

        // Only here is the client shown to hold this user's key. The auth id above
        // named them, but naming is not proving: those sixteen bytes carry no secret
        // an observer could not have copied off the wire, so counting or billing on
        // them alone let anyone who had seen one of this user's connections inflate
        // their connection count and their traffic by replaying the prefix.
        //
        // This is the first thing on the connection an attacker cannot produce
        // without the uuid. A replay of the whole recorded prefix -- auth id and
        // header together -- is by construction openable and would get past it, which
        // is why `auth_ids` above rejected that case before this point.
        // Everything read so far is already counted against the inbound; the meter
        // hands it over.
        if !bind_connection_user(&identity.user) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "user could not be admitted: removed, suspended, or at their connection limit",
            ));
        }

        let payload_length = u16::from_be_bytes(encrypted_payload_length[0..2].try_into().unwrap());

        let header_aead_key = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );

        let header_nonce = super::sha2::kdf(
            &instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let mut encrypted_header =
            allocate_vec(payload_length as usize + TAG_LEN).into_boxed_slice();

        stream_reader
            .read_slice_into(&mut server_stream, &mut encrypted_header)
            .await?;

        // TODO: don't unwrap
        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();

        let mut opening_key =
            OpeningKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_header)
            .is_err()
        {
            return Err(std::io::Error::other("failed to open encrypted header"));
        }

        let mut header_reader = AeadHeaderReader {
            server_stream,
            decrypted_header: encrypted_header,
            cursor: 0,
        };

        let mut fnv_hasher = Fnv1aHasher::new();

        // Read fixed 38-byte header first
        let mut fixed_header = [0u8; 38];
        header_reader.read_slice_into(&mut fixed_header)?;
        fnv_hasher.write(&fixed_header);

        if fixed_header[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid version {}", fixed_header[0]),
            ));
        }

        let command = fixed_header[37];

        log::trace!("VMess command: {}", command);

        // For MUX/XUDP command (0x03), there is NO destination in the VMess header
        // Destinations come in XUDP frames themselves
        let remote_location = if command == COMMAND_MUX {
            // Use a placeholder address for XUDP - actual destinations come from XUDP frames
            log::trace!(
                "VMess MUX/XUDP: No destination in VMess header (destinations come in XUDP frames)"
            );
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        } else {
            // For TCP/UDP commands, read port (2 bytes) and address
            let mut port_and_addr_type = [0u8; 3];
            header_reader.read_slice_into(&mut port_and_addr_type)?;
            fnv_hasher.write(&port_and_addr_type);

            let port = u16::from_be_bytes(port_and_addr_type[0..2].try_into().unwrap());

            match port_and_addr_type[2] {
                1 => {
                    // 4 byte ipv4 address
                    let mut address_bytes = [0u8; 4];
                    header_reader.read_slice_into(&mut address_bytes)?;
                    fnv_hasher.write(&address_bytes);

                    let v4addr = Ipv4Addr::new(
                        address_bytes[0],
                        address_bytes[1],
                        address_bytes[2],
                        address_bytes[3],
                    );
                    NetLocation::new(Address::Ipv4(v4addr), port)
                }
                2 => {
                    // domain name
                    let mut domain_name_len = [0u8; 1];
                    header_reader.read_slice_into(&mut domain_name_len)?;
                    fnv_hasher.write(&domain_name_len);

                    let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
                    header_reader.read_slice_into(&mut domain_name_bytes)?;
                    fnv_hasher.write(&domain_name_bytes);

                    let address_str = match std::str::from_utf8(&domain_name_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Failed to decode address: {e}"),
                            ));
                        }
                    };

                    // Although this is supposed to be a hostname, some clients will pass
                    // ipv4 and ipv6 addresses as well, so parse it rather than directly
                    // using Address:Hostname enum.
                    NetLocation::new(Address::from(address_str)?, port)
                }
                3 => {
                    // 16 byte ipv6 address
                    let mut address_bytes = [0u8; 16];
                    header_reader.read_slice_into(&mut address_bytes)?;
                    fnv_hasher.write(&address_bytes);

                    let v6addr = Ipv6Addr::new(
                        u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                        u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
                    );

                    NetLocation::new(Address::Ipv6(v6addr), port)
                }
                invalid_type => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid address type: {invalid_type}"),
                    ));
                }
            }
        };

        let margin_len: u8 = fixed_header[35] >> 4;
        log::trace!("VMess margin_len: {}, command: {}", margin_len, command);
        if margin_len > 0 {
            let mut margin_bytes = allocate_vec(margin_len as usize).into_boxed_slice();
            header_reader.read_slice_into(&mut margin_bytes)?;
            log::trace!("VMess margin_bytes: {:?}", &margin_bytes[..]);
            fnv_hasher.write(&margin_bytes);
        }

        let mut check_bytes = [0u8; 4];
        header_reader.read_slice_into(&mut check_bytes)?;
        log::trace!("VMess check_bytes: {:?}", &check_bytes);

        let expected_check_value = u32::from_be_bytes(check_bytes[0..4].try_into().unwrap());
        let actual_check_value = fnv_hasher.finish();
        log::trace!(
            "VMess FNV1a: expected={}, actual={}",
            expected_check_value,
            actual_check_value
        );
        if expected_check_value != actual_check_value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Bad fnv1a checksum, expected {expected_check_value}, got {actual_check_value}"
                ),
            ));
        }

        let server_stream = header_reader.into_stream();

        let data_encryption_iv: &[u8] = &fixed_header[1..17];
        let data_encryption_key: &[u8] = &fixed_header[17..33];
        let response_authentication_v = fixed_header[33];
        let option = fixed_header[34];

        if option & 0x01 != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Standard format data stream was not requested",
            ));
        }

        if option & 0x10 == 0x10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Auth length option is not supported",
            ));
        }

        let enable_chunk_masking = option & 0x04 == 0x04;
        let enable_global_padding = option & 0x08 == 0x08;

        if enable_global_padding && !enable_chunk_masking {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Global padding cannot be enabled without chunk masking",
            ));
        }

        // the developer docs have incorrect values for the data type,
        // see headers.pb.go in v2ray-core for the correct values.
        let requested_data_cipher = match fixed_header[35] & 0b1111 {
            1 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unsupported aes-128-cfb data cipher requested",
                ));
            }
            3 => DataCipher::Aes128Gcm,
            4 => DataCipher::ChaCha20Poly1305,
            5 => DataCipher::None,
            unknown_cipher_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested cipher: {unknown_cipher_type}"),
                ));
            }
        };

        if self.data_cipher != DataCipher::Any && requested_data_cipher != self.data_cipher {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Server only allows {:?} but client requested {:?}",
                    self.data_cipher, requested_data_cipher
                ),
            ));
        }

        let response_header: [u8; 4] = [
            response_authentication_v,
            0, // option
            0, // command
            0, // command length
        ];

        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

        let unbound_keys = match requested_data_cipher {
            // TODO: stop unwrapping
            DataCipher::Aes128Gcm => {
                // key is 16 bytes
                Some((
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                ))
            }
            DataCipher::ChaCha20Poly1305 => {
                // key is 32 bytes
                Some((
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(data_encryption_key))
                        .unwrap(),
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_header_key))
                        .unwrap(),
                ))
            }
            DataCipher::None => None,
            DataCipher::Any => unreachable!(),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        let (read_length_shake_reader, write_length_shake_reader) = if enable_chunk_masking {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(request_reader), Some(response_reader))
        } else {
            (None, None)
        };

        // store the response header as prefix bytes to read when we are streaming.
        // writing the response header immediately without reading causes Surge to fail with
        // "Got short header" error.
        // AEAD mode only
        let response_header_length_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Len Key"]);
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header Len IV"]);

        let mut encrypted_response_header = [0u8; 2 + TAG_LEN + 4 + TAG_LEN];

        // we know the size of response_header already.
        encrypted_response_header[1] = 4;

        // TODO: don't unwrap
        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_response_header[0..2])
            .unwrap();
        encrypted_response_header[2..2 + TAG_LEN].copy_from_slice(tag.as_ref());

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header IV"]);
        let unbound_key = UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4].copy_from_slice(&response_header);

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4],
            )
            .unwrap();
        encrypted_response_header[2 + TAG_LEN + 4..].copy_from_slice(tag.as_ref());

        let prefix_bytes = BytesMut::from(&encrypted_response_header[..]);

        match command {
            COMMAND_TCP => {
                // Check for h2mux magic destination
                if let Address::Hostname(host) = remote_location.address()
                    && host == MUX_DESTINATION_HOST
                    && remote_location.port() == MUX_DESTINATION_PORT
                {
                    // Create VMess stream with response header for h2mux
                    let mut vmess_stream = VmessStream::new(
                        server_stream,
                        false,
                        data_keys,
                        read_length_shake_reader,
                        write_length_shake_reader,
                        enable_global_padding,
                        Some(prefix_bytes),
                        None,
                    );

                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        vmess_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    let proxy_selector = self.proxy_selector.clone();
                    let resolver = self.resolver.clone();
                    let udp_enabled = self.udp_enabled;
                    let meter = current_connection();

                    tokio::spawn(async move {
                        if let Err(e) = handle_h2mux_session_with_meter(
                            Box::new(vmess_stream),
                            None, // initial data already fed to vmess_stream
                            udp_enabled,
                            proxy_selector,
                            resolver,
                            meter,
                        )
                        .await
                        {
                            log::debug!("VMess h2mux session ended: {}", e);
                        }
                    });

                    return Ok(TcpServerSetupResult::AlreadyHandled);
                }

                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    false, // is_udp = false
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                let server_stream = Box::new(vmess_stream);

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    // Wait until there is data to send the response header.
                    need_initial_flush: false,
                    connection_success_response: None,
                    initial_remote_data: None,
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            COMMAND_UDP => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }

                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    true, // is_udp = true
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                let server_stream = Box::new(vmess_stream);

                Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: false,
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                // For XUDP mode, use is_udp=false since XUDP wraps the stream
                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    false, // XUDP handles UDP multiplexing, VmessStream sees it as TCP-like
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                // Wrap VmessStream with XudpMessageStream for session multiplexing
                let xudp_stream = XudpMessageStream::new_with_resolver(
                    Box::new(vmess_stream),
                    self.resolver.clone(),
                );

                // No unparsed data to feed since VmessStream already consumed it
                // (XUDP framing starts after VMess header)

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            unknown_protocol_type => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown requested protocol: {unknown_protocol_type}"),
            )),
        }
    }
}

struct AeadHeaderReader {
    server_stream: Box<dyn AsyncStream>,
    decrypted_header: Box<[u8]>,
    cursor: usize,
}

impl AeadHeaderReader {
    fn read_slice_into(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let len = data.len();
        data.copy_from_slice(&self.decrypted_header[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(())
    }

    fn into_stream(self) -> Box<dyn AsyncStream> {
        self.server_stream
    }
}

pub struct VmessTcpClientHandler {
    data_cipher: DataCipher,
    instruction_key: [u8; 16],
    aead_encrypting_key: CipherEncryptingKey,
    udp_enabled: bool,
}

impl std::fmt::Debug for VmessTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessTcpClientHandler")
            .field("data_cipher", &self.data_cipher)
            .field("udp_enabled", &self.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl VmessTcpClientHandler {
    pub fn new(cipher_name: &str, user_id: &str, udp_enabled: bool) -> Self {
        let mut user_id_bytes = parse_uuid(user_id).unwrap();
        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let unbound_key = UnboundCipherKey::new(&AES_128, &derived_key[0..16]).unwrap();
        let aead_encrypting_key = CipherEncryptingKey::ecb(unbound_key).unwrap();

        Self {
            data_cipher: cipher_name.into(),
            aead_encrypting_key,
            instruction_key,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for VmessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // AEAD allows 120 second delta from the current time.
        // See authid.go in v2ray-core.
        let random_delta: u64 = rand::rng().random_range(0..241);
        let time_secs: u64 =
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

        let mut aead_bytes = [0u8; 16];
        let time_bytes = time_secs.to_be_bytes();
        aead_bytes[0..8].copy_from_slice(&time_bytes);

        rand::rng().fill_bytes(&mut aead_bytes[8..12]);

        let checksum_value = super::crc32::crc32c(&aead_bytes[0..12]);
        let checksum = checksum_value.to_be_bytes();
        aead_bytes[12..16].copy_from_slice(&checksum);

        self.aead_encrypting_key
            .less_safe_encrypt(&mut aead_bytes, EncryptionContext::None)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "AEAD auth ID encryption failed",
                )
            })?;

        let cert_hash = aead_bytes;

        // max length of encrypted header:
        // 41 (instructions up to addr type) + 256 (max domain name length 255 + 1 length byte) +
        // 15 (max margin length, 4 bits) + 4 (fnv1a hash) = 316 + TAG_LEN
        let mut header_bytes = [0u8; 316 + TAG_LEN];

        header_bytes[0] = 1;

        // this fills:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // construct everything where we need data_encryption_iv and data_encryption_key now,
        // because instructions_to_addr_type will be encrypted once it's filled.
        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

        let (read_length_shake_reader, write_length_shake_reader) = {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(response_reader), Some(request_reader))
        };

        let (encryption_method, unbound_keys) = match self.data_cipher {
            DataCipher::Aes128Gcm => {
                // key is 16 bytes
                (
                    3u8,
                    Some((
                        UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                        UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                    )),
                )
            }
            DataCipher::ChaCha20Poly1305 | DataCipher::Any => {
                // default to chacha.
                // key is 32 bytes
                (
                    4u8,
                    Some((
                        UnboundKey::new(
                            &CHACHA20_POLY1305,
                            &create_chacha_key(&response_header_key),
                        )
                        .unwrap(),
                        UnboundKey::new(
                            &CHACHA20_POLY1305,
                            &create_chacha_key(data_encryption_key),
                        )
                        .unwrap(),
                    )),
                )
            }
            DataCipher::None => (5u8, None),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        // continue filling out other parts of instructions_to_addr_type.

        // set options, standard format data stream and metadata obfuscation
        header_bytes[34] = 0x01 | 0x04;

        // only 4 bits, generate this now before our first await.
        let margin_len: u8 = rand::random::<u8>() & 0xf;
        header_bytes[35] = (margin_len << 4) | encryption_method;

        // specify tcp protocol
        header_bytes[37] = 1;

        let (remote_address, remote_port) = remote_location.into_location().unwrap_components();

        header_bytes[38] = (remote_port >> 8) as u8;
        header_bytes[39] = (remote_port & 0xff) as u8;

        let mut cursor = match remote_address {
            Address::Ipv4(v4addr) => {
                header_bytes[40] = 1;
                header_bytes[41..45].copy_from_slice(&v4addr.octets());
                45
            }
            Address::Ipv6(v6addr) => {
                header_bytes[40] = 3;
                header_bytes[41..57].copy_from_slice(&v6addr.octets());
                57
            }
            Address::Hostname(hostname) => {
                if hostname.len() > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Hostname is too long: {hostname}"),
                    ));
                }
                header_bytes[40] = 2;
                header_bytes[41] = hostname.len() as u8;
                header_bytes[42..42 + hostname.len()].copy_from_slice(hostname.as_bytes());
                42 + hostname.len()
            }
        };

        if margin_len > 0 {
            rand::rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        // AEAD mode only
        let mut encrypted_payload_length = [0u8; 18];
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        encrypted_payload_length[0] = (cursor >> 8) as u8;
        encrypted_payload_length[1] = (cursor & 0xff) as u8;

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_payload_length[0..2])
            .unwrap();

        encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

        let header_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );

        let header_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        // TODO: don't unwrap
        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut sealing_key =
            SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut header_bytes[0..cursor])
            .unwrap();

        header_bytes[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
        cursor += TAG_LEN;

        // Build complete AEAD request in a single buffer to avoid multiple writes as some
        // servers expect to read the entire header in one shot
        let total_len = 16 + 18 + 8 + cursor;
        let mut complete_request = Vec::with_capacity(total_len);
        complete_request.extend_from_slice(&cert_hash);
        complete_request.extend_from_slice(&encrypted_payload_length);
        complete_request.extend_from_slice(&nonce);
        complete_request.extend_from_slice(&header_bytes[0..cursor]);

        write_all(&mut client_stream, &complete_request).await?;

        // Flush the entire request.
        client_stream.flush().await?;

        // Info for reading the server response, which arrives along with the initial data.
        // Always AEAD mode
        let read_header_info = ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
        };

        let client_stream = Box::new(VmessStream::new(
            client_stream,
            false,
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            false,
            None,
            Some(read_header_info),
        ));

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled // VMess supports UDP-over-TCP tunneling when enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // VMess single-target UDP mode: Send VMess header with COMMAND_UDP (2)
        // and destination address. Uses VmessStream with is_udp=true.
        self.setup_udp_stream_impl(client_stream, target.into_location())
            .await
    }
}

impl VmessTcpClientHandler {
    /// Setup UDP stream for VMess single-target bidirectional UDP mode.
    /// Sends VMess header with COMMAND_UDP (2) and the destination address.
    async fn setup_udp_stream_impl(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // VMess single-target UDP mode: Send VMess header with COMMAND_UDP (2).
        // Same as TCP setup but with command=2 and is_udp=true for VmessStream.

        // AEAD allows 120 second delta from the current time.
        let random_delta: u64 = rand::rng().random_range(0..241);
        let time_secs: u64 =
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

        let mut aead_bytes = [0u8; 16];
        let time_bytes = time_secs.to_be_bytes();
        aead_bytes[0..8].copy_from_slice(&time_bytes);

        rand::rng().fill_bytes(&mut aead_bytes[8..12]);

        let checksum_value = super::crc32::crc32c(&aead_bytes[0..12]);
        let checksum = checksum_value.to_be_bytes();
        aead_bytes[12..16].copy_from_slice(&checksum);

        self.aead_encrypting_key
            .less_safe_encrypt(&mut aead_bytes, EncryptionContext::None)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "AEAD auth ID encryption failed",
                )
            })?;

        let cert_hash = aead_bytes;

        // max length of encrypted header (same as TCP):
        // 41 (instructions up to addr type) + 256 (max domain name length) +
        // 15 (max margin length) + 4 (fnv1a hash) = 316 + TAG_LEN
        let mut header_bytes = [0u8; 316 + TAG_LEN];

        header_bytes[0] = 1; // version

        // Fill encryption keys and response auth:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

        let (read_length_shake_reader, write_length_shake_reader) = {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(response_reader), Some(request_reader))
        };

        let (encryption_method, unbound_keys) = match self.data_cipher {
            DataCipher::Aes128Gcm => (
                3u8,
                Some((
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                )),
            ),
            DataCipher::ChaCha20Poly1305 | DataCipher::Any => (
                4u8,
                Some((
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_header_key))
                        .unwrap(),
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(data_encryption_key))
                        .unwrap(),
                )),
            ),
            DataCipher::None => (5u8, None),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        // Set options: standard format data stream and metadata obfuscation
        header_bytes[34] = 0x01 | 0x04;

        // Margin length (4 bits) + encryption method
        let margin_len: u8 = rand::random::<u8>() & 0xf;
        header_bytes[35] = (margin_len << 4) | encryption_method;

        // Reserved byte
        header_bytes[36] = 0;

        // Command = UDP (2) instead of TCP (1)
        header_bytes[37] = COMMAND_UDP;

        let (remote_address, remote_port) = remote_location.unwrap_components();

        header_bytes[38] = (remote_port >> 8) as u8;
        header_bytes[39] = (remote_port & 0xff) as u8;

        let mut cursor = match remote_address {
            Address::Ipv4(v4addr) => {
                header_bytes[40] = 1;
                header_bytes[41..45].copy_from_slice(&v4addr.octets());
                45
            }
            Address::Ipv6(v6addr) => {
                header_bytes[40] = 3;
                header_bytes[41..57].copy_from_slice(&v6addr.octets());
                57
            }
            Address::Hostname(hostname) => {
                if hostname.len() > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Hostname is too long: {hostname}"),
                    ));
                }
                header_bytes[40] = 2;
                header_bytes[41] = hostname.len() as u8;
                header_bytes[42..42 + hostname.len()].copy_from_slice(hostname.as_bytes());
                42 + hostname.len()
            }
        };

        if margin_len > 0 {
            rand::rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        // AEAD encryption of header
        let mut encrypted_payload_length = [0u8; 18];
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        encrypted_payload_length[0] = (cursor >> 8) as u8;
        encrypted_payload_length[1] = (cursor & 0xff) as u8;

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_payload_length[0..2])
            .unwrap();

        encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

        let header_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );

        let header_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut sealing_key =
            SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut header_bytes[0..cursor])
            .unwrap();

        header_bytes[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
        cursor += TAG_LEN;

        // Build complete AEAD request in a single buffer
        let total_len = 16 + 18 + 8 + cursor;
        let mut complete_request = Vec::with_capacity(total_len);
        complete_request.extend_from_slice(&cert_hash);
        complete_request.extend_from_slice(&encrypted_payload_length);
        complete_request.extend_from_slice(&nonce);
        complete_request.extend_from_slice(&header_bytes[0..cursor]);

        write_all(&mut client_stream, &complete_request).await?;
        client_stream.flush().await?;

        // Info for reading the server response
        let read_header_info = ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
        };

        // Create VmessStream with is_udp=true for bidirectional UDP
        let vmess_stream = VmessStream::new(
            client_stream,
            true, // is_udp = true for bidirectional UDP mode
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            false,
            None,
            Some(read_header_info),
        );

        Ok(Box::new(vmess_stream))
    }
}
