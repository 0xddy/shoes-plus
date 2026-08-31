use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use parking_lot::Mutex;
use rand::{Rng, RngExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::salt_checker::SaltChecker;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksUdpMode;
use crate::dynamic::{UserContext, UserRegistry, bind_connection_user, current_connection};
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session_with_meter};
use crate::resolver::Resolver;
use crate::socks_handler::{read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::inbound_replay::{ShadowsocksSaltFilter, new_shadowsocks_salt_filter};
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::util::write_all;

use super::blake3_key::Blake3Key;
use super::default_key::DefaultKey;
use super::eih;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream::ShadowsocksStream;
use super::shadowsocks_stream_type::ShadowsocksStreamType;
use super::shadowsocks_udp::ShadowsocksUdpCodecConfig;

/// What this handler does about identity headers, if anything.
///
/// Absent on every path shoes had before: a 2022 endpoint that speaks for exactly one
/// key sends no header and needs no registry, which is what a config file describes.
enum IdentityRole {
    /// An inbound serving many users. `identity_psk` is its own key -- the one all of
    /// its clients know -- and it opens a header whose contents name which of `users`'
    /// PSKs the session keys should come from.
    Server {
        identity_psk: Box<[u8]>,
        users: Arc<dyn UserRegistry>,
    },
    /// An outbound speaking to such an inbound. The chain runs from the outermost
    /// identity PSK to this client's own key, which is also the key it derives sessions
    /// from, so `chain.last()` is what a single-user client would have been given.
    Client { chain: Box<[Box<[u8]>]> },
}

impl std::fmt::Debug for IdentityRole {
    /// Written by hand so that key material stays out of logs. (The `key` field beside
    /// it is upstream's and is left as it is.)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server { users, .. } => f
                .debug_struct("Server")
                .field("num_users", &users.user_count())
                .finish(),
            Self::Client { chain } => f
                .debug_struct("Client")
                .field("chain_len", &chain.len())
                .finish(),
        }
    }
}

#[derive(Debug)]
pub struct ShadowsocksTcpHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022: bool,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    udp_mode: ShadowsocksUdpMode,
    udp_codec_config: Option<ShadowsocksUdpCodecConfig>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
    /// Set only for the two multi-user constructors; see [`IdentityRole`].
    identity: Option<IdentityRole>,
}

impl ShadowsocksTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_mode: if udp_enabled {
                ShadowsocksUdpMode::Uot
            } else {
                ShadowsocksUdpMode::Disabled
            },
            udp_codec_config: None,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            identity: None,
        }
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_mode: ShadowsocksUdpMode,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        let udp_codec_config = (udp_mode == ShadowsocksUdpMode::Native)
            .then(|| ShadowsocksUdpCodecConfig::legacy(cipher, key.clone()));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_mode,
            udp_codec_config,
            proxy_selector: None,
            resolver: None,
            identity: None,
        }
    }

    /// Create one standalone AEAD2022 server handler with a fresh salt namespace.
    /// Built-in multi-bind/reload listeners inject one inbound-scoped filter into
    /// every handler generation instead.
    pub fn new_aead2022_server(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_aead2022_server_with_replay_filter(
            cipher,
            key_bytes,
            udp_enabled,
            proxy_selector,
            resolver,
            new_shadowsocks_salt_filter(),
        )
    }

    pub(crate) fn new_aead2022_server_with_replay_filter(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        salt_checker: ShadowsocksSaltFilter,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(salt_checker),
            udp_mode: if udp_enabled {
                ShadowsocksUdpMode::Uot
            } else {
                ShadowsocksUdpMode::Disabled
            },
            udp_codec_config: None,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            identity: None,
        }
    }

    /// Create a new AEAD2022 handler for client use
    pub fn new_aead2022_client(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_mode: ShadowsocksUdpMode,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        let udp_codec_config = if udp_mode == ShadowsocksUdpMode::Native {
            Some(
                ShadowsocksUdpCodecConfig::aead2022(
                    cipher,
                    vec![key_bytes.to_vec().into_boxed_slice()].into_boxed_slice(),
                )
                .expect("validated Shadowsocks 2022 client key"),
            )
        } else {
            None
        };
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(new_shadowsocks_salt_filter()),
            udp_mode,
            udp_codec_config,
            proxy_selector: None,
            resolver: None,
            identity: None,
        }
    }

    /// Create a new AEAD2022 handler for a server whose users come from a registry.
    ///
    /// `identity_psk` is the inbound's own key, the one every client of it knows.
    /// Whose connection it is comes from the identity header instead, which `users`
    /// resolves to that client's own PSK -- and it is that PSK, not this one, that the
    /// session keys derive from.
    ///
    /// This is the only 2022 arrangement that can serve more than one user, and it
    /// exists only for the AES ciphers, so an unsuitable cipher is refused here rather
    /// than accepted into an inbound nobody can reach.
    ///
    /// This public constructor represents one standalone inbound and creates a
    /// fresh salt namespace. Built-in listeners share an inbound-scoped filter
    /// across bind addresses and reload generations.
    pub fn new_aead2022_multi_user_server(
        cipher: ShadowsocksCipher,
        identity_psk: &[u8],
        users: Arc<dyn UserRegistry>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<Self> {
        Self::new_aead2022_multi_user_server_with_replay_filter(
            cipher,
            identity_psk,
            users,
            udp_enabled,
            proxy_selector,
            resolver,
            new_shadowsocks_salt_filter(),
        )
    }

    pub(crate) fn new_aead2022_multi_user_server_with_replay_filter(
        cipher: ShadowsocksCipher,
        identity_psk: &[u8],
        users: Arc<dyn UserRegistry>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        salt_checker: ShadowsocksSaltFilter,
    ) -> std::io::Result<Self> {
        if !eih::supports_identity_headers(&cipher) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "shadowsocks cipher {} has no identity headers, so it cannot serve more than one user",
                    cipher.name()
                ),
            ));
        }
        check_psk_len(&cipher, identity_psk.len())?;

        // `key` ends up holding the identity PSK, which is never used as a session key
        // on this path: `setup_server_stream` resolves one per connection.
        let mut handler = Self::new_aead2022_server_with_replay_filter(
            cipher,
            identity_psk,
            udp_enabled,
            proxy_selector,
            resolver,
            salt_checker,
        );
        handler.identity = Some(IdentityRole::Server {
            identity_psk: identity_psk.to_vec().into_boxed_slice(),
            users,
        });
        Ok(handler)
    }

    /// Create a new AEAD2022 handler for a client that names itself to a multi-user
    /// server.
    ///
    /// `identity_keys` runs outermost first and `key_bytes` is this client's own key,
    /// the one it derives sessions from. With no identity keys there is nothing to name,
    /// so nothing is sent and the handler is exactly what [`Self::new_aead2022_client`]
    /// would have built.
    pub fn new_aead2022_client_with_identity(
        cipher: ShadowsocksCipher,
        identity_keys: &[Box<[u8]>],
        key_bytes: &[u8],
        udp_mode: ShadowsocksUdpMode,
    ) -> std::io::Result<Self> {
        check_psk_len(&cipher, key_bytes.len())?;
        for key in identity_keys {
            check_psk_len(&cipher, key.len())?;
        }

        let mut handler = Self::new_aead2022_client(cipher, key_bytes, udp_mode);
        if identity_keys.is_empty() {
            return Ok(handler);
        }

        if !eih::supports_identity_headers(&handler.cipher) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "shadowsocks cipher {} has no identity headers, so it cannot use identity keys",
                    handler.cipher.name()
                ),
            ));
        }

        let chain = identity_keys
            .iter()
            .cloned()
            .chain(std::iter::once(key_bytes.to_vec().into_boxed_slice()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        if udp_mode == ShadowsocksUdpMode::Native {
            handler.udp_codec_config =
                Some(ShadowsocksUdpCodecConfig::aead2022(cipher, chain.clone())?);
        }
        handler.identity = Some(IdentityRole::Client { chain });
        Ok(handler)
    }

    /// Read the salt and identity header, and resolve them to the user whose key this
    /// connection speaks.
    ///
    /// Returns that user's session key together with the salt, which has to be handed
    /// to the record layer afterwards: it was consumed from the socket here, and it is
    /// what the session key is derived against on both sides. The user comes back
    /// too, **unauthenticated** -- see the note on counting at the end of this
    /// function.
    async fn resolve_identity(
        &self,
        stream: &mut Box<dyn AsyncStream>,
        identity_psk: &[u8],
        users: &Arc<dyn UserRegistry>,
    ) -> std::io::Result<(Arc<Box<dyn ShadowsocksKey>>, Box<[u8]>, Arc<UserContext>)> {
        let salt_len = self.cipher.salt_len();
        let mut prefix = [0u8; eih::MAX_SALT_LEN + eih::IDENTITY_HEADER_LEN];
        let prefix = &mut prefix[..salt_len + eih::IDENTITY_HEADER_LEN];
        stream.read_exact(prefix).await?;

        let (salt, header) = prefix.split_at(salt_len);
        // Always succeeds for a well-formed read: a wrong identity PSK yields 16 bytes
        // that name nobody rather than an error, and the lookup below is what turns
        // that into a refusal.
        let named = eih::open_identity_header(identity_psk, salt, header.try_into().unwrap())?;

        let identity = users.find_shadowsocks_psk_hash(&named).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unknown shadowsocks identity",
            )
        })?;

        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            identity.psk,
            self.cipher.algorithm().key_len(),
        )));

        // Deliberately neither counted nor bound here, unlike every other protocol
        // that authenticates in one step. An identity header is sealed under the
        // *inbound's* key, not the user's, so it names a user without proving the
        // sender is one: those bytes cross the wire in the clear and replaying them
        // costs nothing. Counting here let anyone who had recorded one of a user's
        // connections inflate that user's connection count, and bill them for
        // whatever garbage followed.
        //
        // The proof is the record layer: it checks the salt against the replay filter
        // and then opens the first chunk under a key derived from the user's own PSK.
        // `setup_server_stream` counts once that succeeds.
        Ok((key, salt.to_vec().into_boxed_slice(), identity.user))
    }

    /// Build the outgoing record layer, naming this client to the server when it
    /// speaks for a chain of keys.
    fn new_client_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut stream = ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        );

        if let Some(IdentityRole::Client { chain }) = &self.identity {
            // Sealed against the salt this stream is about to send, so what goes out
            // is good for this connection only.
            let headers = eih::seal_identity_headers(chain, stream.write_salt())?;
            stream.set_identity_headers(headers);
        }

        Ok(Box::new(stream))
    }
}

/// Reject a 2022 key of the wrong size here, where it can be reported, rather than
/// leaving it to the assertion inside `Blake3Key::create_session_key`.
fn check_psk_len(cipher: &ShadowsocksCipher, len: usize) -> std::io::Result<()> {
    if len != cipher.salt_len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "shadowsocks cipher {} needs {} byte keys, got {} bytes",
                cipher.name(),
                cipher.salt_len(),
                len
            ),
        ));
    }
    Ok(())
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Server
        } else {
            ShadowsocksStreamType::Aead
        };

        // A multi-user inbound resolves its session key per connection, out of the
        // identity header. The arms are spelled out rather than defaulted because
        // reaching the fallback with a `Server` role would mean accepting the inbound's
        // own identity PSK as somebody's session key.
        let (key, replayed_salt, named_user) = match &self.identity {
            Some(IdentityRole::Server {
                identity_psk,
                users,
            }) => {
                let (key, salt, user) = self
                    .resolve_identity(&mut server_stream, identity_psk, users)
                    .await?;
                (key, Some(salt), Some(user))
            }
            Some(IdentityRole::Client { .. }) | None => (self.key.clone(), None, None),
        };

        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            key,
            self.salt_checker.clone(),
        );

        if let Some(salt) = replayed_salt {
            // Put back what `resolve_identity` took, minus the identity header, which
            // has served its purpose and is not part of the record layer's handshake.
            server_stream.feed_initial_read_data(&salt)?;
        }

        let mut stream_reader = StreamReader::new_with_buffer_size(1024);

        // Blocks waiting for the location since the client always sends it before expecting a response.
        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        // The first read through the record layer is what proves the client holds
        // this user's PSK: it rejects a replayed salt outright and then opens a chunk
        // under a key only that PSK derives. Until it returns, the identity header
        // was a claim; from here it is a fact, so this is where the authentication is
        // counted and the connection starts being billed.
        if let Some(user) = named_user {
            // Everything read so far -- salt, header, the first chunk -- is already
            // counted against the inbound, and the meter hands it over.
            if !bind_connection_user(&user) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "user could not be admitted: removed, suspended, or at their connection limit",
                ));
            }
        }

        if self.aead2022 {
            let padding_len = stream_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {padding_len}"),
                    ));
                }
                stream_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");
            let udp_enabled = self.udp_mode != ShadowsocksUdpMode::Disabled;

            let initial_data = stream_reader.unparsed_data_owned();
            let meter = current_connection();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session_with_meter(
                    server_stream,
                    initial_data,
                    udp_enabled,
                    proxy_selector,
                    resolver,
                    meter,
                )
                .await
                {
                    debug!("Shadowsocks h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        // Checks for UDP-over-TCP (UoT) magic addresses
        if let Address::Hostname(host) = remote_location.address() {
            if self.udp_mode == ShadowsocksUdpMode::Disabled
                && (host == UOT_V1_MAGIC_ADDRESS || host == UOT_V2_MAGIC_ADDRESS)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "UDP-over-TCP is disabled for this Shadowsocks server",
                ));
            }
            if host == UOT_V1_MAGIC_ADDRESS {
                // UoT V1: Multi-destination UDP
                // Each packet has: ATYP + address + port + length + data
                let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

                // Feeds unparsed data since first UoT packet might be in same TCP segment
                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "Shadowsocks UoT V1: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    need_initial_flush: false,
                    proxy_selector: self
                        .proxy_selector
                        .clone()
                        .expect("proxy_selector required for server handler"),
                });
            } else if host == UOT_V2_MAGIC_ADDRESS {
                // UoT V2: Read request header first
                // Request: isConnect(u8) + ATYP + address + port
                // Note: V2 uses SOCKS address format (0x01=IPv4, 0x03=Domain, 0x04=IPv6),
                // NOT UoT address format!
                let is_connect = stream_reader.read_u8(&mut server_stream).await?;
                log::debug!("Shadowsocks UoT V2: is_connect = {}", is_connect);

                // Reads destination address using SOCKS address format
                let destination = read_location(&mut server_stream, &mut stream_reader).await?;
                log::debug!("Shadowsocks UoT V2: destination = {:?}", destination);

                if is_connect == 1 {
                    // V2 Connect mode: Single destination, length-prefixed packets only
                    // Reuse UotV2Stream which has identical format: length(u16be) + data
                    let unparsed_data = stream_reader.unparsed_data();
                    let mut uot_v2_stream = UotV2Stream::new(server_stream);
                    if !unparsed_data.is_empty() {
                        uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    return Ok(TcpServerSetupResult::BidirectionalUdp {
                        remote_location: destination,
                        stream: Box::new(uot_v2_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                } else {
                    // V2 Non-connect mode: Same as V1 (multi-destination)
                    let mut uot_stream = UotV1ServerStream::new_uot(server_stream);
                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        log::debug!(
                            "Shadowsocks UoT V2 non-connect: feeding {} bytes of initial data",
                            unparsed_data.len()
                        );
                        uot_stream.feed_initial_data(unparsed_data);
                    }

                    return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                        stream: Box::new(uot_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                    });
                }
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            // Lets the IV be written when data actually arrives rather than flushing here.
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_stream = self.new_client_stream(client_stream)?;

        let mut location_vec = write_location_to_vec(remote_location.location());

        if self.aead2022 {
            let location_len = location_vec.len();

            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);

            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);

            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;
        client_stream.flush().await?;

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_mode == ShadowsocksUdpMode::Uot
    }

    fn supports_native_udp(&self) -> bool {
        self.udp_mode == ShadowsocksUdpMode::Native
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use crate::uot::{UOT_V2_MAGIC_ADDRESS, UotV2Stream};

        let mut client_stream = self.new_client_stream(client_stream)?;

        // UoT V2 connect mode: Single destination. Writes magic address first.
        let magic_location =
            NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut location_vec = write_location_to_vec(&magic_location);

        if self.aead2022 {
            let location_len = location_vec.len();
            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);
            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);
            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;

        // Writes UoT V2 request header: isConnect(1) + SOCKS address
        let mut uot_header = Vec::with_capacity(64);
        uot_header.push(1u8); // isConnect = 1 (connect mode)
        let target_bytes = write_location_to_vec(target.location());
        uot_header.extend_from_slice(&target_bytes);
        write_all(&mut client_stream, &uot_header).await?;
        client_stream.flush().await?;

        // Uses UotV2Stream for length-prefixed packets
        let message_stream = UotV2Stream::new(client_stream);

        Ok(Box::new(message_stream))
    }

    async fn setup_client_native_udp(
        &self,
        client_stream: Box<dyn AsyncMessageStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_mode != ShadowsocksUdpMode::Native {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Shadowsocks native UDP is not enabled",
            ));
        }
        self.udp_codec_config
            .as_ref()
            .expect("native UDP client has codec key material")
            .wrap(client_stream, target.into_location())
    }
}
