//! Factory functions for creating TCP server handlers from config.

use std::net::IpAddr;
use std::sync::Arc;

use rustc_hash::FxHashMap;

use crate::anytls::{AnyTlsServerHandler, PaddingFactory};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{ClientChainHop, ClientConfig};
use crate::config::{
    ConfigSelection, RealityServerConfig, RuleConfig, ServerProxyConfig, ShadowTlsServerConfig,
    ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig, WebsocketServerConfig,
};
use crate::dynamic::{StaticUserRegistry, UserRegistry};
use crate::http_handler::HttpTcpServerHandler;
use crate::mixed_handler::MixedTcpServerHandler;
use crate::option_util::OneOrSome;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::reality::RealityServerTarget;
use crate::resolver::Resolver;
use crate::rustls_config_util::create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::ShadowsocksTcpHandler;
use crate::snell::snell_handler::SnellServerHandler;
use crate::socks_handler::SocksTcpServerHandler;
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tcp::inbound_replay::InboundReplayScope;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tls_server_handler::NaiveConfig;
use crate::tls_server_handler::{
    InnerProtocol, TlsServerHandler, TlsServerTarget, VisionVlessConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
use crate::vless::vless_server_handler::VlessTcpServerHandler;
use crate::vmess::VmessTcpServerHandler;
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

use super::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;

fn create_auth_credentials(
    username: Option<String>,
    password: Option<String>,
) -> Option<(String, String)> {
    match (&username, &password) {
        (None, None) => None,
        _ => Some((username.unwrap_or_default(), password.unwrap_or_default())),
    }
}

/// Registry for a protocol that authenticates by 16-byte uuid (VLESS, VMess).
///
/// An injected registry wins outright. Falling back to the config credential is
/// what keeps a plain config file behaving exactly as it did before registries
/// existed: one uuid, compared in constant time, nothing else accepted.
fn resolve_uuid_users(
    users: Option<&Arc<dyn UserRegistry>>,
    config_uuid: &str,
) -> Arc<dyn UserRegistry> {
    match users {
        Some(registry) => Arc::clone(registry),
        // The uuid was already validated during config load.
        None => StaticUserRegistry::single_uuid(config_uuid).expect("Invalid user_id UUID"),
    }
}

/// Registry for AnyTLS, which authenticates by the raw SHA-256 of a password.
///
/// Takes the whole config list rather than one credential, because AnyTLS is the
/// first protocol here whose config already declares several users. Without an
/// injected registry all of them are loaded into a static one, so an inbound that
/// listed three users in YAML still serves three.
fn resolve_anytls_users(
    users: Option<&Arc<dyn UserRegistry>>,
    config_users: &[crate::config::server::AnyTlsUserConfig],
) -> Arc<dyn UserRegistry> {
    match users {
        Some(registry) => Arc::clone(registry),
        None => {
            let mut registry = StaticUserRegistry::new();
            for (index, user) in config_users.iter().enumerate() {
                // A nameless config user is reported by position. Never by their
                // password: an id is not a secret -- it reaches logs and reports --
                // and `add_anytls_password` does not index on it, so using the
                // credential there bought nothing and leaked it. An empty id would
                // instead make two nameless users indistinguishable in a report,
                // which is what the position avoids.
                let fallback;
                let id = if user.name.is_empty() {
                    fallback = format!("anytls-user-{index}");
                    &fallback
                } else {
                    &user.name
                };
                registry.add_anytls_password(id, &user.password);
            }
            Arc::new(registry)
        }
    }
}

/// Registry for NaiveProxy, which authenticates by an HTTP Basic credential.
///
/// Like AnyTLS, its config is already a list, so without an injected registry every
/// declared user goes into a static one rather than just the first.
fn resolve_naive_users(
    users: Option<&Arc<dyn UserRegistry>>,
    config_users: &[crate::config::server::NaiveUserConfig],
) -> Arc<dyn UserRegistry> {
    match users {
        Some(registry) => Arc::clone(registry),
        None => {
            let mut registry = StaticUserRegistry::new();
            for user in config_users {
                // A nameless user falls back to their `username`, which is the same
                // thing dynamic mode reports: on a naive inbound the username *is*
                // the id, and unlike the password it is not a secret. An empty id
                // would make two nameless users indistinguishable in a report.
                let id = if user.name.is_empty() {
                    &user.username
                } else {
                    &user.name
                };
                registry.add_naive_user(id, &user.username, &user.password);
            }
            Arc::new(registry)
        }
    }
}

/// Registry for Trojan, which authenticates by the hex digest of a password.
fn resolve_trojan_users(
    users: Option<&Arc<dyn UserRegistry>>,
    config_password: &str,
) -> Arc<dyn UserRegistry> {
    match users {
        Some(registry) => Arc::clone(registry),
        None => StaticUserRegistry::single_trojan_password(config_password),
    }
}

/// Create a TCP server handler from config.
///
/// # Arguments
/// * `server_proxy_config` - The protocol configuration
/// * `client_proxy_selector` - Selector for outbound proxy routing
/// * `resolver` - DNS resolver
/// * `bind_ip` - Optional bind IP for handlers that need it (e.g., Socks5 UDP, Mixed)
/// * `users` - Optional externally managed user registry for this inbound
///
/// The `bind_ip` is required for:
/// - `Socks` with `udp_enabled: true` (for UDP ASSOCIATE)
/// - `Mixed` with `udp_enabled: true` (for UDP ASSOCIATE)
///
/// `users` is inherited by every nested protocol, so a VLESS handler inside TLS
/// inside WebSocket authenticates against the same registry as the inbound that
/// owns it. When it is `None`, each authenticating protocol builds an immutable
/// registry from its own config credential; when it is `Some`, that registry is the
/// only authority and the config credential is ignored.
///
/// This compatibility constructor creates a fresh replay namespace and therefore
/// represents one standalone inbound handler. Built-in listeners use the
/// inbound-scoped factory below so multiple bind IPs and reload generations share
/// VMess/Shadowsocks replay protection; callers should prefer the listener APIs
/// instead of invoking this constructor separately for one logical inbound.
pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
) -> Box<dyn TcpServerHandler> {
    let replay_scope = InboundReplayScope::new(Default::default());
    create_tcp_server_handler_with_replay_state(
        server_proxy_config,
        client_proxy_selector,
        resolver,
        bind_ip,
        users,
        &replay_scope,
    )
}

/// Keeps the complete replay namespace alive for as long as an accepted handler
/// can still perform a VMess/Shadowsocks authentication.
///
/// The protocol-specific handlers retain their individual filter Arcs. This outer
/// owner is additionally required so the engine's weak live-generation registry can
/// recover the whole namespace when the same tag is gracefully rebuilt.
struct ReplayScopedTcpServerHandler {
    inner: Box<dyn TcpServerHandler>,
    _replay_scope: InboundReplayScope,
}

impl std::fmt::Debug for ReplayScopedTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReplayScopedTcpServerHandler")
            .field(&self.inner)
            .finish()
    }
}

#[async_trait::async_trait]
impl TcpServerHandler for ReplayScopedTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn crate::async_stream::AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.inner.setup_server_stream(server_stream).await
    }
}

/// Build one handler generation while retaining the replay namespace of its
/// inbound. Startup passes the same state to every bind address and reload passes
/// it to every replacement generation.
pub(crate) fn create_tcp_server_handler_with_replay_state(
    server_proxy_config: ServerProxyConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
    replay_state: &InboundReplayScope,
) -> Box<dyn TcpServerHandler> {
    let handler: Box<dyn TcpServerHandler> = match server_proxy_config {
        ServerProxyConfig::Http { username, password } => Box::new(HttpTcpServerHandler::new(
            create_auth_credentials(username, password),
            client_proxy_selector.clone(),
        )),
        ServerProxyConfig::Socks {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(SocksTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Mixed {
            username,
            password,
            udp_enabled,
        } => {
            // Use 0.0.0.0 as default if bind_ip not provided
            let ip = bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            Box::new(MixedTcpServerHandler::new(
                create_auth_credentials(username, password),
                udp_enabled,
                ip,
                client_proxy_selector.clone(),
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } => match config {
            ShadowsocksConfig::Legacy { cipher, password } => {
                Box::new(ShadowsocksTcpHandler::new_server(
                    cipher,
                    &password,
                    udp_enabled,
                    client_proxy_selector.clone(),
                    resolver.clone(),
                ))
            }
            ShadowsocksConfig::Aead2022 {
                cipher,
                key_bytes,
                identity_keys,
            } => {
                // Outbound-only, and `validate_server_proxy_config` refuses a
                // server config that carries any -- so there is nothing to do with
                // them here beyond naming why they are ignored.
                let _ = identity_keys;
                match users {
                    // Many users, told apart by the identity header each one sends. The
                    // inbound's own key opens the header; the session keys come from
                    // whichever user it named.
                    Some(users) => Box::new(
                        ShadowsocksTcpHandler::new_aead2022_multi_user_server_with_replay_filter(
                            cipher,
                            &key_bytes,
                            users.clone(),
                            udp_enabled,
                            client_proxy_selector.clone(),
                            resolver.clone(),
                            replay_state.shadowsocks_salts(),
                        )
                        .expect("Invalid multi-user shadowsocks inbound"),
                    ),
                    None => Box::new(
                        ShadowsocksTcpHandler::new_aead2022_server_with_replay_filter(
                            cipher,
                            &key_bytes,
                            udp_enabled,
                            client_proxy_selector.clone(),
                            resolver.clone(),
                            replay_state.shadowsocks_salts(),
                        ),
                    ),
                }
            }
        },
        ServerProxyConfig::Snell {
            cipher,
            password,
            udp_enabled,
        } => Box::new(SnellServerHandler::new(
            cipher.as_str().try_into().unwrap(),
            &password,
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
        )),
        ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } => Box::new(VlessTcpServerHandler::new(
            resolve_uuid_users(users, &user_id),
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
            fallback,
        )),
        ServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => Box::new(TrojanTcpHandler::new_server(
            resolve_trojan_users(users, &password),
            &shadowsocks,
            client_proxy_selector.clone(),
            resolver.clone(),
        )),
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            let mut all_targets = tls_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_tls_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            users,
                            replay_state,
                        ),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            let default_tls_target = default_tls_target.map(|config| {
                create_tls_server_target(
                    *config,
                    client_proxy_selector,
                    resolver,
                    bind_ip,
                    users,
                    replay_state,
                )
            });
            let shadowtls_targets = shadowtls_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_shadow_tls_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            users,
                            replay_state,
                        ),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(shadowtls_targets);
            let reality_server_targets = reality_targets
                .into_iter()
                .map(|(sni, config)| {
                    (
                        sni,
                        create_reality_server_target(
                            config,
                            client_proxy_selector,
                            resolver,
                            bind_ip,
                            users,
                            replay_state,
                        ),
                    )
                })
                .collect::<FxHashMap<String, TlsServerTarget>>();
            all_targets.extend(reality_server_targets);
            Box::new(TlsServerHandler::new(
                all_targets,
                default_tls_target,
                tls_buffer_size,
                resolver.clone(),
            ))
        }
        ServerProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
        } => Box::new(VmessTcpServerHandler::new_with_replay_filter(
            &cipher,
            resolve_uuid_users(users, &user_id),
            udp_enabled,
            client_proxy_selector.clone(),
            resolver.clone(),
            replay_state.vmess_auth_ids(),
        )),
        ServerProxyConfig::Websocket { targets } => {
            let server_targets: Vec<WebsocketServerTarget> = targets
                .into_vec()
                .into_iter()
                .map(|config| {
                    create_websocket_server_target(
                        config,
                        client_proxy_selector,
                        resolver,
                        bind_ip,
                        users,
                        replay_state,
                    )
                })
                .collect::<Vec<_>>();
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        ServerProxyConfig::PortForward { targets } => {
            let targets = targets.into_vec();
            Box::new(PortForwardServerHandler::new(
                targets,
                client_proxy_selector.clone(),
            ))
        }
        ServerProxyConfig::Anytls {
            // Renamed rather than destructured as `users`, which would shadow the
            // registry parameter of the same name for the rest of this arm.
            users: config_users,
            padding_scheme,
            udp_enabled,
            fallback,
        } => {
            let anytls_users = resolve_anytls_users(users, &config_users.into_vec());

            let padding = if let Some(scheme_lines) = padding_scheme {
                let scheme_str = scheme_lines.join("\n");
                Arc::new(
                    PaddingFactory::new(scheme_str.as_bytes())
                        .expect("Invalid padding scheme (should be validated during config load)"),
                )
            } else {
                PaddingFactory::default_factory()
            };

            // AnyTLS spawns its own task and returns AlreadyHandled, so it needs the proxy
            // provider directly (it won't inherit from outer handler through TcpForward)
            Box::new(AnyTlsServerHandler::new(
                anytls_users,
                padding,
                resolver.clone(),
                Arc::clone(client_proxy_selector),
                udp_enabled,
                fallback,
            ))
        }
        ServerProxyConfig::Naiveproxy { .. } => {
            // This should be caught at config validation time
            unreachable!(
                "NaiveProxy must be used inside a TLS or Reality protocol - \
                 config validation should have rejected this"
            )
        }
        unknown_config => {
            panic!("Unsupported TCP proxy config: {unknown_config:?}")
        }
    };
    Box::new(ReplayScopedTcpServerHandler {
        inner: handler,
        _replay_scope: replay_state.clone(),
    })
}

fn create_override_selector(
    rules: Vec<RuleConfig>,
    parent: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
) -> Arc<ClientProxySelector> {
    Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
        rules,
        resolver.clone(),
        parent.sniff_policy(),
    ))
}

fn create_tls_server_target(
    tls_server_config: TlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
    replay_state: &InboundReplayScope,
) -> TlsServerTarget {
    let TlsServerConfig {
        cert,
        key,
        alpn_protocols,
        client_ca_certs,
        client_fingerprints,
        vision,
        protocol,
        override_rules,
    } = tls_server_config;

    // Certificates are already embedded as PEM data during config validation
    let cert_bytes = cert.as_bytes().to_vec();
    let key_bytes = key.as_bytes().to_vec();

    let client_ca_certs = client_ca_certs
        .into_iter()
        .map(|cert| cert.as_bytes().to_vec())
        .collect();

    // For NaiveProxy, hardcode ALPN to h2 and http/1.1
    let is_naive = matches!(protocol, ServerProxyConfig::Naiveproxy { .. });
    let effective_alpn: Vec<String> = if is_naive {
        let naive_alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let user_alpn = alpn_protocols.into_vec();
        if user_alpn != naive_alpn {
            log::warn!(
                "NaiveProxy requires ALPN [\"h2\", \"http/1.1\"], ignoring user-specified {:?}",
                user_alpn
            );
        }
        naive_alpn
    } else {
        alpn_protocols.into_vec()
    };

    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        client_ca_certs,
        &effective_alpn,
        &client_fingerprints.into_vec(),
    ));

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        create_override_selector(rules, client_proxy_selector, resolver)
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        // Renamed rather than destructured as `users`, which would shadow the
        // registry parameter of the same name for the rest of this block.
        users: config_users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        InnerProtocol::Naive(NaiveConfig {
            users: resolve_naive_users(users, &config_users.into_vec()),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } = &protocol
        {
            InnerProtocol::VisionVless(VisionVlessConfig {
                users: resolve_uuid_users(users, user_id),
                udp_enabled: *udp_enabled,
                fallback: fallback.clone(),
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        let handler = create_tcp_server_handler_with_replay_state(
            protocol,
            &effective_selector,
            resolver,
            bind_ip,
            users,
            replay_state,
        );
        InnerProtocol::Normal(handler)
    };

    TlsServerTarget::Tls {
        server_config,
        effective_selector,
        inner_protocol,
    }
}

fn create_shadow_tls_server_target(
    shadow_tls_server_config: ShadowTlsServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
    replay_state: &InboundReplayScope,
) -> TlsServerTarget {
    let ShadowTlsServerConfig {
        password,
        handshake,
        protocol,
        override_rules,
    } = shadow_tls_server_config;

    let target_handshake = match handshake {
        ShadowTlsServerHandshakeConfig::Local(handshake) => {
            // Certificates are already embedded as PEM data during config validation
            let cert_bytes = handshake.cert.as_bytes().to_vec();
            let key_bytes = handshake.key.as_bytes().to_vec();

            let client_ca_certs = handshake
                .client_ca_certs
                .into_iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect();

            let server_config = Arc::new(create_server_config(
                &cert_bytes,
                &key_bytes,
                client_ca_certs,
                &handshake.alpn_protocols.into_vec(),
                &handshake.client_fingerprints.into_vec(),
            ));

            ShadowTlsServerTargetHandshake::new_local(server_config)
        }
        ShadowTlsServerHandshakeConfig::Remote(handshake) => {
            // Build ClientProxyChain from client_chain
            // client_chain is guaranteed to be non-empty (defaults to direct hop)
            let client_chain = build_client_proxy_chain(handshake.client_chain, resolver.clone());
            ShadowTlsServerTargetHandshake::new_remote(handshake.address, client_chain)
        }
    };

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        create_override_selector(rules, client_proxy_selector, resolver)
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_tcp_server_handler_with_replay_state(
        protocol,
        &effective_selector,
        resolver,
        bind_ip,
        users,
        replay_state,
    );

    TlsServerTarget::ShadowTls(ShadowTlsServerTarget::new(
        password,
        target_handshake,
        handler,
    ))
}

fn create_reality_server_target(
    reality_server_config: RealityServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
    replay_state: &InboundReplayScope,
) -> TlsServerTarget {
    let RealityServerConfig {
        private_key,
        short_ids,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites,
        vision,
        protocol,
        dest_client_chain,
        override_rules,
    } = reality_server_config;

    // Decode private key from base64url (validated during config load)
    let private_key_bytes = crate::reality::decode_private_key(&private_key)
        .expect("Invalid REALITY private key (should be validated during config load)");

    // Decode short IDs from hex strings (validated during config load)
    // OneOrSome ensures at least one short_id is always present (default is all zeros)
    let short_id_bytes: Vec<[u8; 8]> = short_ids
        .into_vec()
        .into_iter()
        .map(|s| {
            crate::reality::decode_short_id(&s)
                .expect("Invalid REALITY short_id (should be validated during config load)")
        })
        .collect();

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        create_override_selector(rules, client_proxy_selector, resolver)
    } else {
        client_proxy_selector.clone()
    };

    // Create inner_protocol based on protocol type
    let inner_protocol = if let ServerProxyConfig::Naiveproxy {
        // Renamed rather than destructured as `users`, which would shadow the
        // registry parameter of the same name for the rest of this block.
        users: config_users,
        padding,
        fallback,
        udp_enabled,
    } = protocol
    {
        // NaiveProxy uses hyper-based handler
        InnerProtocol::Naive(NaiveConfig {
            users: resolve_naive_users(users, &config_users.into_vec()),
            fallback_path: fallback.map(|f| f.0),
            udp_enabled,
            padding_enabled: padding,
        })
    } else if vision {
        // Vision requires VLESS protocol (validated in config/mod.rs)
        if let ServerProxyConfig::Vless {
            user_id,
            udp_enabled,
            fallback,
        } = &protocol
        {
            InnerProtocol::VisionVless(VisionVlessConfig {
                users: resolve_uuid_users(users, user_id),
                udp_enabled: *udp_enabled,
                fallback: fallback.clone(),
            })
        } else {
            unreachable!("Vision requires VLESS (should be validated during config load)")
        }
    } else {
        let handler = create_tcp_server_handler_with_replay_state(
            protocol,
            &effective_selector,
            resolver,
            bind_ip,
            users,
            replay_state,
        );
        InnerProtocol::Normal(handler)
    };

    // Build dest client chain: if specified use it, otherwise default to direct
    let dest_client_chain = {
        let hops = dest_client_chain.into_vec();
        if hops.is_empty() {
            // Default to direct connection
            build_client_proxy_chain(
                OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                    ClientConfig::default(),
                ))),
                resolver.clone(),
            )
        } else if hops.len() == 1 {
            build_client_proxy_chain(
                OneOrSome::One(hops.into_iter().next().unwrap()),
                resolver.clone(),
            )
        } else {
            build_client_proxy_chain(OneOrSome::Some(hops), resolver.clone())
        }
    };

    TlsServerTarget::Reality(RealityServerTarget {
        private_key: private_key_bytes,
        short_ids: short_id_bytes,
        dest,
        max_time_diff,
        min_client_version,
        max_client_version,
        cipher_suites: cipher_suites.into_vec(),
        effective_selector,
        inner_protocol,
        dest_client_chain,
    })
}

fn create_websocket_server_target(
    websocket_server_config: WebsocketServerConfig,
    client_proxy_selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind_ip: Option<IpAddr>,
    users: Option<&Arc<dyn UserRegistry>>,
    replay_state: &InboundReplayScope,
) -> WebsocketServerTarget {
    let WebsocketServerConfig {
        matching_path,
        matching_headers,
        ping_type,
        protocol,
        override_rules,
    } = websocket_server_config;

    let matching_headers = matching_headers.map(|h| {
        h.into_iter()
            .map(|(mut key, val)| {
                key.make_ascii_lowercase();
                (key, val)
            })
            .collect::<FxHashMap<_, _>>()
    });

    // Compute effective selector: if override_rules exist, create new selector; otherwise use parent's
    let effective_selector = if !override_rules.is_empty() {
        let rules = override_rules
            .map(ConfigSelection::unwrap_config)
            .into_vec();
        create_override_selector(rules, client_proxy_selector, resolver)
    } else {
        client_proxy_selector.clone()
    };

    let handler = create_tcp_server_handler_with_replay_state(
        protocol,
        &effective_selector,
        resolver,
        bind_ip,
        users,
        replay_state,
    );

    WebsocketServerTarget {
        matching_path,
        matching_headers,
        ping_type,
        handler,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::server::{AnyTlsUserConfig, NaiveUserConfig};
    use crate::dynamic::HandlerSlot;
    use crate::dynamic::credential::{naive_basic_credential, password_sha256};
    use crate::resolver::NativeResolver;

    #[test]
    fn override_rules_inherit_the_inbound_sniff_policy() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        for policy in [None, Some(true), Some(false)] {
            let parent = Arc::new(ClientProxySelector::with_sniff_policy(Vec::new(), policy));
            let child = create_override_selector(vec![RuleConfig::default()], &parent, &resolver);
            assert_eq!(child.sniff_policy(), policy);
        }
    }

    #[test]
    fn accepted_handler_owns_the_live_replay_scope_after_listener_drop() {
        let state = crate::dynamic::InboundReplayState::default();
        let scope = InboundReplayScope::new(state);
        let weak = scope.downgrade();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let handler: Arc<dyn TcpServerHandler> = create_tcp_server_handler_with_replay_state(
            ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            &selector,
            &resolver,
            None,
            None,
            &scope,
        )
        .into();
        let slot = HandlerSlot::new(handler, Arc::clone(&resolver));
        let (accepted_handler, accepted_resolver) = slot.load();

        drop(scope);
        drop(slot);
        assert!(
            weak.upgrade().is_some(),
            "an accepted handler must keep the namespace discoverable after its slot drops"
        );
        drop(accepted_handler);
        drop(accepted_resolver);
        assert!(
            weak.upgrade().is_none(),
            "the weak registry owner must become reclaimable after the last handler exits"
        );
    }

    /// NOTE(shoes-engine): a user's id reaches logs and reports -- the AnyTLS handler
    /// debug-logs it on every successful authentication -- so it must never be their
    /// credential. Config users may omit a name, and the fallback is what this guards.
    #[test]
    fn a_nameless_config_user_is_never_identified_by_their_secret() {
        let users = vec![
            AnyTlsUserConfig {
                name: String::new(),
                password: "hunter2".to_string(),
            },
            AnyTlsUserConfig {
                name: String::new(),
                password: "correcthorse".to_string(),
            },
            AnyTlsUserConfig {
                name: "named".to_string(),
                password: "third".to_string(),
            },
        ];
        let registry = resolve_anytls_users(None, &users);

        let first = registry
            .find_password_sha256(&password_sha256("hunter2"))
            .expect("the first user still authenticates");
        let second = registry
            .find_password_sha256(&password_sha256("correcthorse"))
            .expect("the second user still authenticates");
        let third = registry
            .find_password_sha256(&password_sha256("third"))
            .expect("the named user still authenticates");

        assert_ne!(&**first.id(), "hunter2");
        assert_ne!(&**second.id(), "correcthorse");
        // Positional, so two nameless users stay distinguishable in a report.
        assert_ne!(first.id(), second.id());
        // A name that was given is still what gets reported.
        assert_eq!(&**third.id(), "named");
    }

    #[test]
    fn a_nameless_naive_user_is_reported_by_their_username() {
        let users = vec![NaiveUserConfig {
            name: String::new(),
            username: "alice".to_string(),
            password: "hunter2".to_string(),
        }];
        let registry = resolve_naive_users(None, &users);

        let user = registry
            .find_naive_basic(&naive_basic_credential("alice", "hunter2"))
            .expect("the user still authenticates");
        // The username, which is half the credential but not the secret half, and is
        // what dynamic mode reports for the same user.
        assert_eq!(&**user.id(), "alice");
    }
}
