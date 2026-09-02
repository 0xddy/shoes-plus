//! Read-copy-update for a running inbound.
//!
//! Two things have to change while an inbound is serving traffic: the rules it
//! routes by, and whether it is listening at all. This module holds the mechanism
//! for both, and nothing about when to use it -- deciding that is the embedder's
//! job, since only the embedder knows what the caller asked for.
//!
//! # The grace period is the `Arc`
//!
//! An accept path reads its handler out of a [`HandlerSlot`] once per independently
//! routed flow: a TCP connection or a generic-QUIC bidirectional stream. Everything
//! the flow needs afterwards -- protocol settings, routing rules, TLS config --
//! hangs off it, so the flow is pinned to the generation it started on. A
//! [`HandlerSlot::store`] therefore cannot affect anything already running: it
//! only changes what the *next* `load` returns. The old handler is freed when its
//! last connection ends, which is the whole of the grace period; there is nothing
//! to count, drain or wait for.
//!
//! This is why the swap is at the handler rather than inside the rule list.
//! `ClientProxySelector::judge` returns a decision that borrows the rule it
//! matched, so a rule list that could change under a live borrow would need every
//! caller to hold a guard. Replacing the handler wholesale needs no such
//! cooperation, and it can change strictly more: protocol options and
//! certificates travel with it.
//!
//! # Stopping a listener without stopping its connections
//!
//! Every accepted connection is `tokio::spawn`ed, so a listener task is only ever
//! the accept loop -- cancelling it cannot reach the connections it started. That
//! is what makes [`ServerHandle::shutdown`] safe for TCP: the token stops the
//! loop, the listener is dropped, the port is free, and established sessions run
//! to completion against the rules they were accepted under.
//!
//! QUIC cannot be quite that clean. Its connections are multiplexed over one UDP
//! socket owned by the endpoint, so releasing the port *is* tearing the
//! connections down. The accept loops there stop accepting, refuse new handshakes
//! and then wait for the live connections to finish, bounded, before dropping the
//! endpoint -- see `quic_server::QUIC_DRAIN_TIMEOUT`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use log::debug;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{
    BindLocation, ConfigSelection, Hysteria2MasqueradeConfig, Hysteria2ObfsConfig, ServerConfig,
    ServerProxyConfig, TcpConfig, Transport,
};
use crate::dynamic::UserRegistry;
use crate::resolver::Resolver;
use crate::tcp::inbound_replay::{InboundReplayScope, InboundReplayState};
#[cfg(test)]
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector_with_sniff_policy;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server::ResolvedBind;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler_with_replay_state;

/// How long [`ServerHandle::shutdown`] waits for an *aborted* listener to
/// actually stop before it gives up and returns anyway.
///
/// Short on purpose: by this point the listener has already ignored both its
/// cancellation token and the caller's drain budget, so this is not a grace
/// period so much as the last chance for the runtime to run the cancellation.
const ABORT_GRACE: Duration = Duration::from_millis(250);

/// One generation of everything a logical flow is pinned to when it is accepted.
///
/// The resolver belongs here, next to the handler, and not in the accept loop. A
/// reload rebuilds the handler *with a new resolver* -- an inbound may carry its own
/// `dns` section -- so a loop holding its own copy from startup would hand every new
/// connection the rules from one generation and the DNS from another. The call would
/// report success and traffic would go on resolving the old way, which is the exact
/// failure the swap exists to avoid.
///
/// `ArcSwap` also needs a sized value, and `Arc<dyn TcpServerHandler>` is a fat
/// pointer, so this doubles as the indirection that used to be a newtype.
struct HandlerCell {
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
}

/// The handler an accept loop hands to each connection it accepts, replaceable
/// while the listener stays up.
///
/// See the module docs for why the swap lives here and what makes it safe.
pub struct HandlerSlot {
    current: ArcSwap<HandlerCell>,
    generation: AtomicU64,
}

impl HandlerSlot {
    pub fn new(handler: Arc<dyn TcpServerHandler>, resolver: Arc<dyn Resolver>) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(HandlerCell { handler, resolver }),
            generation: AtomicU64::new(0),
        })
    }

    /// What a logical flow being accepted now runs under: its handler and the resolver
    /// that handler's rules were built against.
    ///
    /// On the hot path, once per TCP connection or QUIC stream. `load` is a lock-free read; the clones
    /// are two uncontended refcount bumps, one of which the old
    /// `server_handler.clone()` already did and the other of which replaces the
    /// accept loop's own `resolver.clone()`.
    #[inline]
    pub fn load(&self) -> (Arc<dyn TcpServerHandler>, Arc<dyn Resolver>) {
        let current = self.current.load();
        (Arc::clone(&current.handler), Arc::clone(&current.resolver))
    }

    /// Install `handler` for connections accepted from here on, and return the
    /// generation it was given.
    ///
    /// Connections already running keep the handler they were accepted with.
    pub fn store(&self, handler: Arc<dyn TcpServerHandler>, resolver: Arc<dyn Resolver>) -> u64 {
        self.current
            .store(Arc::new(HandlerCell { handler, resolver }));
        self.generation.fetch_add(1, Ordering::Release) + 1
    }

    /// How many times this slot has been swapped since the listener started.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for HandlerSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerSlot")
            .field("generation", &self.generation())
            .field("handler", &self.current.load().handler)
            .finish()
    }
}

/// The routing rules an accept loop hands to each connection it accepts,
/// replaceable while the listener stays up.
///
/// [`HandlerSlot`] for protocols that never build a [`TcpServerHandler`]. Hysteria2
/// and TUIC authenticate inside their own QUIC accept loops, so there is no handler
/// to swap and nothing above the socket to hang rules off -- but the rules
/// themselves are still an `Arc` read once per new TCP flow or UDP association, which is the only
/// property the swap needs.
///
/// The safety argument is [`HandlerSlot`]'s, unchanged: the protocol `load`s once
/// per new logical flow and hands that `Arc` to every loop the flow fans out into,
/// so the flow is pinned to the generation it started on and a
/// [`store`](Self::store) can only change what the *next* `load` returns.
///
/// The rules and the resolver they were built against, swapped as one. Same
/// reasoning as [`HandlerCell`]: a logical flow must not mix generations.
struct SelectorCell {
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

pub struct SelectorSlot {
    current: ArcSwap<SelectorCell>,
    generation: AtomicU64,
}

impl SelectorSlot {
    pub fn new(selector: Arc<ClientProxySelector>, resolver: Arc<dyn Resolver>) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(SelectorCell { selector, resolver }),
            generation: AtomicU64::new(0),
        })
    }

    /// The rules for a connection being accepted now, and the resolver they route by.
    #[inline]
    pub fn load(&self) -> (Arc<ClientProxySelector>, Arc<dyn Resolver>) {
        let current = self.current.load();
        (Arc::clone(&current.selector), Arc::clone(&current.resolver))
    }

    /// Install `selector` for connections accepted from here on, and return the
    /// generation it was given.
    pub fn store(&self, selector: Arc<ClientProxySelector>, resolver: Arc<dyn Resolver>) -> u64 {
        self.current
            .store(Arc::new(SelectorCell { selector, resolver }));
        self.generation.fetch_add(1, Ordering::Release) + 1
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for SelectorSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectorSlot")
            .field("generation", &self.generation())
            .finish()
    }
}

/// What a QUIC-native inbound baked into its accept loop at start, and therefore
/// cannot change without being replaced.
///
/// Hysteria2 and TUIC read their settings once, before the loop starts, and pass
/// them by value into every connection it spawns. A [`SelectorSlot`] reaches the
/// rules and nothing else, so a reload that also changed `udp_enabled` would leave
/// UDP running after an operator turned it off -- fail-open, and invisible until
/// somebody noticed. Recording the settings here is what lets `check_reload` say so
/// instead.
///
/// A credential is recorded as `None` when a registry was injected: in dynamic mode
/// the config's credential is a placeholder the control plane regenerates on every
/// call, so it carries no intent to compare against. Without a registry it is the
/// real credential and changing it needs a new listener, so it is compared.
#[derive(Debug, Clone)]
struct FixedProtocol {
    settings: QuicNativeSettings,
    /// Recorded so that a reload extracts the incoming config the same way this one
    /// was extracted, rather than guessing from the values it finds.
    has_registry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QuicNativeSettings {
    Hysteria2 {
        password: Option<String>,
        udp_enabled: bool,
        /// Used by the per-endpoint controller factory and auth exchange. The
        /// selector slot cannot reach either after the listener has started.
        up_mbps: u64,
        down_mbps: u64,
        ignore_client_bandwidth: bool,
        /// Compared in full, password included, unlike the credential above.
        ///
        /// A registry can take over *authentication*, but nothing can take over
        /// obfuscation: it is applied beneath QUIC by the accept loop's socket,
        /// so changing it means rebuilding the listener. Hiding it the way
        /// `password` is hidden would let a reload silently keep the old one.
        obfs: Option<Hysteria2ObfsConfig>,
        /// The accept loop hands this to each new H3 connection, outside the rule
        /// slot, so it is fixed for the listener's lifetime too.
        masquerade: Option<Hysteria2MasqueradeConfig>,
    },
    Tuic {
        uuid: Option<String>,
        password: Option<String>,
        zero_rtt_handshake: bool,
    },
}

impl FixedProtocol {
    /// The settings of a QUIC-native protocol, or `None` for anything that reloads
    /// through a [`HandlerSlot`] and has nothing fixed.
    fn extract(protocol: &ServerProxyConfig, has_registry: bool) -> Option<Self> {
        QuicNativeSettings::extract(protocol, has_registry).map(|settings| Self {
            settings,
            has_registry,
        })
    }

    /// Whether `protocol` describes the same fixed listener, or which field says it
    /// does not.
    fn check(&self, protocol: &ServerProxyConfig) -> Result<(), &'static str> {
        match QuicNativeSettings::extract(protocol, self.has_registry) {
            Some(incoming) => match self.settings.first_difference(&incoming) {
                Some(field) => Err(field),
                None => Ok(()),
            },
            None => Err("type"),
        }
    }
}

impl QuicNativeSettings {
    fn extract(protocol: &ServerProxyConfig, has_registry: bool) -> Option<Self> {
        let hide = |value: &String| (!has_registry).then(|| value.clone());
        match protocol {
            ServerProxyConfig::Hysteria2 {
                password,
                udp_enabled,
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                obfs,
                masquerade,
            } => Some(Self::Hysteria2 {
                password: hide(password),
                udp_enabled: *udp_enabled,
                up_mbps: *up_mbps,
                down_mbps: *down_mbps,
                ignore_client_bandwidth: *ignore_client_bandwidth,
                obfs: obfs.clone(),
                masquerade: masquerade.clone(),
            }),
            ServerProxyConfig::TuicV5 {
                uuid,
                password,
                zero_rtt_handshake,
            } => Some(Self::Tuic {
                uuid: hide(uuid),
                password: hide(password),
                zero_rtt_handshake: *zero_rtt_handshake,
            }),
            _ => None,
        }
    }

    /// Names the first field that cannot be changed in place, for the error message.
    fn first_difference(&self, other: &Self) -> Option<&'static str> {
        match (self, other) {
            (
                Self::Hysteria2 {
                    password,
                    udp_enabled,
                    up_mbps,
                    down_mbps,
                    ignore_client_bandwidth,
                    obfs,
                    masquerade,
                },
                Self::Hysteria2 {
                    password: new_password,
                    udp_enabled: new_udp,
                    up_mbps: new_up_mbps,
                    down_mbps: new_down_mbps,
                    ignore_client_bandwidth: new_ignore_client_bandwidth,
                    obfs: new_obfs,
                    masquerade: new_masquerade,
                },
            ) => {
                if password != new_password {
                    Some("password")
                } else if udp_enabled != new_udp {
                    Some("udp_enabled")
                } else if up_mbps != new_up_mbps {
                    Some("up_mbps")
                } else if down_mbps != new_down_mbps {
                    Some("down_mbps")
                } else if ignore_client_bandwidth != new_ignore_client_bandwidth {
                    Some("ignore_client_bandwidth")
                } else if obfs != new_obfs {
                    Some("obfs")
                } else if masquerade != new_masquerade {
                    Some("masquerade")
                } else {
                    None
                }
            }
            (
                Self::Tuic {
                    uuid,
                    password,
                    zero_rtt_handshake,
                },
                Self::Tuic {
                    uuid: new_uuid,
                    password: new_password,
                    zero_rtt_handshake: new_zero_rtt,
                },
            ) => {
                if uuid != new_uuid {
                    Some("uuid")
                } else if password != new_password {
                    Some("password")
                } else if zero_rtt_handshake != new_zero_rtt {
                    Some("zero_rtt_handshake")
                } else {
                    None
                }
            }
            // A different variant entirely, which `check_reload` reports on its own.
            _ => Some("type"),
        }
    }
}

/// What the *listener* baked in at start, as opposed to what the handler carries.
///
/// [`FixedProtocol`] covers a QUIC-native inbound's protocol object. This covers the
/// layer beneath it, which no inbound can reload: an accept loop reads `tcp_settings`
/// once before it starts, a QUIC endpoint owns its certificate and ALPN list rather
/// than handing them to each connection, and a unix socket's path is the socket. A
/// reload rebuilds handlers and nothing else, so every one of these silently kept its
/// original value while the call reported success -- which is the worst possible
/// answer for a certificate rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FixedListener {
    /// Read once by the accept loop and passed to each accepted socket.
    no_delay: bool,
    /// `None` for a TCP listener.
    quic: Option<FixedQuic>,
    /// `None` for an address-backed listener. Compared by
    /// [`ServerHandle::check_bind_location`], which can otherwise only tell that
    /// both sides are unix sockets.
    path: Option<String>,
}

/// The endpoint's own settings, which live below the handler and outlive a swap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FixedQuic {
    cert: String,
    key: String,
    alpn_protocols: Vec<String>,
    client_ca_certs: Vec<String>,
    client_fingerprints: Vec<String>,
    num_endpoints: usize,
}

impl FixedListener {
    fn extract(config: &ServerConfig) -> Self {
        Self {
            // Defaulted the same way `start_tcp_servers` defaults it, so an omitted
            // section and an explicitly-default one compare equal rather than
            // reading as a change.
            no_delay: config
                .tcp_settings
                .as_ref()
                .map(|tcp| tcp.no_delay)
                .unwrap_or_else(|| TcpConfig::default().no_delay),
            quic: config.quic_settings.as_ref().map(|quic| FixedQuic {
                cert: quic.cert.clone(),
                key: quic.key.clone(),
                alpn_protocols: quic.alpn_protocols.iter().cloned().collect(),
                client_ca_certs: quic.client_ca_certs.iter().cloned().collect(),
                client_fingerprints: quic.client_fingerprints.iter().cloned().collect(),
                num_endpoints: quic.num_endpoints,
            }),
            path: match &config.bind_location {
                BindLocation::Path(path) => Some(path.display().to_string()),
                BindLocation::Address(_) => None,
            },
        }
    }

    /// Names the first setting that cannot be changed in place.
    ///
    /// The path is deliberately not named here: a changed listen location is
    /// [`ServerHandle::check_bind_location`]'s to report, and it words it better.
    fn first_difference(&self, other: &Self) -> Option<&'static str> {
        if self.no_delay != other.no_delay {
            return Some("tcp_settings.no_delay");
        }
        match (&self.quic, &other.quic) {
            (Some(mine), Some(theirs)) => {
                if mine.cert != theirs.cert {
                    Some("quic_settings.cert")
                } else if mine.key != theirs.key {
                    Some("quic_settings.key")
                } else if mine.alpn_protocols != theirs.alpn_protocols {
                    Some("quic_settings.alpn_protocols")
                } else if mine.client_ca_certs != theirs.client_ca_certs {
                    Some("quic_settings.client_ca_certs")
                } else if mine.client_fingerprints != theirs.client_fingerprints {
                    Some("quic_settings.client_fingerprints")
                } else if mine.num_endpoints != theirs.num_endpoints {
                    Some("quic_settings.num_endpoints")
                } else {
                    None
                }
            }
            (None, None) => None,
            // Gaining or losing the whole section. `check_reload` refuses a
            // transport change before this can be reached, so this is a config that
            // kept its transport and dropped the settings that transport needs.
            _ => Some("quic_settings"),
        }
    }
}

/// Which listener a [`HandlerSlot`] belongs to.
///
/// Handlers are shared per bind IP rather than per port: a protocol's state does
/// not depend on the port, but some of it does depend on the address it will hand
/// out to clients, so two ports on one IP share a handler and two IPs never do.
/// A unix socket has no address to share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HandlerKey {
    Ip(IpAddr),
    Path,
}

/// Whether an accepted physical stream can create independently routed work after
/// its handler generation was loaded. These protocols cannot safely use a
/// connection-level RCU swap: a long-lived mux session could keep admitting new
/// logical flows through a retired selector and resolver indefinitely.
fn protocol_has_post_accept_logical_flows(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Socks { udp_enabled, .. }
        | ServerProxyConfig::Mixed { udp_enabled, .. } => *udp_enabled,
        ServerProxyConfig::Hysteria2 { udp_enabled, .. } => *udp_enabled,
        ServerProxyConfig::TuicV5 { .. } => true,
        ServerProxyConfig::Shadowsocks { .. }
        | ServerProxyConfig::Snell { .. }
        | ServerProxyConfig::Vless { .. }
        | ServerProxyConfig::Trojan { .. }
        | ServerProxyConfig::Vmess { .. }
        | ServerProxyConfig::Anytls { .. }
        | ServerProxyConfig::Naiveproxy { .. } => true,
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            tls_targets
                .values()
                .any(|target| protocol_has_post_accept_logical_flows(&target.protocol))
                || default_tls_target
                    .as_ref()
                    .is_some_and(|target| protocol_has_post_accept_logical_flows(&target.protocol))
                || shadowtls_targets
                    .values()
                    .any(|target| protocol_has_post_accept_logical_flows(&target.protocol))
                || reality_targets
                    .values()
                    .any(|target| protocol_has_post_accept_logical_flows(&target.protocol))
        }
        ServerProxyConfig::Websocket { targets } => targets
            .iter()
            .any(|target| protocol_has_post_accept_logical_flows(&target.protocol)),
        _ => false,
    }
}

/// One started inbound: its listener tasks, their handler slots, and the two
/// cancellation trees that control it.
///
/// Dropping this does **not** stop anything. The listeners hold their own clones
/// of the token and the slots, so an embedder that never wants to reload or stop
/// can throw the handle away -- which is what [`crate::tcp::tcp_server::start_servers`]
/// does for a config-file run.
pub struct ServerHandle {
    transport: Transport,
    /// Every address this inbound listens on, in the order they were bound.
    /// Compared against a new config on reload: a different listen set is a
    /// different set of listeners, which is not something to change silently.
    binds: Vec<SocketAddr>,
    /// Empty for a protocol that authenticates inside its own accept loop
    /// (hysteria2, TUIC): those never go through a `TcpServerHandler`, so there is
    /// nothing here to swap. Those inbounds record a [`SelectorSlot`] instead.
    slots: Vec<(HandlerKey, Arc<HandlerSlot>)>,
    /// The rule slots of a QUIC-native inbound, one per bind address. Empty for
    /// everything that reloads through `slots`, whose rules travel inside the
    /// handler.
    selectors: Vec<Arc<SelectorSlot>>,
    /// What such an inbound cannot change in place. `None` until a selector slot is
    /// recorded, and for every handler-based inbound.
    fixed: Option<FixedProtocol>,
    /// What the *listener* baked in, which no inbound of any kind can change in
    /// place. `None` only for a handle nothing recorded settings on.
    fixed_listener: Option<FixedListener>,
    /// Whether this listener can produce new logical flows after physical accept.
    post_accept_logical_flows: bool,
    /// Replay protection belongs to the inbound, not to one bind address or one
    /// replaceable handler generation.
    replay_state: InboundReplayState,
    /// Live-generation owner retained by listeners and every handler handed to an
    /// accepted connection. Unlike `replay_state`, rollback leases do not own this.
    replay_scope: InboundReplayScope,
    /// Stops only the accept loops. Cancelling it is the graceful path: established
    /// connections are deliberately allowed to finish.
    cancel: CancellationToken,
    /// Parents every dynamically metered connection accepted by this handle, and is
    /// also observed by QUIC endpoints. It is intentionally independent of `cancel`
    /// so ordinary removal does not revoke established sessions.
    connection_cancel: CancellationToken,
    listeners: Mutex<Vec<JoinHandle<()>>>,
}

impl ServerHandle {
    pub(crate) fn new(transport: Transport, cancel: CancellationToken) -> Self {
        Self::new_with_replay_state(transport, cancel, InboundReplayState::default())
    }

    pub(crate) fn new_with_replay_state(
        transport: Transport,
        cancel: CancellationToken,
        replay_state: InboundReplayState,
    ) -> Self {
        Self::new_with_replay_scope(transport, cancel, InboundReplayScope::new(replay_state))
    }

    pub(crate) fn new_with_replay_scope(
        transport: Transport,
        cancel: CancellationToken,
        replay_scope: InboundReplayScope,
    ) -> Self {
        let replay_state = replay_scope.state();
        Self {
            transport,
            binds: Vec::new(),
            slots: Vec::new(),
            selectors: Vec::new(),
            fixed: None,
            fixed_listener: None,
            post_accept_logical_flows: false,
            replay_state,
            replay_scope,
            cancel,
            connection_cancel: CancellationToken::new(),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// The token every listener task in this handle selects on.
    pub(crate) fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The parent token for established connections owned by this inbound.
    ///
    /// A connection must take a child rather than cancel this token directly: user
    /// revocation remains connection-local, while a hard inbound removal propagates
    /// from this parent to every child at once.
    pub(crate) fn connection_token(&self) -> CancellationToken {
        self.connection_cancel.clone()
    }

    pub(crate) fn replay_state(&self) -> InboundReplayState {
        self.replay_state.clone()
    }

    pub(crate) fn replay_scope(&self) -> InboundReplayScope {
        self.replay_scope.clone()
    }

    pub(crate) fn push_listener(&mut self, handle: JoinHandle<()>) {
        self.listeners.lock().unwrap().push(handle);
    }

    pub(crate) fn push_address(&mut self, address: SocketAddr) {
        self.binds.push(address);
    }

    /// Record what this inbound's listeners baked in, so a later reload can refuse
    /// to change it rather than report success and ignore it.
    ///
    /// Called by the start functions with the config they are about to start from.
    pub(crate) fn record_listener_settings(&mut self, config: &ServerConfig) {
        self.fixed_listener = Some(FixedListener::extract(config));
        self.post_accept_logical_flows = protocol_has_post_accept_logical_flows(&config.protocol);
    }

    /// Record the slot serving `ip`, or return the one already recorded for it.
    ///
    /// Mirrors the `HashMap<IpAddr, _>` the start functions use to share a handler
    /// between two ports on one address.
    pub(crate) fn slot_for_ip(
        &mut self,
        ip: IpAddr,
        resolver: &Arc<dyn Resolver>,
        build: impl FnOnce() -> Arc<dyn TcpServerHandler>,
    ) -> Arc<HandlerSlot> {
        let key = HandlerKey::Ip(ip);
        if let Some((_, slot)) = self.slots.iter().find(|(k, _)| *k == key) {
            return Arc::clone(slot);
        }
        let slot = HandlerSlot::new(build(), Arc::clone(resolver));
        self.slots.push((key, Arc::clone(&slot)));
        slot
    }

    pub(crate) fn slot_for_path(
        &mut self,
        handler: Arc<dyn TcpServerHandler>,
        resolver: &Arc<dyn Resolver>,
    ) -> Arc<HandlerSlot> {
        let slot = HandlerSlot::new(handler, Arc::clone(resolver));
        self.slots.push((HandlerKey::Path, Arc::clone(&slot)));
        slot
    }

    /// Record a rule slot for a QUIC-native listener, along with the protocol
    /// settings that listener baked in.
    ///
    /// Unlike [`slot_for_ip`](Self::slot_for_ip) each bind address gets its own
    /// slot, because these listeners take the selector directly rather than sharing
    /// a handler; `reload` stores the same rebuilt selector into all of them, so
    /// they stay in step regardless.
    pub(crate) fn push_selector(
        &mut self,
        selector: Arc<ClientProxySelector>,
        resolver: &Arc<dyn Resolver>,
        protocol: &ServerProxyConfig,
        has_registry: bool,
    ) -> Arc<SelectorSlot> {
        let slot = SelectorSlot::new(selector, Arc::clone(resolver));
        self.selectors.push(Arc::clone(&slot));
        if self.fixed.is_none() {
            self.fixed = FixedProtocol::extract(protocol, has_registry);
        }
        slot
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.lock().unwrap().len()
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.binds
    }

    /// The highest generation any of this inbound's slots has reached, of either
    /// kind. An inbound only ever has one kind.
    pub fn generation(&self) -> u64 {
        let handlers = self.slots.iter().map(|(_, slot)| slot.generation());
        let selectors = self.selectors.iter().map(|slot| slot.generation());
        handlers.chain(selectors).max().unwrap_or(0)
    }

    /// Returns the first listener task that has already exited, if any.
    ///
    /// The start functions create their listener *inside* the spawned task and
    /// `.unwrap()` the result, so a failed bind does not come back as an `Err` --
    /// it shows up as a listener task that panicked. Checking for an early exit is
    /// how an embedder turns that into a synchronous error.
    pub fn take_dead_listener(&self) -> Option<JoinHandle<()>> {
        let mut listeners = self.listeners.lock().unwrap();
        let index = listeners.iter().position(|h| h.is_finished())?;
        Some(listeners.swap_remove(index))
    }

    /// Everything about a reload that can fail, without doing any of it.
    ///
    /// One config becomes several `ServerConfig`s when its groups are expanded, so
    /// an embedder reloading several handles at once can check them all first and
    /// keep the whole reload all-or-nothing rather than half applied.
    pub fn check_reload(&self, config: &ServerConfig) -> std::io::Result<()> {
        let resolved_bind = ResolvedBind::resolve(&config.bind_location)?;
        self.check_reload_resolved(config, &resolved_bind)
    }

    /// Validate a reload against a listen set resolved by the caller.
    ///
    /// Unlike [`Self::check_reload`], this path never invokes the platform name
    /// service. Embedders can therefore prepare the candidate before taking a
    /// control lock, then compare the exact same addresses against the running
    /// listeners inside their generation fence.
    pub fn check_reload_resolved(
        &self,
        config: &ServerConfig,
        resolved_bind: &ResolvedBind,
    ) -> std::io::Result<()> {
        if config.transport != self.transport {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot change transport in place: listening as {:?}, config says {:?}",
                    self.transport, config.transport
                ),
            ));
        }

        if self.slots.is_empty() && self.selectors.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this listener has nothing to swap in place, so its settings are \
                 fixed until it is replaced",
            ));
        }

        if self.post_accept_logical_flows
            || protocol_has_post_accept_logical_flows(&config.protocol)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this protocol can create new logical flows inside an accepted physical stream; replace the inbound so retired routing generations cannot keep admitting work",
            ));
        }

        // A selector slot reaches the rules and nothing else. Everything else in a
        // QUIC-native inbound's protocol object was read once, before its accept
        // loop started, so accepting a change to it here would report success for a
        // setting that never took effect.
        if let Some(fixed) = &self.fixed
            && let Err(field) = fixed.check(&config.protocol)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot change `{field}` in place: this listener reads it once, \
                     before it starts accepting. Only `rules` can be reloaded here; \
                     replace the inbound to change anything else"
                ),
            ));
        }

        // Below the handler: the accept loop's own settings, the QUIC endpoint's
        // certificate and ALPN list. A reload rebuilds handlers and nothing else, so
        // accepting a change to any of these would report a certificate rotation as
        // applied while the endpoint went on presenting the old one.
        if let Some(fixed) = &self.fixed_listener
            && let Some(field) = fixed.first_difference(&FixedListener::extract(config))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot change `{field}` in place: it belongs to the listener,                      which a reload does not rebuild. Replace the inbound to change it"
                ),
            ));
        }

        self.check_bind_location(&config.bind_location, resolved_bind)?;

        if config.rules.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no rules to route by",
            ));
        }

        Ok(())
    }

    /// Rebuild this inbound's handlers from `config` and swap them in.
    ///
    /// Nothing rebinds and no connection is disturbed: the listeners keep running
    /// and the connections they have already accepted keep the handler they
    /// started with. Only connections accepted after this returns see `config`.
    ///
    /// For a TCP inbound this covers everything above the socket -- routing rules,
    /// protocol options, TLS certificates -- because all of it is built into the
    /// handler. For QUIC the certificates are in the endpoint instead, so they are
    /// fixed until the listener is replaced.
    ///
    /// `users` must be the same registry the inbound was started with if it has
    /// one, so that online users and their counters survive the swap.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::check_reload`] rejects, and nothing else: once the checks
    /// pass, building and storing the handlers cannot fail.
    pub fn reload(
        &self,
        config: ServerConfig,
        resolver: &Arc<dyn Resolver>,
        users: Option<&Arc<dyn UserRegistry>>,
    ) -> std::io::Result<u64> {
        let resolved_bind = ResolvedBind::resolve(&config.bind_location)?;
        self.reload_resolved(config, resolver, users, &resolved_bind)
    }

    /// Rebuild and publish a handler using a caller-resolved listen set.
    ///
    /// This is the mutation half paired with [`Self::check_reload_resolved`]. It
    /// deliberately performs no hostname lookup, including during its defensive
    /// recheck immediately before the swap.
    pub fn reload_resolved(
        &self,
        config: ServerConfig,
        resolver: &Arc<dyn Resolver>,
        users: Option<&Arc<dyn UserRegistry>>,
        resolved_bind: &ResolvedBind,
    ) -> std::io::Result<u64> {
        self.check_reload_resolved(&config, resolved_bind)?;

        let ServerConfig {
            protocol,
            sniff,
            rules,
            ..
        } = config;

        let rules = rules.map(ConfigSelection::unwrap_config).into_vec();

        // Built once and shared by every handler, exactly as at start: the
        // selector is immutable, and sharing it means one rule set and one
        // routing cache per inbound rather than per bind IP.
        let selector = Arc::new(create_tcp_client_proxy_selector_with_sniff_policy(
            rules,
            resolver.clone(),
            sniff,
        ));

        // Everything fallible is done before the first store, so a rejected reload
        // leaves every slot on its previous generation rather than half of them.
        let mut rebuilt = Vec::with_capacity(self.slots.len());
        for (key, slot) in &self.slots {
            let bind_ip = match key {
                HandlerKey::Ip(ip) => Some(*ip),
                HandlerKey::Path => None,
            };
            let handler: Arc<dyn TcpServerHandler> = create_tcp_server_handler_with_replay_state(
                protocol.clone(),
                &selector,
                resolver,
                bind_ip,
                users,
                &self.replay_scope,
            )
            .into();
            rebuilt.push((slot, handler));
        }

        let mut generation = 0;
        for (slot, handler) in rebuilt {
            // The resolver goes in with the handler, so a connection cannot be
            // accepted under one generation's rules and route by another's DNS.
            generation = generation.max(slot.store(handler, Arc::clone(resolver)));
        }
        // The same selector into every slot: they are per bind address only because
        // each QUIC-native listener holds its own, not because they can differ.
        for slot in &self.selectors {
            generation = generation.max(slot.store(Arc::clone(&selector), Arc::clone(resolver)));
        }

        debug!(
            "reloaded {} handler slot(s) and {} rule slot(s) on {:?} to generation {generation}",
            self.slots.len(),
            self.selectors.len(),
            self.binds
        );

        Ok(generation)
    }

    /// Rejects a config whose listen set is not the one this handle is serving.
    fn check_bind_location(
        &self,
        bind_location: &BindLocation,
        resolved_bind: &ResolvedBind,
    ) -> std::io::Result<()> {
        match (bind_location, resolved_bind) {
            (BindLocation::Address(_), ResolvedBind::Addresses(addresses)) => {
                let mut wanted = addresses.clone();
                wanted.sort();
                wanted.dedup();

                let mut running = self.binds.clone();
                running.sort();
                running.dedup();

                if wanted != running {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "cannot change the listen set in place: listening on {}, config says {}",
                            display_addresses(&running),
                            display_addresses(&wanted)
                        ),
                    ));
                }
                Ok(())
            }
            (BindLocation::Path(path), ResolvedBind::Path(resolved_path)) => {
                if path != resolved_path {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "resolved unix bind {} does not match configured path {}",
                            resolved_path.display(),
                            path.display()
                        ),
                    ));
                }
                if !self.slots.iter().any(|(key, _)| *key == HandlerKey::Path) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot move from an address to a unix socket in place",
                    ));
                }
                // Being a unix socket is not enough: the path *is* the socket, so a
                // different one is a different listener. Without this, moving from
                // `/tmp/a` to `/tmp/b` reported success and went on serving `/tmp/a`.
                let wanted = path.display().to_string();
                match self.fixed_listener.as_ref().and_then(|f| f.path.as_deref()) {
                    Some(running) if running == wanted => Ok(()),
                    Some(running) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "cannot change the listen path in place: listening on                              {running}, config says {wanted}"
                        ),
                    )),
                    // Nothing recorded the path, so there is nothing to compare
                    // against and claiming a match would be a guess.
                    None => Ok(()),
                }
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "resolved bind kind does not match configured bind location",
            )),
        }
    }

    /// Tell the accept loops to stop, without waiting for them.
    ///
    /// The synchronous half of [`shutdown`](Self::shutdown), for a caller that has no
    /// `await` to spend -- a `Drop` impl cleaning up after a cancelled request, say.
    /// Established connections are untouched either way: they were spawned off the
    /// accept loop and hold their own handler.
    ///
    /// What this does *not* give you is [`shutdown`]'s guarantee that the sockets are
    /// free when it returns. For TCP the listener drops almost immediately; a QUIC
    /// endpoint drains its live connections first, and nothing here waits for that.
    /// So this frees the port eventually, not by the time it returns.
    ///
    /// [`shutdown`]: Self::shutdown
    pub fn stop_accepting(&self) {
        self.cancel.cancel();
    }

    /// Stop accepting and revoke the established-connection tree immediately.
    ///
    /// QUIC listener tasks observe the connection token themselves and close their
    /// endpoints. Every TCP connection runs under a child context; metered fallback
    /// tasks retain that context through their traffic stream. This synchronous half
    /// is also used when a hard-removal future is cancelled.
    pub fn hard_stop(&self) {
        // Cancel connections first. If an accept races this call, the child token it
        // creates is born cancelled and cannot escape the hard stop.
        self.connection_cancel.cancel();
        self.cancel.cancel();
    }

    /// Stop accepting and wait for the listeners to release their sockets.
    ///
    /// Established connections are deliberately left running. QUIC endpoints drain
    /// them within the supplied bound; aborting a listener after that bound can cut
    /// those connections short.
    pub async fn shutdown(&self, drain: Duration) {
        self.cancel.cancel();

        self.join_listeners(drain).await;
    }

    /// Stop accepting, revoke established connections, and wait for the listener
    /// tasks to release their sockets.
    pub async fn hard_shutdown(&self, drain: Duration) {
        self.hard_stop();
        self.join_listeners(drain).await;
    }

    async fn join_listeners(&self, drain: Duration) {
        let mut listeners: Vec<JoinHandle<()>> = {
            let mut guard = self.listeners.lock().unwrap();
            guard.drain(..).collect()
        };
        if listeners.is_empty() {
            return;
        }

        let joined = futures::future::join_all(listeners.iter_mut());
        if tokio::time::timeout(drain, joined).await.is_err() {
            debug!(
                "listener(s) on {:?} did not stop within {drain:?}; aborting",
                self.binds
            );
            for handle in &listeners {
                handle.abort();
            }
            // `abort` only *schedules* the cancellation. Awaiting the handles
            // afterwards is what makes "the sockets are free when this returns"
            // true rather than nearly true -- a caller handing the same address
            // to a new inbound would otherwise race the dying task.
            //
            // Finished handles are filtered out because their output was already
            // taken by the join above, and polling a `JoinHandle` twice panics.
            let aborted =
                futures::future::join_all(listeners.iter_mut().filter(|task| !task.is_finished()));
            // Bounded again: a task that cannot be stopped at all must not turn a
            // shutdown into a hang.
            if tokio::time::timeout(ABORT_GRACE, aborted).await.is_err() {
                debug!(
                    "listener(s) on {:?} still had not stopped {ABORT_GRACE:?} after being aborted",
                    self.binds
                );
            }
        }
    }

    /// The listener tasks, for a caller that will never reload or stop this
    /// inbound and only wants something to await on.
    pub fn into_listeners(self) -> Vec<JoinHandle<()>> {
        self.listeners.into_inner().unwrap()
    }

    /// Fold another handle's listeners, slots and addresses into this one.
    ///
    /// One config can produce several sets of listeners; they share a cancellation
    /// token so the embedder holds one handle per inbound rather than one per
    /// listener.
    pub(crate) fn absorb(&mut self, other: ServerHandle) {
        let ServerHandle {
            binds,
            slots,
            listeners,
            ..
        } = other;
        self.binds.extend(binds);
        self.slots.extend(slots);
        self.listeners
            .lock()
            .unwrap()
            .extend(listeners.into_inner().unwrap());
    }
}

fn display_addresses(addresses: &[SocketAddr]) -> String {
    if addresses.is_empty() {
        return "nothing".to_string();
    }
    addresses
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("transport", &self.transport)
            .field("binds", &self.binds)
            .field("slots", &self.slots.len())
            .field("generation", &self.generation())
            .field("listeners", &self.listener_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;

    use crate::async_stream::AsyncStream;
    use crate::tcp::tcp_handler::TcpServerSetupResult;

    fn parsed_protocol(json: &str) -> ServerProxyConfig {
        serde_yaml::from_str(json).expect("test protocol parses")
    }

    #[test]
    fn multiplexing_protocols_require_physical_stream_replacement() {
        for protocol in [
            r#"{"type":"ss","cipher":"aes-256-gcm","password":"secret"}"#,
            r#"{"type":"snell","cipher":"aes-128-gcm","password":"secret"}"#,
            r#"{"type":"vless","user_id":"11111111-1111-4111-8111-111111111111"}"#,
            r#"{"type":"trojan","password":"secret"}"#,
            r#"{"type":"vmess","cipher":"any","user_id":"11111111-1111-4111-8111-111111111111"}"#,
            r#"{"type":"anytls","users":{"password":"secret"}}"#,
            r#"{"type":"naive","users":{"username":"u","password":"secret"}}"#,
        ] {
            assert!(
                protocol_has_post_accept_logical_flows(&parsed_protocol(protocol)),
                "{protocol}"
            );
        }
        assert!(!protocol_has_post_accept_logical_flows(&parsed_protocol(
            r#"{"type":"socks","udp_enabled":false}"#
        )));
    }

    #[test]
    fn socks_udp_associations_require_replacement_only_when_enabled() {
        for protocol in [
            r#"{"type":"socks","udp_enabled":true}"#,
            r#"{"type":"mixed","udp_enabled":true}"#,
        ] {
            assert!(
                protocol_has_post_accept_logical_flows(&parsed_protocol(protocol)),
                "UDP ASSOCIATE outlives the physical setup future: {protocol}"
            );
        }

        for protocol in [
            r#"{"type":"socks","udp_enabled":false}"#,
            r#"{"type":"mixed","udp_enabled":false}"#,
        ] {
            assert!(
                !protocol_has_post_accept_logical_flows(&parsed_protocol(protocol)),
                "TCP-only SOCKS/Mixed remains safe for handler RCU: {protocol}"
            );
        }
    }

    #[test]
    fn native_quic_udp_associations_require_listener_replacement() {
        assert!(protocol_has_post_accept_logical_flows(&parsed_protocol(
            r#"{"type":"hysteria2","password":"secret","udp_enabled":true}"#
        )));
        assert!(protocol_has_post_accept_logical_flows(&parsed_protocol(
            r#"{"type":"tuic","uuid":"550e8400-e29b-41d4-a716-446655440000","password":"secret"}"#
        )));
        assert!(
            !protocol_has_post_accept_logical_flows(&parsed_protocol(
                r#"{"type":"hysteria2","password":"secret","udp_enabled":false}"#
            )),
            "TCP-only Hysteria2 loads the current selector for each new stream"
        );
    }

    #[test]
    fn multiplexing_classification_recurses_through_transport_wrappers() {
        for protocol in [
            r#"{"type":"tls","default_target":{"cert":"c","key":"k","protocol":{"type":"vless","user_id":"11111111-1111-4111-8111-111111111111"}}}"#,
            r#"{"type":"tls","shadowtls_targets":{"x":{"password":"p","handshake":{"address":"example.com:443"},"protocol":{"type":"snell","cipher":"aes-128-gcm","password":"p"}}}}"#,
            r#"{"type":"tls","reality_targets":{"x":{"private_key":"key","short_ids":[""],"dest":"example.com:443","protocol":{"type":"trojan","password":"p"}}}}"#,
            r#"{"type":"websocket","targets":{"protocol":{"type":"vmess","cipher":"any","user_id":"11111111-1111-4111-8111-111111111111"}}}"#,
            r#"{"type":"websocket","targets":{"protocol":{"type":"socks","udp_enabled":true}}}"#,
        ] {
            assert!(
                protocol_has_post_accept_logical_flows(&parsed_protocol(protocol)),
                "wrapper failed to expose multiplexing child: {protocol}"
            );
        }
    }

    #[test]
    fn check_reload_rejects_connection_multiplexing_before_any_slot_swap() {
        let config: ServerConfig = serde_yaml::from_str(
            r#"{
                "address":"127.0.0.1:1080",
                "protocol":{
                    "type":"vless",
                    "user_id":"11111111-1111-4111-8111-111111111111"
                }
            }"#,
        )
        .unwrap();
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.record_listener_settings(&config);
        handle.slot_for_path_for_test(marker("old"));
        let error = handle
            .check_reload(&config)
            .expect_err("VLESS can open H2MUX logical flows after physical accept");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("logical flows"));
        assert_eq!(handle.generation(), 0);
    }

    /// A handler that does nothing but say which generation it belongs to.
    ///
    /// `TcpServerHandler` requires `Debug`, so its rendering is enough to tell two
    /// handlers apart without setting up a stream for them.
    #[derive(Debug)]
    struct Marker(&'static str);

    #[async_trait]
    impl TcpServerHandler for Marker {
        async fn setup_server_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Err(std::io::Error::other(self.0))
        }
    }

    impl HandlerSlot {
        /// The slot's real constructor takes the resolver its handler routes by.
        /// These tests are about the swap itself, so they hand it a stand-in.
        fn new_for_test(handler: Arc<dyn TcpServerHandler>) -> Arc<Self> {
            Self::new(handler, resolver())
        }

        fn store_for_test(&self, handler: Arc<dyn TcpServerHandler>) -> u64 {
            self.store(handler, resolver())
        }
    }

    impl ServerHandle {
        fn slot_for_path_for_test(
            &mut self,
            handler: Arc<dyn TcpServerHandler>,
        ) -> Arc<HandlerSlot> {
            self.slot_for_path(handler, &resolver())
        }
    }

    impl SelectorSlot {
        fn new_for_test(selector: Arc<ClientProxySelector>) -> Arc<Self> {
            Self::new(selector, resolver())
        }
    }

    fn marker(name: &'static str) -> Arc<dyn TcpServerHandler> {
        Arc::new(Marker(name))
    }

    /// The handler half of a `load`, named. A slot hands back the resolver too, but
    /// these tests are about which *handler* a connection is pinned to.
    fn name_of(loaded: &(Arc<dyn TcpServerHandler>, Arc<dyn Resolver>)) -> String {
        format!("{:?}", loaded.0)
    }

    fn resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }

    fn multi_bind_handle_with_replay(
        config: &ServerConfig,
        replay_state: InboundReplayState,
    ) -> ServerHandle {
        let mut handle = ServerHandle::new_with_replay_state(
            Transport::Tcp,
            CancellationToken::new(),
            replay_state,
        );
        handle.record_listener_settings(config);
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let resolver = resolver();
        let replay_scope = handle.replay_scope();

        for address in ["127.0.0.1:1080", "127.0.0.2:1080"] {
            let address: SocketAddr = address.parse().unwrap();
            let protocol = config.protocol.clone();
            let selector = Arc::clone(&selector);
            let handler_resolver = Arc::clone(&resolver);
            let replay_scope = replay_scope.clone();
            handle.push_address(address);
            handle.slot_for_ip(address.ip(), &resolver, move || {
                create_tcp_server_handler_with_replay_state(
                    protocol,
                    &selector,
                    &handler_resolver,
                    Some(address.ip()),
                    None,
                    &replay_scope,
                )
                .into()
            });
        }

        handle
    }

    #[test]
    fn load_returns_the_current_handler() {
        let slot = HandlerSlot::new_for_test(marker("first"));
        assert_eq!(name_of(&slot.load()), "Marker(\"first\")");
        assert_eq!(slot.generation(), 0);
    }

    #[test]
    fn store_changes_what_the_next_load_sees() {
        let slot = HandlerSlot::new_for_test(marker("first"));
        assert_eq!(slot.store_for_test(marker("second")), 1);
        assert_eq!(name_of(&slot.load()), "Marker(\"second\")");
        assert_eq!(slot.generation(), 1);
    }

    #[test]
    fn the_resolver_changes_generation_with_the_handler() {
        // The resolver is in the slot rather than captured by the accept loop, so
        // that a connection cannot be accepted under one generation's rules and
        // route by another's DNS. An inbound may carry its own `dns` section, so a
        // reload really can hand the rebuilt handler a different resolver.
        let first = resolver();
        let second = resolver();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "the two stand-ins must be distinguishable"
        );

        let slot = HandlerSlot::new(marker("old"), Arc::clone(&first));
        let (_, loaded) = slot.load();
        assert!(Arc::ptr_eq(&loaded, &first));

        // A connection accepted now holds both halves of its own generation.
        let in_flight = slot.load();

        slot.store(marker("new"), Arc::clone(&second));
        let (handler, loaded) = slot.load();
        assert_eq!(format!("{handler:?}"), "Marker(\"new\")");
        assert!(
            Arc::ptr_eq(&loaded, &second),
            "a new connection must get the resolver that came with the new handler"
        );

        // And the in-flight one is untouched, in both halves.
        assert_eq!(format!("{:?}", in_flight.0), "Marker(\"old\")");
        assert!(
            Arc::ptr_eq(&in_flight.1, &first),
            "an established connection keeps the DNS it started with"
        );
    }

    #[test]
    fn a_handler_already_loaded_is_unaffected_by_a_store() {
        // The whole of the RCU guarantee: a connection accepted before the swap
        // keeps the handler it was given, for as long as it holds the `Arc`.
        let slot = HandlerSlot::new_for_test(marker("old"));
        let in_flight = slot.load();
        slot.store_for_test(marker("new"));
        assert_eq!(name_of(&in_flight), "Marker(\"old\")");
        assert_eq!(name_of(&slot.load()), "Marker(\"new\")");
    }

    #[test]
    fn slots_are_shared_per_ip_and_not_across_ips() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        let first = handle.slot_for_ip("127.0.0.1".parse().unwrap(), &resolver(), || marker("a"));
        let same = handle.slot_for_ip("127.0.0.1".parse().unwrap(), &resolver(), || marker("b"));
        let other = handle.slot_for_ip("127.0.0.2".parse().unwrap(), &resolver(), || marker("c"));

        assert!(Arc::ptr_eq(&first, &same), "one handler per bind IP");
        assert!(!Arc::ptr_eq(&first, &other), "never shared across IPs");
        assert_eq!(handle.slots.len(), 2);
    }

    #[tokio::test]
    async fn shutdown_cancels_the_listeners_it_holds() {
        let cancel = CancellationToken::new();
        let mut handle = ServerHandle::new(Transport::Tcp, cancel.clone());
        let token = cancel.clone();
        handle.push_listener(tokio::spawn(async move { token.cancelled().await }));

        handle.shutdown(Duration::from_secs(5)).await;

        assert!(cancel.is_cancelled());
        assert_eq!(handle.listener_count(), 0);
    }

    #[tokio::test]
    async fn graceful_shutdown_preserves_connections_while_hard_shutdown_revokes_them() {
        let accept = CancellationToken::new();
        let graceful = ServerHandle::new(Transport::Tcp, accept.clone());
        let graceful_connection = graceful.connection_token().child_token();

        graceful.shutdown(Duration::from_secs(1)).await;

        assert!(accept.is_cancelled());
        assert!(!graceful_connection.is_cancelled());

        let accept = CancellationToken::new();
        let hard = ServerHandle::new(Transport::Tcp, accept.clone());
        let hard_connection = hard.connection_token().child_token();

        hard.hard_shutdown(Duration::from_secs(1)).await;

        assert!(accept.is_cancelled());
        assert!(hard_connection.is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_aborts_a_listener_that_ignores_the_token() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        let stuck = tokio::spawn(std::future::pending::<()>());
        let abort_handle = stuck.abort_handle();
        handle.push_listener(stuck);

        // Short bound: the point is that shutdown returns rather than hanging.
        handle.shutdown(Duration::from_millis(50)).await;

        // Not merely "abort was called": shutdown waits for the abort to land, so
        // that a caller may reuse the address the moment this returns.
        assert!(abort_handle.is_finished());
    }

    #[test]
    fn a_handle_without_slots_refuses_to_reload() {
        // A listener that recorded neither kind of slot has nothing above the socket
        // to reach, so say so instead of pretending.
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        let config: ServerConfig =
            serde_yaml::from_str("address: 127.0.0.1:1080\nprotocol:\n  type: socks\n").unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("no slots to swap");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    /// A hysteria2 inbound as the QUIC start path records it: one rule slot per bind
    /// address, and the settings its accept loop baked in.
    fn hysteria2_handle(
        udp_enabled: bool,
        has_registry: bool,
    ) -> (ServerHandle, Arc<SelectorSlot>) {
        let config = hysteria2_config(udp_enabled);
        let selector = Arc::new(create_tcp_client_proxy_selector(
            config
                .rules
                .clone()
                .map(ConfigSelection::unwrap_config)
                .into_vec(),
            resolver(),
        ));

        let mut handle = ServerHandle::new(Transport::Quic, CancellationToken::new());
        let slot = handle.push_selector(selector, &resolver(), &config.protocol, has_registry);
        handle.push_address("127.0.0.1:18443".parse().unwrap());
        (handle, slot)
    }

    fn hysteria2_config(udp_enabled: bool) -> ServerConfig {
        serde_yaml::from_str(&format!(
            "address: 127.0.0.1:18443\n\
             transport: quic\n\
             quic_settings:\n  cert: c\n  key: k\n\
             protocol:\n  type: hysteria2\n  password: p\n  udp_enabled: {udp_enabled}\n\
             rules:\n  - masks: 0.0.0.0/0\n    action: allow\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_rule_slot_reloads_where_a_handler_slot_would_have_nothing_to_swap() {
        // A TCP-only hysteria2 listener loads the selector once per accepted
        // stream, so new streams can safely observe an RCU generation. UDP-enabled
        // hysteria2 and TUIC are covered separately: their long-lived associations
        // require listener replacement.
        let (handle, slot) = hysteria2_handle(false, true);
        assert_eq!(slot.generation(), 0);

        let generation = handle
            .reload(hysteria2_config(false), &resolver(), None)
            .expect("rules should swap on a selector-only listener");

        assert_eq!(generation, 1);
        assert_eq!(slot.generation(), 1, "the running listener sees the swap");
        assert_eq!(handle.generation(), 1);
    }

    #[test]
    fn reload_swaps_sniff_policy_for_new_connections_only() {
        let (handle, slot) = hysteria2_handle(false, true);
        let in_flight = slot.load().0;
        assert_eq!(in_flight.sniff_policy(), None);

        let mut enabled = hysteria2_config(false);
        enabled.sniff = Some(true);
        handle
            .reload(enabled, &resolver(), None)
            .expect("sniff policy is selector state, not a fixed listener setting");
        assert_eq!(slot.load().0.sniff_policy(), Some(true));
        assert_eq!(
            in_flight.sniff_policy(),
            None,
            "a connection pinned to the old selector keeps its generation"
        );

        let mut disabled = hysteria2_config(false);
        disabled.sniff = Some(false);
        handle.reload(disabled, &resolver(), None).unwrap();
        assert_eq!(slot.load().0.sniff_policy(), Some(false));
    }

    #[test]
    fn a_rule_slot_refuses_a_changed_protocol_setting() {
        // `udp_enabled` is read once, before the accept loop starts. Accepting the
        // change would report success for a setting that never took effect -- and
        // leave UDP running after an operator turned it off.
        let (handle, slot) = hysteria2_handle(true, true);
        let err = handle
            .reload(hysteria2_config(false), &resolver(), None)
            .expect_err("udp_enabled cannot change in place");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("udp_enabled"), "{err}");
        assert!(
            err.to_string().contains("rules"),
            "say what *can* change: {err}"
        );
        assert_eq!(slot.generation(), 0, "a rejected reload swaps nothing");
    }

    #[test]
    fn a_rule_slot_refuses_a_changed_client_bandwidth_policy() {
        let (handle, slot) = hysteria2_handle(false, true);
        let mut changed = hysteria2_config(false);
        if let ServerProxyConfig::Hysteria2 {
            ignore_client_bandwidth,
            ..
        } = &mut changed.protocol
        {
            *ignore_client_bandwidth = true;
        }

        let err = handle
            .reload(changed, &resolver(), None)
            .expect_err("ignore_client_bandwidth cannot change in place");

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("ignore_client_bandwidth"), "{err}");
        assert_eq!(slot.generation(), 0, "a rejected reload swaps nothing");
    }

    #[test]
    fn a_rule_slot_ignores_the_credential_only_when_a_registry_supersedes_it() {
        let changed = |handle: &ServerHandle| {
            let mut config = hysteria2_config(false);
            if let ServerProxyConfig::Hysteria2 { password, .. } = &mut config.protocol {
                *password = "rotated".to_string();
            }
            handle.reload(config, &resolver(), None)
        };

        // In dynamic mode the config password is a placeholder the control plane
        // regenerates on every call, so comparing it would refuse every reload.
        let (dynamic, _) = hysteria2_handle(false, true);
        assert!(changed(&dynamic).is_ok());

        // Without a registry it is the real credential, and the accept loop already
        // turned it into a one-user registry it will not rebuild.
        let (classic, _) = hysteria2_handle(false, false);
        let err = changed(&classic).expect_err("the config credential cannot change in place");
        assert!(err.to_string().contains("password"), "{err}");
    }

    #[test]
    fn a_rule_slot_refuses_a_different_protocol_entirely() {
        let (handle, _) = hysteria2_handle(true, true);
        let config: ServerConfig = serde_yaml::from_str(
            "address: 127.0.0.1:18443\n\
             transport: quic\n\
             quic_settings:\n  cert: c\n  key: k\n\
             protocol:\n  type: socks\n  udp_enabled: false\n\
             rules:\n  - masks: 0.0.0.0/0\n    action: allow\n",
        )
        .unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("a hysteria2 listener cannot become a socks one");
        assert!(err.to_string().contains("`type`"), "{err}");
    }

    #[test]
    fn reload_rejects_a_different_listen_set() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.slot_for_ip("127.0.0.1".parse().unwrap(), &resolver(), || {
            marker("running")
        });

        let config: ServerConfig = serde_yaml::from_str(
            "address: 127.0.0.1:1081\nprotocol:\n  type: socks\n  udp_enabled: false\n",
        )
        .unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("the port moved");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("127.0.0.1:1081"),
            "the message should name both sets: {err}"
        );
    }

    #[test]
    fn reload_rejects_a_different_transport() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.slot_for_ip("127.0.0.1".parse().unwrap(), &resolver(), || {
            marker("running")
        });

        let config: ServerConfig = serde_yaml::from_str(
            "address: 127.0.0.1:1080\ntransport: quic\nprotocol:\n  type: socks\n  udp_enabled: false\n",
        )
        .unwrap();
        let err = handle
            .reload(config, &resolver(), None)
            .expect_err("the transport changed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn reload_swaps_every_slot_and_reports_one_generation() {
        let mut handle = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        handle.push_address("127.0.0.1:1080".parse().unwrap());
        handle.push_address("127.0.0.1:1081".parse().unwrap());
        let shared =
            handle.slot_for_ip("127.0.0.1".parse().unwrap(), &resolver(), || marker("old"));

        let config: ServerConfig = serde_yaml::from_str(
            "address:\n  - 127.0.0.1:1080\n  - 127.0.0.1:1081\nprotocol:\n  type: socks\n  udp_enabled: false\n",
        )
        .unwrap();

        let in_flight = shared.load();
        assert_eq!(handle.reload(config, &resolver(), None).unwrap(), 1);
        assert_eq!(handle.generation(), 1);
        // The slot now holds a real socks handler, but the connection that loaded
        // before the swap still holds the marker.
        assert_eq!(name_of(&in_flight), "Marker(\"old\")");
        assert_ne!(name_of(&shared.load()), "Marker(\"old\")");
    }

    #[test]
    fn multi_bind_hard_replacement_keeps_one_replay_scope_and_isolates_other_inbounds() {
        let vmess: ServerConfig = serde_yaml::from_str(
            r#"address:
  - 127.0.0.1:1080
  - 127.0.0.2:1080
protocol:
  type: vmess
  cipher: any
  user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
"#,
        )
        .unwrap();

        let handle = multi_bind_handle_with_replay(&vmess, InboundReplayState::default());
        let vmess_filter = handle.replay_state.vmess_auth_ids();
        let shadowsocks_filter = handle.replay_state.shadowsocks_salts();
        assert!(vmess_filter.lock().check_and_insert(b"vmess-auth-id"));
        assert!(
            shadowsocks_filter
                .lock()
                .insert_and_check(b"shadowsocks-salt")
        );

        // The handle and this local variable hold one reference each; the other
        // two are the handlers built for the two bind IPs. If either handler had
        // constructed a new filter, this would stay at two instead of four.
        assert_eq!(Arc::strong_count(&vmess_filter), 4);
        let error = handle
            .reload(vmess.clone(), &resolver(), None)
            .expect_err("VMess H2MUX requires physical-stream replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            !vmess_filter.lock().check_and_insert(b"vmess-auth-id"),
            "a rejected RCU reload must not reopen the VMess replay window"
        );

        let shadowsocks: ServerConfig = serde_yaml::from_str(
            r#"address:
  - 127.0.0.1:1080
  - 127.0.0.2:1080
protocol:
  type: shadowsocks
  cipher: 2022-blake3-aes-128-gcm
  password: AAAAAAAAAAAAAAAAAAAAAA==
"#,
        )
        .unwrap();

        // A hard replacement carries the inbound replay lease into its new handle.
        // Changing protocol may drop the old VMess handlers, but it must preserve
        // both namespaces and share the SS salt filter across every new bind.
        let replay_state = handle.replay_state();
        drop(handle);
        let handle = multi_bind_handle_with_replay(&shadowsocks, replay_state);
        assert_eq!(Arc::strong_count(&shadowsocks_filter), 4);
        assert!(
            !vmess_filter.lock().check_and_insert(b"vmess-auth-id"),
            "hard replacement must retain the inactive VMess replay namespace"
        );
        assert!(
            !shadowsocks_filter
                .lock()
                .insert_and_check(b"shadowsocks-salt"),
            "hard replacement must not forget Shadowsocks salts"
        );

        let error = handle
            .reload(shadowsocks.clone(), &resolver(), None)
            .expect_err("Shadowsocks H2MUX requires physical-stream replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        let replay_state = handle.replay_state();
        drop(handle);
        let _replacement = multi_bind_handle_with_replay(&shadowsocks, replay_state);
        assert_eq!(Arc::strong_count(&shadowsocks_filter), 4);
        assert!(
            !shadowsocks_filter
                .lock()
                .insert_and_check(b"shadowsocks-salt"),
            "a second hard replacement must keep using the same filter"
        );

        let other = ServerHandle::new(Transport::Tcp, CancellationToken::new());
        assert!(
            other
                .replay_state
                .vmess_auth_ids()
                .lock()
                .check_and_insert(b"vmess-auth-id"),
            "different inbounds must have independent VMess replay namespaces"
        );
        assert!(
            other
                .replay_state
                .shadowsocks_salts()
                .lock()
                .insert_and_check(b"shadowsocks-salt"),
            "different inbounds must have independent Shadowsocks replay namespaces"
        );
    }
}
