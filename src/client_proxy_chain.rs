//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents an ordered sequence of proxy hops, where each hop
//! can be a pool of connectors (for round-robin selection). Traffic flows through
//! each hop in sequence to reach the final destination.
//!
//! ## Design: InitialHopEntry for Hop 0
//!
//! Hop 0 is fundamentally different from subsequent hops:
//! - **Hop 0**: Creates socket AND optionally sets up protocol (if not direct)
//! - **Hops 1+**: Only set up protocol on existing stream
//!
//! To handle mixed pools at hop 0 (e.g., direct + various proxy types), we use
//! `InitialHopEntry` which pairs socket and proxy together, ensuring they are
//! always selected atomically during round-robin.
//!
//! ## Structure
//!
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)

use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures::{StreamExt, future::BoxFuture, stream};
use log::debug;
use parking_lot::{Mutex, RwLock};
use percent_encoding::percent_decode_str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::time::Instant;
use url::Url;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::{ClientChainSelectionConfig, DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS};
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::resolver::{LateBoundResolver, Resolver, resolve_addresses};
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

pub struct UdpClientSetupResult {
    pub client_stream: Box<dyn AsyncMessageStream>,
    /// The final logical UDP destination selected from the ordered candidates.
    /// This is never the proxy transport peer.
    pub remote_addr: std::net::SocketAddr,
}

/// Build the target that the preceding hop must connect to for one proxy.
///
/// A hop-specific resolver is a local-resolution directive: the preceding
/// proxy must receive the selected IP, not the original hostname. The proxy
/// connector itself retains its original hostname for TLS SNI and protocol
/// state.
async fn preceding_hop_targets(
    proxy: &dyn ProxyConnector,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Vec<ResolvedLocation>> {
    let location = proxy.proxy_location();
    let Some(upstream) = proxy.dns_resolver() else {
        return Ok(vec![location.into()]);
    };
    let addresses =
        crate::resolver::resolve_addresses_via(resolver, Some(upstream), location).await?;
    if addresses.is_empty() {
        return Err(std::io::Error::other(format!(
            "DNS upstream {upstream:?} returned no address for proxy {location}"
        )));
    }
    Ok(addresses
        .into_iter()
        .map(|address| {
            let ip_location = NetLocation::new(
                match address.ip() {
                    std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
                },
                address.port(),
            );
            ResolvedLocation::with_resolved(ip_location, address)
        })
        .collect())
}

/// Project a resolved hostname to the selected IP only for protocols whose UDP
/// wire format cannot encode domains (currently VLESS packetaddr). Other proxy
/// protocols must retain the original hostname so the upstream remains the DNS
/// authority; the selected address stays attached as connection metadata.
fn proxy_udp_target(proxy: &dyn ProxyConnector, target: ResolvedLocation) -> ResolvedLocation {
    if !proxy.requires_literal_udp_target() || !matches!(target.address(), Address::Hostname(_)) {
        return target;
    }
    let Some(candidate) = target.resolved_addr() else {
        return target;
    };
    let literal = NetLocation::new(
        match candidate.ip() {
            std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
            std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
        },
        candidate.port(),
    );
    ResolvedLocation::with_resolved(literal, candidate)
}

/// Establish a TCP stream through the selected proxy prefix.
///
/// The recursion mirrors sing-box's nested resolve dialers. The server addresses
/// for the outermost proxy are tried serially; each attempt rebuilds its entire
/// detour prefix, whose own named resolver is evaluated again. Once a stream to
/// one server address succeeds, that proxy's protocol setup runs exactly once,
/// so an authentication/protocol failure is not misclassified as an address
/// connect failure for the same proxy.
fn connect_tcp_layers<'a>(
    entry: &'a InitialHopEntry,
    subsequent_proxies: &'a [&'a dyn ProxyConnector],
    target: &'a ResolvedLocation,
    resolver: &'a Arc<dyn Resolver>,
    observe_final_write_handshake: bool,
) -> BoxFuture<'a, std::io::Result<(TcpClientSetupResult, Option<Instant>)>> {
    Box::pin(async move {
        let Some((proxy, prefix)) = subsequent_proxies.split_last() else {
            return match entry {
                InitialHopEntry::Direct(socket) => {
                    let stream = socket.connect(resolver, target).await?;
                    Ok((
                        TcpClientSetupResult {
                            client_stream: stream,
                            early_data: None,
                        },
                        None,
                    ))
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    let proxy_location = proxy.proxy_location().into();
                    let stream = socket.connect(resolver, &proxy_location).await?;
                    if observe_final_write_handshake {
                        proxy
                            .setup_tcp_stream_with_write_handshake_boundary(stream, target)
                            .await
                    } else {
                        proxy
                            .setup_tcp_stream(stream, target)
                            .await
                            .map(|setup| (setup, None))
                    }
                }
            };
        };

        let candidates = preceding_hop_targets(*proxy, resolver).await?;
        let mut last_error = None;
        let mut connected_prefix = None;
        for (index, candidate) in candidates.iter().enumerate() {
            match connect_tcp_layers(entry, prefix, candidate, resolver, false).await {
                Ok((setup, _)) if setup.early_data.is_none() => {
                    if index > 0 {
                        debug!(
                            "Proxy {} reached via address #{} ({}) after {} failed address(es)",
                            proxy.proxy_location(),
                            index,
                            candidate.location(),
                            index
                        );
                    }
                    connected_prefix = Some(setup.client_stream);
                    break;
                }
                Ok((setup, _)) => {
                    let length = setup.early_data.as_ref().map_or(0, Vec::len);
                    last_error = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Unexpected early data ({length} bytes) before proxy {}",
                            proxy.proxy_location()
                        ),
                    ));
                }
                Err(error) => {
                    debug!(
                        "Proxy {} address {} failed through its detour: {}, trying next",
                        proxy.proxy_location(),
                        candidate.location(),
                        error
                    );
                    last_error = Some(error);
                }
            }
        }
        let stream = connected_prefix.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                std::io::Error::other(format!(
                    "No resolved address succeeded for proxy {}",
                    proxy.proxy_location()
                ))
            })
        })?;

        if observe_final_write_handshake {
            proxy
                .setup_tcp_stream_with_write_handshake_boundary(stream, target)
                .await
        } else {
            proxy
                .setup_tcp_stream(stream, target)
                .await
                .map(|setup| (setup, None))
        }
    })
}

/// Entry in the initial hop (hop 0) pool.
///
/// Each entry pairs socket creation with optional protocol setup,
/// ensuring they are always selected together during round-robin.
pub enum InitialHopEntry {
    /// Direct connection - socket only, no protocol setup.
    /// Connects directly to the next hop's proxy or final destination.
    Direct(Box<dyn SocketConnector>),

    /// Proxy connection - socket + protocol setup paired together.
    /// Socket connects to proxy_location, then protocol wraps the stream.
    Proxy {
        socket: Box<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) => true, // Direct always supports UDP
            InitialHopEntry::Proxy { proxy, .. } => {
                proxy.supports_udp_over_tcp() || proxy.supports_native_udp()
            }
        }
    }
}

/// A chain of proxy hops with paired initial hop entries.
///
/// Structure:
/// - `initial_hop`: Pool of InitialHopEntry for hop 0 (socket + optional proxy paired)
/// - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation needed)
pub struct ClientProxyChain {
    /// Initial hop pool: each entry is either Direct or Proxy.
    /// Socket and proxy are paired and selected together.
    initial_hop: Vec<InitialHopEntry>,
    /// Round-robin index for initial hop selection.
    initial_hop_next_index: AtomicU32,

    /// Protocol connectors for subsequent hops (hops 1+).
    /// Outer vec = hops, inner vec = round-robin pool per hop.
    subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    /// Round-robin indices for each subsequent hop's pool.
    subsequent_next_indices: Vec<AtomicU32>,

    /// Indices into the FINAL hop pool for UDP-capable entries.
    /// This is either indices into initial_hop (if no subsequent hops),
    /// or indices into the last subsequent hop pool.
    udp_final_hop_indices: Vec<usize>,
    /// Round-robin index for UDP-capable final hop entries.
    udp_final_hop_next_index: AtomicU32,
    /// Flag indicating which pool udp_final_hop_indices refers to.
    /// true = udp_final_hop_indices points to initial_hop
    /// false = udp_final_hop_indices points to last subsequent hop
    udp_uses_initial_hop: bool,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("initial_hop_count", &self.initial_hop.len())
            .field(
                "subsequent_hops",
                &self
                    .subsequent_hops
                    .iter()
                    .map(|h| h.len())
                    .collect::<Vec<_>>(),
            )
            .field("udp_final_hop_indices", &self.udp_final_hop_indices)
            .field("udp_uses_initial_hop", &self.udp_uses_initial_hop)
            .finish()
    }
}

impl ClientProxyChain {
    /// Create a new chain from initial hop entries and subsequent hop pools.
    ///
    /// # Arguments
    /// * `initial_hop` - Pool of InitialHopEntry for hop 0
    /// * `subsequent_hops` - Protocol connectors for hops 1+
    ///
    /// # Panics
    /// Panics if initial_hop is empty.
    pub fn new(
        initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );

        // Compute UDP-capable indices in the FINAL hop pool.
        // The final hop is either initial_hop (if no subsequent) or the last subsequent hop.
        // Only the hop that calls setup_udp_stream() needs UDP support.
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            // No subsequent hops: initial hop IS the final hop
            // Filter initial_hop for UDP-capable entries
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
            // Has subsequent hops: filter the FINAL subsequent hop for UDP-capable entries
            let final_hop = subsequent_hops.last().unwrap();
            let indices = final_hop
                .iter()
                .enumerate()
                .filter(|(_, p)| p.supports_udp_over_tcp())
                .map(|(i, _)| i)
                .collect();
            (indices, false)
        };

        let subsequent_next_indices = subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect();

        Self {
            initial_hop,
            initial_hop_next_index: AtomicU32::new(0),
            subsequent_hops,
            subsequent_next_indices,
            udp_final_hop_indices,
            udp_final_hop_next_index: AtomicU32::new(0),
            udp_uses_initial_hop,
        }
    }

    /// Returns the total number of hops.
    #[cfg(test)]
    pub fn num_hops(&self) -> usize {
        1 + self.subsequent_hops.len()
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        !self.udp_final_hop_indices.is_empty()
    }

    /// Returns true if this chain is "direct-only": all initial hops are Direct
    /// and there are no subsequent hops. Such chains can be used for UDP/QUIC
    /// DNS while still supporting bind_interface.
    pub fn is_direct_only(&self) -> bool {
        if !self.subsequent_hops.is_empty() {
            return false;
        }
        self.initial_hop
            .iter()
            .all(|entry| matches!(entry, InitialHopEntry::Direct(_)))
    }

    /// Returns the bind_interface from a direct-only chain.
    /// Returns None if not direct-only or if no bind_interface is configured.
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        // All entries should have the same bind_interface, return from the first.
        self.initial_hop.first().and_then(|entry| match entry {
            InitialHopEntry::Direct(socket) => socket.bind_interface(),
            InitialHopEntry::Proxy { .. } => None,
        })
    }

    /// Select an initial hop entry (round-robin).
    fn select_initial_hop_entry(&self) -> &InitialHopEntry {
        if self.initial_hop.len() == 1 {
            &self.initial_hop[0]
        } else {
            let idx = self.initial_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.initial_hop[idx % self.initial_hop.len()]
        }
    }

    /// Select proxy connectors for subsequent hops (round-robin per hop).
    fn select_subsequent_proxies(&self) -> Vec<&dyn ProxyConnector> {
        self.subsequent_hops
            .iter()
            .enumerate()
            .map(|(i, hop)| {
                if hop.len() == 1 {
                    hop[0].as_ref()
                } else {
                    let idx =
                        self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed) as usize;
                    hop[idx % hop.len()].as_ref()
                }
            })
            .collect()
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.connect_tcp_inner(remote_location, resolver, false)
            .await
            .map(|(setup, _)| setup)
    }

    /// Connect while observing the final protocol's write-handshake boundary.
    ///
    /// This is used by URLTest to match sing-box's latency window.  Normal
    /// callers use [`Self::connect_tcp`] and do not install any observer.
    async fn connect_tcp_with_write_handshake_boundary(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(TcpClientSetupResult, Option<Instant>)> {
        self.connect_tcp_inner(remote_location, resolver, true)
            .await
    }

    async fn connect_tcp_inner(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
        observe_final_write_handshake: bool,
    ) -> std::io::Result<(TcpClientSetupResult, Option<Instant>)> {
        // Select initial hop entry (socket + optional proxy paired)
        let entry = self.select_initial_hop_entry();

        // Select proxy connectors for subsequent hops
        let subsequent_proxies = self.select_subsequent_proxies();

        debug!(
            "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
            subsequent_proxies.len(),
            remote_location.location()
        );

        let result = connect_tcp_layers(
            entry,
            &subsequent_proxies,
            &remote_location,
            resolver,
            observe_final_write_handshake,
        )
        .await?;

        debug!(
            "Chain TCP complete: {} total hop(s) to {}",
            1 + subsequent_proxies.len(),
            remote_location.location()
        );

        Ok(result)
    }

    /// Connect for bidirectional UDP traffic through the chain.
    ///
    /// Returns an AsyncMessageStream that sends/receives UDP packets to the target.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // Check if UDP is supported
        if self.udp_final_hop_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Chain does not support UDP",
            ));
        }

        if self.udp_uses_initial_hop {
            // Case 1: No subsequent hops - initial hop IS the final hop
            // Select from UDP-capable initial hop entries
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let entry = &self.initial_hop[pool_idx];

            debug!(
                "Chain UDP connect: 1 hop (initial IS final), target={}",
                target.location()
            );

            match entry {
                InitialHopEntry::Direct(socket) => {
                    debug!("Chain UDP: Direct connection (native UDP)");
                    socket.connect_udp_bidirectional(resolver, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} (UDP, no subsequent)",
                        proxy.proxy_location()
                    );
                    let target = proxy_udp_target(proxy.as_ref(), target);
                    if proxy.supports_native_udp() {
                        // Native proxy UDP starts with a datagram socket connected
                        // to the proxy itself. The protocol wrapper then puts the
                        // final target into every encrypted packet.
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket
                            .connect_udp_bidirectional(resolver, proxy_loc)
                            .await?;
                        proxy.setup_native_udp(stream, target).await
                    } else {
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket.connect(resolver, &proxy_loc).await?;
                        proxy.setup_udp_bidirectional(stream, target).await
                    }
                }
            }
        } else {
            // Case 2: Has subsequent hops - select initial hop normally,
            // select intermediate hops normally, select final hop from UDP-capable

            // Select initial hop normally (ALL entries work - they just do TCP)
            let entry = self.select_initial_hop_entry();

            // Select intermediate hops normally (ALL entries work - they just do TCP)
            let intermediate_proxies: Vec<&dyn ProxyConnector> = self
                .subsequent_hops
                .iter()
                .enumerate()
                .take(self.subsequent_hops.len() - 1) // All but last
                .map(|(i, hop)| {
                    if hop.len() == 1 {
                        hop[0].as_ref()
                    } else {
                        let idx = self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed)
                            as usize;
                        hop[idx % hop.len()].as_ref()
                    }
                })
                .collect();

            // Select final hop from UDP-capable entries
            let final_hop_pool = self.subsequent_hops.last().unwrap();
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let final_proxy = final_hop_pool[pool_idx].as_ref();

            debug!(
                "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                intermediate_proxies.len(),
                target.location()
            );

            // Resolve the final proxy server at its own layer. Each failed
            // candidate rebuilds the selected detour prefix, matching nested
            // ResolveDialer/ListenSerial behavior.
            let final_candidates = preceding_hop_targets(final_proxy, resolver).await?;
            let mut last_error = None;
            let mut connected_stream = None;
            for (index, candidate) in final_candidates.iter().enumerate() {
                match connect_tcp_layers(entry, &intermediate_proxies, candidate, resolver, false)
                    .await
                {
                    Ok((setup, _)) if setup.early_data.is_none() => {
                        if index > 0 {
                            debug!(
                                "UDP proxy {} reached via address #{} ({}) after {} failed address(es)",
                                final_proxy.proxy_location(),
                                index,
                                candidate.location(),
                                index
                            );
                        }
                        connected_stream = Some(setup.client_stream);
                        break;
                    }
                    Ok((setup, _)) => {
                        let length = setup.early_data.as_ref().map_or(0, Vec::len);
                        last_error = Some(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Unexpected early data ({length} bytes) before UDP proxy {}",
                                final_proxy.proxy_location()
                            ),
                        ));
                    }
                    Err(error) => {
                        debug!(
                            "UDP proxy {} address {} failed through its detour: {}, trying next",
                            final_proxy.proxy_location(),
                            candidate.location(),
                            error
                        );
                        last_error = Some(error);
                    }
                }
            }
            let stream = connected_stream.ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    std::io::Error::other(format!(
                        "No resolved address succeeded for UDP proxy {}",
                        final_proxy.proxy_location()
                    ))
                })
            })?;

            debug!(
                "Chain UDP final hop: {} (UDP)",
                final_proxy.proxy_location()
            );
            let target = proxy_udp_target(final_proxy, target);
            final_proxy.setup_udp_bidirectional(stream, target).await
        }
    }
}

const NO_CHAIN_SELECTED: usize = usize::MAX;
const URLTEST_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";
const MAX_GENERATION_URLTEST_PROBES: usize = 10;

#[derive(Clone, Debug, Default)]
pub(crate) struct UrlTestHistoryStore {
    entries: Arc<RwLock<HashMap<String, UrlTestHistory>>>,
}

#[derive(Clone, Copy, Debug)]
struct UrlTestHistory {
    measured_at: Instant,
    delay_millis: u16,
}

#[derive(Debug)]
struct UrlTestSelectionState {
    histories_millis: RwLock<Vec<Option<u16>>>,
    history_keys: Option<Arc<Vec<String>>>,
    failure_history_keys: Option<Arc<Vec<String>>>,
    shared_histories: Option<UrlTestHistoryStore>,
    selected_tcp: AtomicUsize,
    selected_udp: AtomicUsize,
    tolerance_millis: u16,
    reselect_on_connection_failure: bool,
    /// Serializes history invalidation with selection replacement. Selection
    /// reads stay lock-free, while a late failure from an old connection cannot
    /// overwrite a newer selection.
    selection_update: Mutex<()>,
    activity: Mutex<UrlTestActivity>,
}

#[derive(Debug)]
struct UrlTestActivity {
    ticker_active: bool,
    last_active: Instant,
}

#[derive(Debug)]
struct UrlTestWorkerControl {
    closed: AtomicBool,
    notify: Notify,
    shutdown: watch::Sender<bool>,
}

impl UrlTestWorkerControl {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.shutdown.send_replace(true);
        }
    }
}

struct UrlTestWorkerParams {
    weak_chains: Weak<Vec<ClientProxyChain>>,
    weak_resolver: Weak<dyn Resolver>,
    weak_state: Weak<UrlTestSelectionState>,
    udp_chain_indices: Vec<usize>,
    url: String,
    use_native_roots: bool,
    interval: Duration,
    idle_timeout: Duration,
    probe_permits: Arc<Semaphore>,
    control: Arc<UrlTestWorkerControl>,
}

struct UrlTestRoundParams<'a> {
    chains: Arc<Vec<ClientProxyChain>>,
    resolver: Arc<dyn Resolver>,
    state: Arc<UrlTestSelectionState>,
    udp_chain_indices: &'a [usize],
    url: &'a str,
    use_native_roots: bool,
    interval: Duration,
    probe_permits: &'a Arc<Semaphore>,
    control: &'a Arc<UrlTestWorkerControl>,
}

impl UrlTestSelectionState {
    fn new(
        chain_count: usize,
        tolerance_millis: u64,
        reselect_on_connection_failure: bool,
    ) -> Self {
        Self {
            histories_millis: RwLock::new(vec![None; chain_count]),
            history_keys: None,
            failure_history_keys: None,
            shared_histories: None,
            selected_tcp: AtomicUsize::new(NO_CHAIN_SELECTED),
            selected_udp: AtomicUsize::new(NO_CHAIN_SELECTED),
            tolerance_millis: tolerance_millis as u16,
            reselect_on_connection_failure,
            selection_update: Mutex::new(()),
            activity: Mutex::new(UrlTestActivity {
                ticker_active: false,
                last_active: Instant::now(),
            }),
        }
    }

    fn new_shared(
        history_keys: Vec<String>,
        failure_history_keys: Vec<String>,
        histories: UrlTestHistoryStore,
        tolerance_millis: u64,
        reselect_on_connection_failure: bool,
    ) -> Self {
        let chain_count = history_keys.len();
        let mut state = Self::new(
            chain_count,
            tolerance_millis,
            reselect_on_connection_failure,
        );
        state.failure_history_keys = Some(Arc::new(if failure_history_keys.is_empty() {
            history_keys.clone()
        } else {
            failure_history_keys
        }));
        state.history_keys = Some(Arc::new(history_keys));
        state.shared_histories = Some(histories);
        state
    }

    fn history(&self, index: usize) -> Option<u16> {
        match (&self.history_keys, &self.shared_histories) {
            (Some(keys), Some(histories)) => histories
                .entries
                .read()
                .get(keys.get(index)?)
                .map(|history| history.delay_millis),
            _ => self.histories_millis.read().get(index).copied().flatten(),
        }
    }

    fn history_is_fresh(&self, index: usize, interval: Duration) -> bool {
        match (&self.history_keys, &self.shared_histories) {
            (Some(keys), Some(histories)) => histories
                .entries
                .read()
                .get(&keys[index])
                .is_some_and(|history| history.measured_at.elapsed() < interval),
            _ => false,
        }
    }

    fn store_history(&self, index: usize, delay_millis: u64) {
        let delay_millis = delay_millis.min(u16::MAX as u64) as u16;
        match (&self.history_keys, &self.shared_histories) {
            (Some(keys), Some(histories)) => {
                histories.entries.write().insert(
                    keys[index].clone(),
                    UrlTestHistory {
                        measured_at: Instant::now(),
                        delay_millis,
                    },
                );
            }
            _ => self.histories_millis.write()[index] = Some(delay_millis),
        }
    }

    fn selected(&self, udp: bool) -> &AtomicUsize {
        if udp {
            &self.selected_udp
        } else {
            &self.selected_tcp
        }
    }

    /// Select using sing-box's hysteresis: a candidate only replaces the
    /// current healthy selection when it is faster by more than tolerance.
    fn update_selection(&self, eligible: impl Iterator<Item = usize>, udp: bool) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let _selection_guard = self.selection_update.lock();
        let current = self.selected(udp).load(Ordering::Acquire);
        let current_eligible = current != NO_CHAIN_SELECTED && eligible.contains(&current);
        let candidate = match self.preferred_historical_candidate(&eligible, current) {
            Some(candidate) => candidate,
            None if current_eligible => current,
            None => *eligible.first()?,
        };
        self.selected(udp).store(candidate, Ordering::Release);
        Some(candidate)
    }

    fn clear_history(&self, index: usize) {
        let _selection_guard = self.selection_update.lock();
        self.clear_history_locked(index);
    }

    fn clear_history_locked(&self, index: usize) {
        if let (Some(keys), Some(histories)) = (&self.history_keys, &self.shared_histories) {
            histories.entries.write().remove(&keys[index]);
            return;
        }
        if let Some(history) = self.histories_millis.write().get_mut(index) {
            *history = None;
        }
    }

    fn clear_failure_history_locked(&self, index: usize) {
        if let (Some(keys), Some(histories)) = (&self.failure_history_keys, &self.shared_histories)
        {
            histories.entries.write().remove(&keys[index]);
            return;
        }
        if let Some(history) = self.histories_millis.write().get_mut(index) {
            *history = None;
        }
    }

    fn preferred_historical_candidate(&self, eligible: &[usize], current: usize) -> Option<usize> {
        let mut best = if current != NO_CHAIN_SELECTED && eligible.contains(&current) {
            self.history(current).map(|delay| (current, delay))
        } else {
            None
        };
        for &index in eligible {
            let Some(delay) = self.history(index) else {
                continue;
            };
            if best.is_none_or(|(_, best_delay)| {
                best_delay == 0 || best_delay > delay.wrapping_add(self.tolerance_millis)
            }) {
                best = Some((index, delay));
            }
        }
        best.map(|(index, _)| index)
    }

    /// Invalidate a failed chain. The default Go-compatible mode preserves the
    /// selected member; the shoes-only opt-in immediately moves the affected
    /// network's selection. TCP and UDP selections remain independent even
    /// though their probe histories are shared.
    fn handle_connection_failure(
        &self,
        failed_index: usize,
        eligible: impl Iterator<Item = usize>,
        udp: bool,
    ) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let _selection_guard = self.selection_update.lock();
        self.clear_failure_history_locked(failed_index);

        let selected = self.selected(udp);
        let current = selected.load(Ordering::Acquire);
        if !self.reselect_on_connection_failure {
            return (current != NO_CHAIN_SELECTED && eligible.contains(&current))
                .then_some(current);
        }
        if current != failed_index {
            return (current != NO_CHAIN_SELECTED && eligible.contains(&current))
                .then_some(current);
        }

        // A measured healthy member wins. If no history remains, try another
        // member in declaration order so the next connection does not
        // immediately reuse the known failure. A single-member group keeps its
        // only possible fallback.
        let replacement = self
            .preferred_historical_candidate(&eligible, NO_CHAIN_SELECTED)
            .or_else(|| {
                eligible
                    .iter()
                    .copied()
                    .find(|&index| index != failed_index)
            })
            .or_else(|| eligible.first().copied());
        selected.store(replacement.unwrap_or(NO_CHAIN_SELECTED), Ordering::Release);
        replacement
    }

    fn selected_or_fallback(
        &self,
        eligible: impl Iterator<Item = usize>,
        udp: bool,
    ) -> Option<usize> {
        let eligible = eligible.collect::<Vec<_>>();
        let current = self.selected(udp).load(Ordering::Acquire);
        if current != NO_CHAIN_SELECTED && eligible.contains(&current) {
            Some(current)
        } else {
            self.update_selection(eligible.into_iter(), udp)
        }
    }

    fn touch(&self, control: &UrlTestWorkerControl) {
        let mut activity = self.activity.lock();
        if activity.ticker_active {
            activity.last_active = Instant::now();
        } else {
            activity.ticker_active = true;
            control.notify.notify_one();
        }
    }
}

#[derive(Debug)]
enum ClientChainGroupSelection {
    RoundRobin,
    UrlTest(Arc<UrlTestSelectionState>),
}

/// Generation-scoped cache for logical outbound groups supplied by an embedder.
///
/// The ordinary shoes YAML path never installs this registry and therefore keeps
/// its historical per-rule construction. An embedder can scope one registry over
/// all configs in a topology generation so repeated references to the same
/// `shared_id` reuse one URLTest history, selection and background worker.
#[derive(Clone)]
pub struct ClientChainGroupRegistry {
    groups: Arc<Mutex<HashMap<String, ClientChainGroupRegistryEntry>>>,
    histories: UrlTestHistoryStore,
    probe_resolver: Arc<LateBoundResolver>,
    probe_binding: Arc<Mutex<Option<ProbeBinding>>>,
    probe_permits: Arc<Semaphore>,
}

type ProbeBinding = ([u8; 32], Arc<dyn Resolver>);

struct ClientChainGroupRegistryEntry {
    inner: Arc<ClientChainGroupInner>,
    committed: bool,
    pending_transactions: usize,
}

#[derive(Clone)]
struct ClientChainProbeGenerationLease {
    _probe_resolver: Arc<LateBoundResolver>,
    _probe_binding: Arc<Mutex<Option<ProbeBinding>>>,
}

impl Default for ClientChainGroupRegistry {
    fn default() -> Self {
        Self {
            groups: Arc::new(Mutex::new(HashMap::new())),
            histories: UrlTestHistoryStore::default(),
            probe_resolver: Arc::new(LateBoundResolver::new()),
            probe_binding: Arc::new(Mutex::new(None)),
            probe_permits: Arc::new(Semaphore::new(MAX_GENERATION_URLTEST_PROBES)),
        }
    }
}

impl ClientChainGroupRegistry {
    pub(crate) fn get_or_insert_with(
        &self,
        key: String,
        build: impl FnOnce() -> ClientChainGroup,
    ) -> ClientChainGroup {
        let mut groups = self.groups.lock();
        let claims = CLIENT_CHAIN_GROUP_CONTEXT
            .try_with(|context| {
                (Arc::ptr_eq(&context.registry.groups, &self.groups))
                    .then(|| context.claims.clone())
                    .flatten()
            })
            .ok()
            .flatten();
        if let Some(entry) = groups.get_mut(&key) {
            if let Some(claims) = claims {
                let mut claims = claims.lock();
                if !claims.iter().any(|(claimed_key, claimed)| {
                    claimed_key == &key
                        && claimed
                            .upgrade()
                            .is_some_and(|claimed| Arc::ptr_eq(&claimed, &entry.inner))
                }) {
                    entry.pending_transactions += 1;
                    claims.push((key, Arc::downgrade(&entry.inner)));
                }
            } else {
                entry.committed = true;
            }
            return ClientChainGroup {
                inner: Arc::clone(&entry.inner),
                probe_generation: self.probe_generation_for_current_scope(),
            };
        }

        let group = build();
        let inner = Arc::clone(&group.inner);
        let transactional = claims.is_some();
        groups.insert(
            key.clone(),
            ClientChainGroupRegistryEntry {
                inner: Arc::clone(&inner),
                committed: !transactional,
                pending_transactions: usize::from(transactional),
            },
        );
        if let Some(claims) = claims {
            // Record while the registry lock is still held, so commit/abort can
            // settle the exact pointer it claimed even under concurrent builders.
            claims.lock().push((key, Arc::downgrade(&inner)));
        }
        ClientChainGroup {
            inner,
            probe_generation: self.probe_generation_for_current_scope(),
        }
    }

    fn probe_generation_for_current_scope(&self) -> Option<ClientChainProbeGenerationLease> {
        let retain = CLIENT_CHAIN_GROUP_CONTEXT
            .try_with(|context| {
                Arc::ptr_eq(&context.registry.groups, &self.groups)
                    && context.retain_probe_generation
            })
            .unwrap_or(false);
        retain.then(|| ClientChainProbeGenerationLease {
            _probe_resolver: Arc::clone(&self.probe_resolver),
            _probe_binding: Arc::clone(&self.probe_binding),
        })
    }

    /// Resolver used exclusively by generation-global URLTest background probes.
    /// Business connections continue to pass their own inbound resolver to each
    /// connect call.
    pub(crate) fn probe_resolver(&self) -> Arc<dyn Resolver> {
        self.probe_resolver.clone()
    }

    pub(crate) fn history_store(&self) -> UrlTestHistoryStore {
        self.histories.clone()
    }

    pub(crate) fn probe_permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.probe_permits)
    }

    /// Connect the generation-global probe resolver exactly once. Repeating the
    /// same fingerprint is idempotent; a different graph requires generation
    /// rotation and is rejected rather than becoming order-dependent.
    pub fn bind_probe_resolver(
        &self,
        fingerprint: [u8; 32],
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<bool> {
        let mut binding = self.probe_binding.lock();
        if let Some((current, _)) = binding.as_ref() {
            if *current == fingerprint {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "URLTest probe DNS changed without rotating its generation",
            ));
        }

        self.probe_resolver.bind(&resolver)?;
        *binding = Some((fingerprint, resolver));
        Ok(true)
    }

    /// Check whether this generation is already connected to the requested
    /// probe DNS graph. A different fingerprint is a fail-loud generation error.
    pub fn probe_resolver_matches(&self, fingerprint: [u8; 32]) -> std::io::Result<bool> {
        match self.probe_binding.lock().as_ref() {
            None => Ok(false),
            Some((current, _)) if *current == fingerprint => Ok(true),
            Some(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "URLTest probe DNS changed without rotating its generation",
            )),
        }
    }

    pub fn probe_resolver_is_bound(&self) -> bool {
        self.probe_binding.lock().is_some()
    }

    /// Begin an all-or-nothing construction transaction for this generation.
    ///
    /// A URLTest group may be discovered while building a DNS graph, before its
    /// `LateBoundResolver` is bound and before any listener has started. If any
    /// later step fails, retaining that half-built group would poison the next
    /// retry. The transaction records only newly inserted entries and removes
    /// precisely those entries unless it is committed.
    pub fn transaction(&self) -> ClientChainGroupTransaction {
        ClientChainGroupTransaction {
            registry: self.clone(),
            claims: Arc::new(Mutex::new(Vec::new())),
            committed: false,
        }
    }

    /// Start each newly registered URLTest worker after its surrounding resolver
    /// graph or listener factory has completed successfully. This keeps the
    /// initial PostStart probe from racing an unbound LateBoundResolver.
    pub fn start_pending(&self) {
        let groups = self
            .groups
            .lock()
            .values()
            .map(|entry| Arc::clone(&entry.inner))
            .collect::<Vec<_>>();
        for group in groups {
            group.start_pending_urltest_worker();
        }
    }

    /// Number of logical shared groups retained by this generation.
    pub fn active_group_count(&self) -> usize {
        self.groups.lock().len()
    }

    /// Drop committed groups which are no longer reachable from a published
    /// resolver/listener graph. Keeping the registry's strong reference across
    /// a short construction gap lets one transaction reuse a logical group, but
    /// retaining every group for the full DNS/client-chain generation would let
    /// sequential topology applies bypass the per-config URLTest budgets.
    pub fn prune_dormant_committed(&self) {
        self.groups.lock().retain(|_, entry| {
            !entry.committed
                || entry.pending_transactions > 0
                || Arc::strong_count(&entry.inner) > 1
        });
    }
}

type ClientChainGroupRegistryClaims = Arc<Mutex<Vec<(String, Weak<ClientChainGroupInner>)>>>;

#[derive(Clone)]
struct ClientChainGroupBuildContext {
    registry: ClientChainGroupRegistry,
    claims: Option<ClientChainGroupRegistryClaims>,
    retain_probe_generation: bool,
}

tokio::task_local! {
    static CLIENT_CHAIN_GROUP_CONTEXT: ClientChainGroupBuildContext;
}

/// Run construction work with a generation-scoped logical outbound registry.
pub async fn with_client_chain_group_registry<F>(
    registry: ClientChainGroupRegistry,
    future: F,
) -> F::Output
where
    F: Future,
{
    CLIENT_CHAIN_GROUP_CONTEXT
        .scope(
            ClientChainGroupBuildContext {
                registry,
                claims: None,
                retain_probe_generation: true,
            },
            future,
        )
        .await
}

pub(crate) fn current_client_chain_group_registry() -> Option<ClientChainGroupRegistry> {
    CLIENT_CHAIN_GROUP_CONTEXT
        .try_with(|context| context.registry.clone())
        .ok()
}

/// Transactional construction scope for generation-shared client-chain groups.
pub struct ClientChainGroupTransaction {
    registry: ClientChainGroupRegistry,
    claims: ClientChainGroupRegistryClaims,
    committed: bool,
}

impl ClientChainGroupTransaction {
    /// Run one construction phase in this transaction. Multiple phases may be
    /// scoped independently while sharing the same insertion journal.
    pub async fn scope<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        CLIENT_CHAIN_GROUP_CONTEXT
            .scope(
                ClientChainGroupBuildContext {
                    registry: self.registry.clone(),
                    claims: Some(Arc::clone(&self.claims)),
                    retain_probe_generation: true,
                },
                future,
            )
            .await
    }

    /// Build the canonical probe DNS graph without creating a target cycle.
    /// The graph may contain shared groups itself; ordinary inbound references
    /// subsequently receive a generation lease when they reuse those groups.
    pub async fn scope_without_probe_generation<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        CLIENT_CHAIN_GROUP_CONTEXT
            .scope(
                ClientChainGroupBuildContext {
                    registry: self.registry.clone(),
                    claims: Some(Arc::clone(&self.claims)),
                    retain_probe_generation: false,
                },
                future,
            )
            .await
    }

    /// Publish all groups created by this transaction and start any deferred
    /// URLTest workers. Starting cannot fail and happens only after the embedder
    /// has published the complete resolver/listener graph.
    pub fn commit_and_start(mut self) {
        let groups = self.settle_claims(true);
        self.committed = true;
        for group in groups {
            group.start_pending_urltest_worker();
        }
    }

    fn settle_claims(&mut self, commit: bool) -> Vec<Arc<ClientChainGroupInner>> {
        let claims = std::mem::take(&mut *self.claims.lock());
        let mut groups = self.registry.groups.lock();
        let mut settled = Vec::with_capacity(claims.len());
        for (key, claimed) in claims.into_iter().rev() {
            let Some(claimed) = claimed.upgrade() else {
                continue;
            };
            let remove = if let Some(entry) = groups.get_mut(&key)
                && Arc::ptr_eq(&entry.inner, &claimed)
            {
                debug_assert!(entry.pending_transactions > 0);
                entry.pending_transactions = entry.pending_transactions.saturating_sub(1);
                if commit {
                    entry.committed = true;
                    settled.push(Arc::clone(&entry.inner));
                }
                !entry.committed && entry.pending_transactions == 0
            } else {
                false
            };
            if remove {
                groups.remove(&key);
            }
        }
        settled
    }
}

impl Drop for ClientChainGroupTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        self.settle_claims(false);
    }
}

/// A group of proxy chains with configurable chain selection.
#[derive(Clone)]
pub struct ClientChainGroup {
    inner: Arc<ClientChainGroupInner>,
    probe_generation: Option<ClientChainProbeGenerationLease>,
}

#[doc(hidden)]
pub struct ClientChainGroupInner {
    chains: Arc<Vec<ClientProxyChain>>,
    next_tcp_index: AtomicU32,
    pub(crate) udp_chain_indices: Vec<usize>,
    next_udp_index: AtomicU32,
    selection: ClientChainGroupSelection,
    /// Kept by the live group; the background worker only holds a Weak pointer.
    urltest_resolver: Option<Arc<dyn Resolver>>,
    urltest_worker: Option<Arc<UrlTestWorkerControl>>,
    pending_urltest_worker: Mutex<Option<UrlTestWorkerParams>>,
}

impl Deref for ClientChainGroup {
    type Target = ClientChainGroupInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for ClientChainGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChainGroup")
            .field("chains_count", &self.chains.len())
            .field("udp_chain_indices", &self.udp_chain_indices)
            .field("selection", &self.selection)
            .field("has_urltest_resolver", &self.urltest_resolver.is_some())
            .field("has_urltest_worker", &self.urltest_worker.is_some())
            .field("has_probe_generation", &self.probe_generation.is_some())
            .finish()
    }
}

impl ClientChainGroup {
    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        Self::new_internal(
            chains,
            ClientChainSelectionConfig::RoundRobin,
            None,
            false,
            true,
            None,
            None,
        )
    }

    pub fn new_with_selection(
        chains: Vec<ClientProxyChain>,
        selection_config: ClientChainSelectionConfig,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_internal(
            chains,
            selection_config,
            Some(resolver),
            false,
            true,
            None,
            None,
        )
    }

    pub(crate) fn new_with_deferred_selection(
        chains: Vec<ClientProxyChain>,
        selection_config: ClientChainSelectionConfig,
        resolver: Arc<dyn Resolver>,
        histories: UrlTestHistoryStore,
        probe_permits: Arc<Semaphore>,
    ) -> Self {
        Self::new_internal(
            chains,
            selection_config,
            Some(resolver),
            true,
            false,
            Some(histories),
            Some(probe_permits),
        )
    }

    fn new_internal(
        chains: Vec<ClientProxyChain>,
        selection_config: ClientChainSelectionConfig,
        resolver: Option<Arc<dyn Resolver>>,
        defer_urltest_start: bool,
        retain_urltest_resolver: bool,
        shared_histories: Option<UrlTestHistoryStore>,
        shared_probe_permits: Option<Arc<Semaphore>>,
    ) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup must have at least one chain"
        );

        let udp_chain_indices: Vec<usize> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| chain.supports_udp())
            .map(|(i, _)| i)
            .collect();

        let chains = Arc::new(chains);
        let (selection, background) = match selection_config {
            ClientChainSelectionConfig::RoundRobin => (ClientChainGroupSelection::RoundRobin, None),
            ClientChainSelectionConfig::UrlTest {
                shared_id: _,
                history_keys,
                failure_history_keys,
                url,
                use_native_roots,
                reselect_on_connection_failure,
                interval_millis,
                tolerance_millis,
                idle_timeout_millis,
            } => {
                assert!(
                    interval_millis > 0,
                    "urltest interval_millis must be validated as greater than zero"
                );
                let url = if url.is_empty() {
                    DEFAULT_URLTEST_URL.to_string()
                } else {
                    url
                };
                let state = Arc::new(if history_keys.is_empty() {
                    UrlTestSelectionState::new(
                        chains.len(),
                        tolerance_millis,
                        reselect_on_connection_failure,
                    )
                } else {
                    assert_eq!(
                        history_keys.len(),
                        chains.len(),
                        "urltest history_keys must match its chain count"
                    );
                    UrlTestSelectionState::new_shared(
                        history_keys,
                        failure_history_keys,
                        shared_histories
                            .clone()
                            .expect("shared URLTest history keys require a registry"),
                        tolerance_millis,
                        reselect_on_connection_failure,
                    )
                });
                let idle_timeout_millis = if idle_timeout_millis == 0 {
                    DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS
                } else {
                    idle_timeout_millis
                };
                (
                    ClientChainGroupSelection::UrlTest(state.clone()),
                    Some((
                        url,
                        use_native_roots,
                        Duration::from_millis(interval_millis),
                        Duration::from_millis(idle_timeout_millis),
                        Arc::downgrade(&state),
                    )),
                )
            }
        };

        let worker_control = background.as_ref().map(|_| {
            let (shutdown, _) = watch::channel(false);
            Arc::new(UrlTestWorkerControl {
                closed: AtomicBool::new(false),
                notify: Notify::new(),
                shutdown,
            })
        });
        let worker_resolver = background.as_ref().map(|_| {
            resolver
                .as_ref()
                .expect("urltest selection requires a resolver")
                .clone()
        });
        let group = Self {
            inner: Arc::new(ClientChainGroupInner {
                chains: chains.clone(),
                next_tcp_index: AtomicU32::new(0),
                udp_chain_indices,
                next_udp_index: AtomicU32::new(0),
                selection,
                urltest_resolver: if background.is_some() && retain_urltest_resolver {
                    resolver
                } else {
                    None
                },
                urltest_worker: worker_control.clone(),
                pending_urltest_worker: Mutex::new(None),
            }),
            probe_generation: None,
        };

        if let Some((url, use_native_roots, interval, idle_timeout, state)) = background {
            let resolver = worker_resolver.expect("urltest selection requires a resolver");
            let params = UrlTestWorkerParams {
                weak_chains: Arc::downgrade(&chains),
                weak_resolver: Arc::downgrade(&resolver),
                weak_state: state,
                udp_chain_indices: group.udp_chain_indices.clone(),
                url,
                use_native_roots,
                interval,
                idle_timeout,
                probe_permits: shared_probe_permits
                    .unwrap_or_else(|| Arc::new(Semaphore::new(MAX_GENERATION_URLTEST_PROBES))),
                control: worker_control.expect("urltest selection created a worker control"),
            };
            if defer_urltest_start {
                *group.pending_urltest_worker.lock() = Some(params);
            } else {
                spawn_urltest_task(params);
            }
        }

        group
    }

    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let chain_index = match &self.selection {
            ClientChainGroupSelection::RoundRobin => {
                self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize % self.chains.len()
            }
            ClientChainGroupSelection::UrlTest(state) => {
                state.touch(
                    self.urltest_worker
                        .as_deref()
                        .expect("urltest selection has a worker control"),
                );
                state
                    .selected_or_fallback(0..self.chains.len(), false)
                    .expect("ClientChainGroup has at least one TCP chain")
            }
        };
        let result = self.chains[chain_index]
            .connect_tcp(remote_location, resolver)
            .await;
        if result.is_err()
            && let ClientChainGroupSelection::UrlTest(state) = &self.selection
        {
            let _ = state.handle_connection_failure(chain_index, 0..self.chains.len(), false);
        }
        result
    }

    /// Connect fixed-destination UDP and return the exact logical destination
    /// candidate used by the final hop. Each candidate gets a fresh chain so a
    /// failed proxy handshake cannot accidentally fall back while retaining the
    /// first candidate in response metadata.
    pub async fn connect_udp_bidirectional_with_peer(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<UdpClientSetupResult> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let chain_idx = match &self.selection {
            ClientChainGroupSelection::RoundRobin => {
                let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
                self.udp_chain_indices[idx % self.udp_chain_indices.len()]
            }
            ClientChainGroupSelection::UrlTest(state) => {
                state.touch(
                    self.urltest_worker
                        .as_deref()
                        .expect("urltest selection has a worker control"),
                );
                state
                    .selected_or_fallback(self.udp_chain_indices.iter().copied(), true)
                    .expect("UDP-capable chain indices are non-empty")
            }
        };
        let chain = &self.chains[chain_idx];
        let candidates = match target.resolved_addrs() {
            Some(addresses) => addresses.to_vec(),
            None => resolve_addresses(resolver, target.location()).await?,
        };
        let mut last_error = None;

        for candidate in candidates {
            let candidate_target =
                ResolvedLocation::with_resolved(target.location().clone(), candidate);
            match chain
                .connect_udp_bidirectional(resolver, candidate_target)
                .await
            {
                Ok(client_stream) => {
                    return Ok(UdpClientSetupResult {
                        client_stream,
                        remote_addr: candidate,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }

        if let ClientChainGroupSelection::UrlTest(state) = &self.selection {
            let _ = state.handle_connection_failure(
                chain_idx,
                self.udp_chain_indices.iter().copied(),
                true,
            );
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::other(format!(
                "No UDP destination candidate succeeded for {}",
                target.location()
            ))
        }))
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let chain_idx = match &self.selection {
            ClientChainGroupSelection::RoundRobin => {
                let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
                self.udp_chain_indices[idx % self.udp_chain_indices.len()]
            }
            ClientChainGroupSelection::UrlTest(state) => {
                state.touch(
                    self.urltest_worker
                        .as_deref()
                        .expect("urltest selection has a worker control"),
                );
                state
                    .selected_or_fallback(self.udp_chain_indices.iter().copied(), true)
                    .expect("UDP-capable chain indices are non-empty")
            }
        };
        let chain = &self.chains[chain_idx];
        let result = chain.connect_udp_bidirectional(resolver, target).await;
        if result.is_err()
            && let ClientChainGroupSelection::UrlTest(state) = &self.selection
        {
            let _ = state.handle_connection_failure(
                chain_idx,
                self.udp_chain_indices.iter().copied(),
                true,
            );
        }
        result
    }

    /// Returns whether at least one chain can carry fixed-destination UDP.
    /// Datagram-based users such as DNS-over-QUIC use this to reject a
    /// TCP-only detour before attempting a connection.
    pub fn supports_udp(&self) -> bool {
        !self.udp_chain_indices.is_empty()
    }

    /// Returns true if all chains are direct-only.
    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(|chain| chain.is_direct_only())
    }

    /// Returns the bind_interface if all chains are direct-only and share
    /// the same bind_interface (or all have None).
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        // Return bind_interface from first chain (all should be the same in a group).
        self.chains
            .first()
            .and_then(|chain| chain.get_bind_interface())
    }
}

impl ClientChainGroupInner {
    fn start_pending_urltest_worker(&self) {
        if let Some(params) = self.pending_urltest_worker.lock().take() {
            spawn_urltest_task(params);
        }
    }
}

impl Drop for ClientChainGroupInner {
    fn drop(&mut self) {
        if let Some(worker) = &self.urltest_worker {
            worker.close();
        }
    }
}

fn spawn_urltest_task(params: UrlTestWorkerParams) {
    let UrlTestWorkerParams {
        weak_chains,
        weak_resolver,
        weak_state,
        udp_chain_indices,
        url,
        use_native_roots,
        interval,
        idle_timeout,
        probe_permits,
        control,
    } = params;
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        log::warn!(
            "URLTest client-chain selection was built outside a Tokio runtime; background probing was not started"
        );
        return;
    };

    runtime.spawn(async move {
        let mut worker_shutdown = control.shutdown.subscribe();
        if *worker_shutdown.borrow() {
            return;
        }
        // PostStart semantics: probe exactly once. Periodic probing begins only
        // after the group is touched by real TCP/UDP use.
        let (Some(chains), Some(resolver), Some(state)) = (
            weak_chains.upgrade(),
            weak_resolver.upgrade(),
            weak_state.upgrade(),
        ) else {
            return;
        };
        run_urltest_round(UrlTestRoundParams {
            chains,
            resolver,
            state,
            udp_chain_indices: &udp_chain_indices,
            url: &url,
            use_native_roots,
            interval,
            probe_permits: &probe_permits,
            control: &control,
        })
        .await;

        loop {
            if *worker_shutdown.borrow() {
                return;
            }
            tokio::select! {
                biased;
                changed = worker_shutdown.changed() => {
                    let _ = changed;
                    return;
                }
                _ = control.notify.notified() => {}
            }

            let Some(state) = weak_state.upgrade() else {
                return;
            };
            let run_immediately = {
                let mut activity = state.activity.lock();
                if !activity.ticker_active {
                    false
                } else if activity.last_active.elapsed() > interval {
                    activity.last_active = Instant::now();
                    true
                } else {
                    false
                }
            };
            drop(state);

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tokio::select! {
                biased;
                changed = worker_shutdown.changed() => {
                    let _ = changed;
                    return;
                }
                _ = ticker.tick() => {}
            }

            if run_immediately {
                let (Some(chains), Some(resolver), Some(state)) = (
                    weak_chains.upgrade(),
                    weak_resolver.upgrade(),
                    weak_state.upgrade(),
                ) else {
                    return;
                };
                run_urltest_round(UrlTestRoundParams {
                    chains,
                    resolver,
                    state,
                    udp_chain_indices: &udp_chain_indices,
                    url: &url,
                    use_native_roots,
                    interval,
                    probe_permits: &probe_permits,
                    control: &control,
                })
                .await;
            }

            loop {
                tokio::select! {
                    biased;
                    changed = worker_shutdown.changed() => {
                        let _ = changed;
                        return;
                    }
                    _ = ticker.tick() => {}
                    _ = control.notify.notified() => {
                        continue;
                    }
                }

                let Some(state) = weak_state.upgrade() else {
                    return;
                };
                let should_stop = {
                    let mut activity = state.activity.lock();
                    if activity.last_active.elapsed() > idle_timeout {
                        activity.ticker_active = false;
                        true
                    } else {
                        false
                    }
                };
                drop(state);
                if should_stop {
                    break;
                }

                let (Some(chains), Some(resolver), Some(state)) = (
                    weak_chains.upgrade(),
                    weak_resolver.upgrade(),
                    weak_state.upgrade(),
                ) else {
                    return;
                };
                run_urltest_round(UrlTestRoundParams {
                    chains,
                    resolver,
                    state,
                    udp_chain_indices: &udp_chain_indices,
                    url: &url,
                    use_native_roots,
                    interval,
                    probe_permits: &probe_permits,
                    control: &control,
                })
                .await;
            }
        }
    });
}

async fn run_urltest_round(params: UrlTestRoundParams<'_>) {
    let UrlTestRoundParams {
        chains,
        resolver,
        state,
        udp_chain_indices,
        url,
        use_native_roots,
        interval,
        probe_permits,
        control,
    } = params;
    // Go accepts URLTest topology independently of URL syntax and reports an
    // invalid probe URL asynchronously. Keep the same ACK/runtime boundary.
    let parsed_url = parse_urltest_probe_url(url).map_err(|error| error.to_string());
    stream::iter(0..chains.len())
        .for_each_concurrent(10, |index| {
            let chains = chains.clone();
            let resolver = resolver.clone();
            let state = state.clone();
            let parsed_url = parsed_url.clone();
            let probe_permits = Arc::clone(probe_permits);
            let control = Arc::clone(control);
            async move {
                if control.closed.load(Ordering::Acquire) {
                    return;
                }
                if state.history_is_fresh(index, interval) {
                    return;
                }
                let url = match parsed_url {
                    Ok(url) => url,
                    Err(error) => {
                        debug!("URLTest chain {index} unavailable: {error}");
                        state.clear_history(index);
                        return;
                    }
                };
                let mut shutdown = control.shutdown.subscribe();
                if *shutdown.borrow() {
                    return;
                }
                let permit = tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        let _ = changed;
                        return;
                    }
                    permit = probe_permits.acquire_owned() => {
                        let Ok(permit) = permit else {
                            state.clear_history(index);
                            return;
                        };
                        permit
                    }
                };
                let result = tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        let _ = changed;
                        drop(permit);
                        return;
                    }
                    result = tokio::time::timeout(
                        URLTEST_TIMEOUT,
                        probe_chain_http_head(&chains[index], &resolver, &url, use_native_roots),
                    ) => result,
                };
                drop(permit);

                if control.closed.load(Ordering::Acquire) {
                    return;
                }

                match result {
                    Ok(Ok(delay)) => {
                        debug!("URLTest chain {index} available: {delay}ms");
                        state.store_history(index, delay);
                    }
                    Ok(Err(error)) => {
                        debug!("URLTest chain {index} unavailable: {error}");
                        state.clear_history(index);
                    }
                    Err(_) => {
                        debug!("URLTest chain {index} unavailable: timed out after 15s");
                        state.clear_history(index);
                    }
                }
            }
        })
        .await;

    if control.closed.load(Ordering::Acquire) {
        return;
    }
    state.update_selection(0..chains.len(), false);
    state.update_selection(udp_chain_indices.iter().copied(), true);
}

fn parse_urltest_probe_url(raw: &str) -> std::io::Result<Url> {
    let url = Url::parse(raw).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid URLTest URL {raw:?}: {error}"),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URLTest URL must be an absolute HTTP or HTTPS URL",
        ));
    }
    Ok(url)
}

async fn probe_chain_http_head(
    chain: &ClientProxyChain,
    resolver: &Arc<dyn Resolver>,
    url: &Url,
    use_native_roots: bool,
) -> std::io::Result<u64> {
    let host = url.host_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URLTest URL is missing a host",
        )
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "URLTest URL has no known port",
        )
    })?;
    let target = NetLocation::new(Address::from(host)?, port).into();
    let started = Instant::now();
    let (setup, write_handshake_started_at) = chain
        .connect_tcp_with_write_handshake_boundary(target, resolver)
        .await?;
    // Go's URLTest resets its timer when the returned connection implements
    // NeedHandshakeForWrite.  Shoes sends Trojan/VLESS headers eagerly during
    // setup, so their handlers report the equivalent instant from inside the
    // final hop (after socket, detour, and transport setup).
    let started = write_handshake_started_at.unwrap_or(started);
    if setup.early_data.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "URLTest chain returned application data before the HEAD request",
        ));
    }
    let mut io: Box<dyn AsyncStream> = setup.client_stream;

    if url.scheme() == "https" {
        static BUNDLED_ROOTS_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        static NATIVE_ROOTS_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        let config = if use_native_roots {
            &NATIVE_ROOTS_TLS_CONFIG
        } else {
            &BUNDLED_ROOTS_TLS_CONFIG
        }
        .get_or_init(|| {
            Arc::new(crate::rustls_config_util::create_client_config(
                true,
                Vec::new(),
                vec!["http/1.1".to_string()],
                true,
                None,
                false,
                use_native_roots,
            ))
        })
        .clone();
        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid URLTest TLS server name: {error}"),
                )
            })?;
        let client = rustls::ClientConnection::new(config, server_name).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not create URLTest TLS client: {error}"),
            )
        })?;
        let mut connection = CryptoConnection::new_rustls_client(client);
        perform_crypto_handshake(&mut connection, &mut io, 16_384).await?;
        io = Box::new(CryptoTlsStream::new(io, connection));
    }

    let mut request_target = url.path().to_string();
    if request_target.is_empty() {
        request_target.push('/');
    }
    if let Some(query) = url.query() {
        request_target.push('?');
        request_target.push_str(query);
    }
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let mut request = format!(
        "HEAD {request_target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Go-http-client/1.1\r\n"
    );
    let before_host = &url[..url::Position::BeforeHost];
    let has_user_info = before_host
        .rsplit_once("//")
        .is_some_and(|(_, authority_prefix)| authority_prefix.contains('@'));
    if has_user_info {
        let mut credential = percent_decode_str(url.username()).collect::<Vec<_>>();
        credential.push(b':');
        if let Some(password) = url.password() {
            credential.extend(percent_decode_str(password));
        }
        request.push_str("Authorization: Basic ");
        request.push_str(&BASE64.encode(credential));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    // Go's net/http Transport defaults MaxResponseHeaderBytes to 10 MiB.
    const MAX_RESPONSE_HEADERS: usize = 10 * 1024 * 1024;
    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut total_header_bytes = 0usize;
    loop {
        let mut header_search_from = 0usize;
        let header_end = loop {
            if let Some((end, _)) = find_urltest_http_header_end(&response, header_search_from) {
                if total_header_bytes.saturating_add(end) > MAX_RESPONSE_HEADERS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "URLTest HTTP response headers exceed 10 MiB",
                    ));
                }
                total_header_bytes += end;
                break end;
            }
            if total_header_bytes.saturating_add(response.len()) >= MAX_RESPONSE_HEADERS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "URLTest HTTP response headers exceed 10 MiB",
                ));
            }
            let read = io.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "URLTest HTTP server closed before response headers completed",
                ));
            }
            header_search_from = response.len().saturating_sub(3);
            response.extend_from_slice(&chunk[..read]);
        };

        let (_, header_body_end) = find_urltest_http_header_end(&response[..header_end], 0)
            .expect("header terminator was found above");
        let status_newline = response[..header_end]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "URLTest HTTP response has no status line",
                )
            })?;
        let status_line_end = status_newline
            - usize::from(status_newline > 0 && response.get(status_newline - 1) == Some(&b'\r'));
        let status_line = &response[..status_line_end];
        let status_space = status_line
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "invalid URLTest HTTP status line: {:?}",
                        String::from_utf8_lossy(status_line)
                    ),
                )
            })?;
        let version = &status_line[..status_space];
        let mut status_text = &status_line[status_space + 1..];
        while status_text.first() == Some(&b' ') {
            status_text = &status_text[1..];
        }
        let status = status_text
            .iter()
            .position(|byte| *byte == b' ')
            .map_or(status_text, |end| &status_text[..end]);
        let status = (status.len() == 3)
            .then(|| std::str::from_utf8(status).ok()?.parse::<i16>().ok())
            .flatten()
            .filter(|status| *status >= 0)
            .map(|status| status as u16);
        let version = parse_urltest_http_version(version);
        if version.is_none() || status.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid URLTest HTTP status line: {:?}",
                    String::from_utf8_lossy(status_line)
                ),
            ));
        }
        let version = version.expect("validated above");
        let status = status.expect("validated above");
        let headers = parse_urltest_http_headers(&response[status_newline + 1..header_body_end])?;
        validate_urltest_http_transfer_headers(version, &headers)?;
        if (100..200).contains(&status) && status != 101 {
            response.drain(..header_end);
            continue;
        }
        break;
    }

    Ok(started.elapsed().as_millis().min(u64::MAX as u128) as u64)
}

fn find_urltest_http_header_end(response: &[u8], from: usize) -> Option<(usize, usize)> {
    // Go's textproto reader accepts either LF or CRLF independently for every
    // line. A blank line is therefore either "\n\n" or "\n\r\n"; the latter
    // also covers an ordinary CRLFCRLF terminator.
    let lf = memchr::memmem::find(&response[from..], b"\n\n")
        .map(|position| (from + position + 2, from + position + 1));
    let mixed = memchr::memmem::find(&response[from..], b"\n\r\n")
        .map(|position| (from + position + 3, from + position + 1));
    match (lf, mixed) {
        (Some(lf), Some(mixed)) => Some(if lf.1 <= mixed.1 { lf } else { mixed }),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

fn parse_urltest_http_version(version: &[u8]) -> Option<(u8, u8)> {
    (version.len() == 8
        && version.starts_with(b"HTTP/")
        && version[5].is_ascii_digit()
        && version[6] == b'.'
        && version[7].is_ascii_digit())
    .then(|| (version[5] - b'0', version[7] - b'0'))
}

#[derive(Default)]
struct ParsedUrlTestHttpHeaders {
    content_length: Option<Vec<u8>>,
    transfer_encoding: Option<Vec<u8>>,
    multiple_transfer_encodings: bool,
    forbidden_trailer_key: bool,
}

#[derive(Clone, Copy)]
enum CollectedUrlTestHeader {
    ContentLength,
    TransferEncoding,
    Trailer,
    Other,
}

impl ParsedUrlTestHttpHeaders {
    fn finish_field(&mut self, kind: CollectedUrlTestHeader, value: &[u8]) -> std::io::Result<()> {
        match kind {
            CollectedUrlTestHeader::ContentLength => {
                let value = trim_http_header_whitespace(value);
                if let Some(first) = &self.content_length {
                    if first.as_slice() != value {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "URLTest HTTP response has conflicting Content-Length headers",
                        ));
                    }
                } else {
                    self.content_length = Some(value.to_vec());
                }
            }
            CollectedUrlTestHeader::TransferEncoding => {
                if self.transfer_encoding.is_some() {
                    self.multiple_transfer_encodings = true;
                } else {
                    // Go's textproto reader trims only the left side of the
                    // assembled MIME value. Preserve trailing whitespace so
                    // net/http-style transfer validation still rejects it.
                    self.transfer_encoding = Some(trim_http_header_left_whitespace(value).to_vec());
                }
            }
            CollectedUrlTestHeader::Trailer => {
                self.forbidden_trailer_key |= value.split(|byte| *byte == b',').any(|key| {
                    let key = trim_http_header_whitespace(key);
                    [
                        b"Transfer-Encoding".as_slice(),
                        b"Trailer",
                        b"Content-Length",
                    ]
                    .iter()
                    .any(|reserved| key.eq_ignore_ascii_case(reserved))
                });
            }
            CollectedUrlTestHeader::Other => {}
        }
        Ok(())
    }
}

fn parse_urltest_http_headers(mut headers: &[u8]) -> std::io::Result<ParsedUrlTestHttpHeaders> {
    let mut parsed = ParsedUrlTestHttpHeaders::default();
    let mut current_kind = None;
    let mut current_value = Vec::new();
    while !headers.is_empty() {
        let line_end = headers
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(headers.len());
        let mut line = &headers[..line_end];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        headers = if line_end == headers.len() {
            &[]
        } else {
            &headers[line_end + 1..]
        };

        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            let Some(kind) = current_kind else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "folded URLTest HTTP response header has no preceding field",
                ));
            };
            if !line.iter().copied().all(valid_http_header_value_byte) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid folded URLTest HTTP response header",
                ));
            }
            if !matches!(kind, CollectedUrlTestHeader::Other) {
                current_value.push(b' ');
                current_value.extend_from_slice(trim_http_header_whitespace(line));
            }
            continue;
        }

        if let Some(kind) = current_kind.take() {
            parsed.finish_field(kind, &current_value)?;
            current_value.clear();
        }

        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed URLTest HTTP response header without a colon",
            ));
        };
        let (name, value_with_colon) = line.split_at(colon);
        if name.is_empty()
            || !name
                .iter()
                .copied()
                .all(|byte| byte == b' ' || valid_http_header_name_byte(byte))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid URLTest HTTP response header name",
            ));
        }
        if !value_with_colon[1..]
            .iter()
            .copied()
            .all(valid_http_header_value_byte)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid URLTest HTTP response header value",
            ));
        }
        let kind = if name.eq_ignore_ascii_case(b"Content-Length") {
            CollectedUrlTestHeader::ContentLength
        } else if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            CollectedUrlTestHeader::TransferEncoding
        } else if name.eq_ignore_ascii_case(b"Trailer") {
            CollectedUrlTestHeader::Trailer
        } else {
            CollectedUrlTestHeader::Other
        };
        if !matches!(kind, CollectedUrlTestHeader::Other) {
            current_value.extend_from_slice(trim_http_header_whitespace(&value_with_colon[1..]));
        }
        current_kind = Some(kind);
    }
    if let Some(kind) = current_kind {
        parsed.finish_field(kind, &current_value)?;
    }
    Ok(parsed)
}

fn validate_urltest_http_transfer_headers(
    version: (u8, u8),
    headers: &ParsedUrlTestHttpHeaders,
) -> std::io::Result<()> {
    if let Some(first) = headers.content_length.as_deref()
        && (first.is_empty()
            || !first.iter().all(u8::is_ascii_digit)
            || std::str::from_utf8(first)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value > i64::MAX as u64))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad URLTest HTTP response Content-Length",
        ));
    }

    // net/http's readTransfer treats HTTP/0.0 as its historical HTTP/1.1
    // default before applying transfer-encoding rules.
    let version = if version == (0, 0) { (1, 1) } else { version };
    let chunked = (version.0 > 1 || (version.0 == 1 && version.1 >= 1))
        && headers.transfer_encoding.is_some();
    if chunked
        && (headers.multiple_transfer_encodings
            || !headers
                .transfer_encoding
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(b"chunked")))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported URLTest HTTP response Transfer-Encoding",
        ));
    }

    if chunked && headers.forbidden_trailer_key {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad URLTest HTTP response trailer key",
        ));
    }
    Ok(())
}

fn valid_http_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn valid_http_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte != 0x7f)
}

fn trim_http_header_whitespace(mut value: &[u8]) -> &[u8] {
    value = trim_http_header_left_whitespace(value);
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_http_header_left_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::net::TcpListener;

    use crate::address::NetLocation;
    use crate::async_stream::{AsyncPing, AsyncStream};
    use crate::tcp::proxy_connector::ProxyConnector;
    use crate::tcp::socket_connector::SocketConnector;

    struct TestDuplexStream(DuplexStream);

    impl AsyncRead for TestDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestDuplexStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestDuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestDuplexStream {}

    #[derive(Debug)]
    struct PassTcpSocketConnector;

    #[async_trait]
    impl SocketConnector for PassTcpSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            let (client, peer) = tokio::io::duplex(128);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Box::new(TestDuplexStream(client)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "test connector only supplies the proxy TCP transport",
            ))
        }
    }

    #[derive(Debug)]
    struct CandidateFallbackProxy {
        location: NetLocation,
        rejected: std::net::SocketAddr,
        requires_literal_udp_target: bool,
        attempts: Arc<Mutex<Vec<(NetLocation, std::net::SocketAddr)>>>,
    }

    #[async_trait]
    impl ProxyConnector for CandidateFallbackProxy {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            true
        }

        fn requires_literal_udp_target(&self) -> bool {
            self.requires_literal_udp_target
        }

        async fn setup_tcp_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            unreachable!()
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            let candidate = target
                .resolved_addr()
                .expect("candidate API must attach the selected logical peer");
            self.attempts
                .lock()
                .push((target.into_location(), candidate));
            if candidate == self.rejected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "proxy rejected first logical candidate",
                ));
            }
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            Ok(Box::new(socket))
        }
    }

    #[derive(Debug)]
    struct DelayedHttpSocketConnector {
        connect_delay: Duration,
        response_delay: Duration,
    }

    #[async_trait]
    impl SocketConnector for DelayedHttpSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            tokio::time::sleep(self.connect_delay).await;
            let (client, mut server) = tokio::io::duplex(4096);
            let response_delay = self.response_delay;
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(read) = server.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                tokio::time::sleep(response_delay).await;
                let _ = server
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
            });
            Ok(Box::new(TestDuplexStream(client)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "timing mock has no UDP support",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[derive(Debug)]
    struct TimedBoundaryProxyConnector {
        location: NetLocation,
        before_boundary: Duration,
        after_boundary: Duration,
        marks_write_handshake: bool,
    }

    impl TimedBoundaryProxyConnector {
        fn new(
            port: u16,
            before_boundary: Duration,
            after_boundary: Duration,
            marks_write_handshake: bool,
        ) -> Self {
            Self {
                location: NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), port),
                before_boundary,
                after_boundary,
                marks_write_handshake,
            }
        }
    }

    #[async_trait]
    impl ProxyConnector for TimedBoundaryProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn supports_udp_over_tcp(&self) -> bool {
            false
        }

        fn needs_handshake_for_write(&self) -> bool {
            self.marks_write_handshake
        }

        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            tokio::time::sleep(self.before_boundary).await;
            if self.marks_write_handshake {
                crate::tcp::write_handshake::mark_started();
            }
            tokio::time::sleep(self.after_boundary).await;
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: None,
            })
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "timing mock has no UDP support",
            ))
        }
    }

    #[test]
    fn urltest_selection_falls_back_and_applies_tolerance() {
        let state = UrlTestSelectionState::new(3, 50, false);

        // No history: preserve member order for startup fallback.
        assert_eq!(state.update_selection(0..3, false), Some(0));

        // A 30 ms improvement is inside the 50 ms tolerance, so chain 0 stays.
        *state.histories_millis.write() = vec![Some(100), Some(70), Some(200)];
        assert_eq!(state.update_selection(0..3, false), Some(0));

        // A 60 ms improvement exceeds tolerance and switches to chain 1.
        state.histories_millis.write()[1] = Some(40);
        assert_eq!(state.update_selection(0..3, false), Some(1));

        // UDP has independent selection and only sees its eligible chain set.
        assert_eq!(state.update_selection([2].into_iter(), true), Some(2));
        assert_eq!(state.selected_tcp.load(Ordering::Relaxed), 1);
        assert_eq!(state.selected_udp.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn urltest_tolerance_addition_wraps_like_go_uint16() {
        let state = UrlTestSelectionState::new(2, 60_000, false);
        *state.histories_millis.write() = vec![Some(15_000), Some(10_000)];
        state.selected_tcp.store(0, Ordering::Release);

        // Go stores both delay and tolerance as uint16. 10_000 + 60_000 wraps
        // to 4_464, so the 15_000 ms current member is replaced.
        assert_eq!(state.update_selection(0..2, false), Some(1));
    }

    #[test]
    fn urltest_real_tag_history_is_shared_across_distinct_groups() {
        let histories = UrlTestHistoryStore::default();
        let first = UrlTestSelectionState::new_shared(
            vec!["A".to_string(), "B".to_string()],
            vec!["A".to_string(), "B".to_string()],
            histories.clone(),
            0,
            false,
        );
        let second = UrlTestSelectionState::new_shared(
            vec!["A".to_string(), "C".to_string()],
            vec!["A".to_string(), "C".to_string()],
            histories,
            0,
            false,
        );

        first.store_history(0, 20);
        first.store_history(1, 40);
        assert_eq!(second.history(0), Some(20));
        assert!(second.history_is_fresh(0, Duration::from_secs(60)));
        second.store_history(0, 80);
        assert_eq!(first.history(0), Some(80));
        assert_eq!(first.update_selection(0..2, false), Some(1));

        second.clear_history(0);
        assert_eq!(first.history(0), None);
        assert_eq!(second.history(0), None);
    }

    #[test]
    fn urltest_live_failure_deletes_original_member_tag_like_go() {
        let histories = UrlTestHistoryStore::default();
        let selector_member = UrlTestSelectionState::new_shared(
            vec!["terminal".to_string()],
            vec!["selector".to_string()],
            histories.clone(),
            0,
            false,
        );
        let terminal_member = UrlTestSelectionState::new_shared(
            vec!["terminal".to_string()],
            vec!["terminal".to_string()],
            histories,
            0,
            false,
        );

        selector_member.store_history(0, 20);
        assert_eq!(
            selector_member.handle_connection_failure(0, 0..1, false),
            None
        );
        assert_eq!(
            selector_member.history(0),
            Some(20),
            "Go deletes the selector member tag, not its RealTag"
        );

        terminal_member.handle_connection_failure(0, 0..1, false);
        assert_eq!(selector_member.history(0), None);
    }

    #[tokio::test]
    async fn shared_urltest_registry_survives_reference_gaps_and_starts_once_activated() {
        let registry = ClientChainGroupRegistry::default();
        let selection = ClientChainSelectionConfig::UrlTest {
            shared_id: Some("node-agent-urltest-v1:test".to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        registry
            .bind_probe_resolver([1; 32], resolver.clone())
            .unwrap();

        let first = with_client_chain_group_registry(registry.clone(), async {
            crate::tcp::chain_builder::build_client_chain_group_with_selection(
                crate::option_util::NoneOrSome::None,
                selection.clone(),
                resolver.clone(),
            )
        })
        .await;
        let worker = first
            .urltest_worker
            .as_ref()
            .expect("URLTest creates a worker control")
            .clone();
        assert!(first.pending_urltest_worker.lock().is_some());
        assert_eq!(registry.active_group_count(), 1);

        let second = with_client_chain_group_registry(registry.clone(), async {
            crate::tcp::chain_builder::build_client_chain_group_with_selection(
                crate::option_util::NoneOrSome::None,
                selection,
                resolver,
            )
        })
        .await;
        assert!(Arc::ptr_eq(&first.inner, &second.inner));

        drop(first);
        assert!(!worker.closed.load(Ordering::Acquire));
        registry.start_pending();
        assert!(second.pending_urltest_worker.lock().is_none());
        registry.start_pending();
        assert!(!worker.closed.load(Ordering::Acquire));

        drop(second);
        assert_eq!(registry.active_group_count(), 1);
        assert!(!worker.closed.load(Ordering::Acquire));
        drop(registry);
        assert!(worker.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn shared_urltest_registry_transaction_rolls_back_only_its_new_entries() {
        let registry = ClientChainGroupRegistry::default();
        let selection = ClientChainSelectionConfig::UrlTest {
            shared_id: Some("node-agent-urltest-v1:transaction".to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        registry
            .bind_probe_resolver([2; 32], resolver.clone())
            .unwrap();

        let aborted = registry.transaction();
        let aborted_group = aborted
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        let aborted_worker = aborted_group
            .urltest_worker
            .as_ref()
            .expect("URLTest creates a worker control")
            .clone();
        assert_eq!(registry.active_group_count(), 1);

        drop(aborted);
        assert_eq!(registry.active_group_count(), 0);
        assert!(!aborted_worker.closed.load(Ordering::Acquire));
        drop(aborted_group);
        assert!(aborted_worker.closed.load(Ordering::Acquire));

        let committed = registry.transaction();
        let committed_group = committed
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        let committed_worker = committed_group
            .urltest_worker
            .as_ref()
            .expect("URLTest creates a worker control")
            .clone();
        committed.commit_and_start();
        assert_eq!(registry.active_group_count(), 1);
        assert!(committed_group.pending_urltest_worker.lock().is_none());

        // An aborted retry which merely reused the committed entry did not
        // insert it and therefore must not remove or stop it.
        let reused = registry.transaction();
        let reused_group = reused
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection,
                    resolver,
                )
            })
            .await;
        assert!(Arc::ptr_eq(&committed_group.inner, &reused_group.inner));
        drop(reused);
        assert_eq!(registry.active_group_count(), 1);
        assert!(!committed_worker.closed.load(Ordering::Acquire));

        drop(committed_group);
        drop(reused_group);
        drop(registry);
        assert!(committed_worker.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn generation_commit_prunes_dormant_groups_after_all_inner_transactions() {
        let registry = ClientChainGroupRegistry::default();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        registry
            .bind_probe_resolver([5; 32], resolver.clone())
            .unwrap();
        let selection = |shared_id: &str| ClientChainSelectionConfig::UrlTest {
            shared_id: Some(shared_id.to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };

        let first_transaction = registry.transaction();
        let first = first_transaction
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection("node-agent-urltest-v1:first-batch"),
                    resolver.clone(),
                )
            })
            .await;
        let first_worker = first
            .urltest_worker
            .as_ref()
            .expect("URLTest creates a worker control")
            .clone();
        first_transaction.commit_and_start();
        drop(first);

        // Preserve a brief reference gap so a retry can still reuse the same
        // logical group until the next topology transaction is published.
        assert_eq!(registry.active_group_count(), 1);
        assert!(!first_worker.closed.load(Ordering::Acquire));

        let second_transaction = registry.transaction();
        let second = second_transaction
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection("node-agent-urltest-v1:second-batch"),
                    resolver,
                )
            })
            .await;
        let second_worker = second
            .urltest_worker
            .as_ref()
            .expect("URLTest creates a worker control")
            .clone();
        second_transaction.commit_and_start();

        // A Shoes transaction only publishes one resolver/listener graph. The
        // embedder sweeps after its complete multi-inbound topology commits.
        assert_eq!(registry.active_group_count(), 2);
        registry.prune_dormant_committed();
        assert_eq!(registry.active_group_count(), 1);
        assert!(first_worker.closed.load(Ordering::Acquire));
        assert!(!second_worker.closed.load(Ordering::Acquire));

        drop(second);
        drop(registry);
        assert!(second_worker.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn aborted_replacement_preserves_a_registry_only_committed_group_for_rollback() {
        let registry = ClientChainGroupRegistry::default();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        registry
            .bind_probe_resolver([6; 32], resolver.clone())
            .unwrap();
        let selection = ClientChainSelectionConfig::UrlTest {
            shared_id: Some("node-agent-urltest-v1:rollback-gap".to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };

        let initial_transaction = registry.transaction();
        let initial = initial_transaction
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        let original_inner = Arc::downgrade(&initial.inner);
        initial_transaction.commit_and_start();
        drop(initial);

        let failed_candidate = registry.transaction();
        let candidate = failed_candidate
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        assert!(Arc::ptr_eq(
            &candidate.inner,
            &original_inner.upgrade().unwrap()
        ));
        drop(candidate);
        drop(failed_candidate);

        assert_eq!(registry.active_group_count(), 1);
        let rollback = registry.transaction();
        let restored = rollback
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection,
                    resolver,
                )
            })
            .await;
        assert!(Arc::ptr_eq(
            &restored.inner,
            &original_inner
                .upgrade()
                .expect("failed candidate must preserve rollback state")
        ));
        rollback.commit_and_start();
    }

    #[tokio::test]
    async fn committed_reuser_survives_the_inserting_transaction_abort() {
        let registry = ClientChainGroupRegistry::default();
        let selection = ClientChainSelectionConfig::UrlTest {
            shared_id: Some("node-agent-urltest-v1:overlap".to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 50,
            idle_timeout_millis: 1_800_000,
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        registry
            .bind_probe_resolver([4; 32], resolver.clone())
            .unwrap();

        let inserting = registry.transaction();
        let inserted_group = inserting
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        let reusing = registry.transaction();
        let committed_group = reusing
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection.clone(),
                    resolver.clone(),
                )
            })
            .await;
        assert!(Arc::ptr_eq(&inserted_group.inner, &committed_group.inner));
        reusing.commit_and_start();

        drop(inserting);
        assert_eq!(registry.active_group_count(), 1);

        let retry = registry.transaction();
        let retried_group = retry
            .scope(async {
                crate::tcp::chain_builder::build_client_chain_group_with_selection(
                    crate::option_util::NoneOrSome::None,
                    selection,
                    resolver,
                )
            })
            .await;
        assert!(Arc::ptr_eq(&committed_group.inner, &retried_group.inner));
        drop(retry);
        assert_eq!(registry.active_group_count(), 1);
    }

    #[tokio::test]
    async fn generation_registry_bounds_cross_group_urltest_probes() {
        let registry = ClientChainGroupRegistry::default();
        let permits = registry.probe_permits();
        let all = permits
            .clone()
            .acquire_many_owned(MAX_GENERATION_URLTEST_PROBES as u32)
            .await
            .unwrap();

        assert!(permits.clone().try_acquire_owned().is_err());
        drop(all);
        assert_eq!(permits.available_permits(), MAX_GENERATION_URLTEST_PROBES);
    }

    #[tokio::test]
    async fn shared_urltest_probe_uses_generation_resolver_not_first_inbound() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let port = listener_address.port();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_requests.fetch_add(1, Ordering::Release);
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let registry = ClientChainGroupRegistry::default();
        let fixed = Arc::new(FixedResolver(listener_address));
        let fixed_weak = Arc::downgrade(&fixed);
        let probe_resolver: Arc<dyn Resolver> = fixed.clone();
        registry
            .bind_probe_resolver([3; 32], probe_resolver)
            .unwrap();
        drop(fixed);
        let first_inbound_resolver: Arc<dyn Resolver> =
            Arc::new(FixedResolver("127.0.0.1:9".parse().unwrap()));
        let group = with_client_chain_group_registry(registry.clone(), async {
            crate::tcp::chain_builder::build_client_chain_group_with_selection(
                crate::option_util::NoneOrSome::None,
                ClientChainSelectionConfig::UrlTest {
                    shared_id: Some("node-agent-urltest-v1:late-bound".to_string()),
                    history_keys: Vec::new(),
                    failure_history_keys: Vec::new(),
                    url: format!("http://localhost:{port}/health"),
                    use_native_roots: false,
                    reselect_on_connection_failure: false,
                    interval_millis: 60_000,
                    tolerance_millis: 50,
                    idle_timeout_millis: 1_800_000,
                },
                first_inbound_resolver,
            )
        })
        .await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(requests.load(Ordering::Acquire), 0);
        assert!(group.pending_urltest_worker.lock().is_some());

        registry.start_pending();
        // Simulate Engine rotating to the next DNS generation while an old
        // listener/selector wrapper is still alive.
        drop(registry);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("activated URLTest did not send its initial probe");
        server.await.unwrap();
        drop(group);
        assert!(
            fixed_weak.upgrade().is_none(),
            "the retired probe graph is released with its final old selector"
        );
    }

    #[test]
    fn urltest_connection_failure_defaults_to_go_history_only_semantics() {
        let state = UrlTestSelectionState::new(3, 10, false);
        *state.histories_millis.write() = vec![Some(100), Some(40), Some(70)];
        state.selected_tcp.store(0, Ordering::Relaxed);
        state.selected_udp.store(0, Ordering::Relaxed);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(0));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 0);
        assert_eq!(state.selected_udp.load(Ordering::Acquire), 0);
    }

    #[test]
    fn urltest_connection_failure_reselects_only_the_affected_network() {
        let state = UrlTestSelectionState::new(3, 10, true);
        *state.histories_millis.write() = vec![Some(100), Some(40), Some(70)];
        state.selected_tcp.store(0, Ordering::Relaxed);
        state.selected_udp.store(0, Ordering::Relaxed);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(1));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 1);
        assert_eq!(
            state.selected_udp.load(Ordering::Acquire),
            0,
            "a TCP failure must not replace the independent UDP selection"
        );

        assert_eq!(
            state.handle_connection_failure(0, [0, 2].into_iter(), true),
            Some(2)
        );
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 1);
        assert_eq!(state.selected_udp.load(Ordering::Acquire), 2);
    }

    #[test]
    fn urltest_connection_failure_uses_an_ordered_unmeasured_fallback() {
        let state = UrlTestSelectionState::new(3, 50, true);
        state.selected_tcp.store(0, Ordering::Relaxed);

        assert_eq!(
            state.handle_connection_failure(0, 0..3, false),
            Some(1),
            "a known failure must not be immediately selected again when another member exists"
        );

        state.selected_tcp.store(0, Ordering::Relaxed);
        assert_eq!(
            state.handle_connection_failure(0, [0].into_iter(), false),
            Some(0),
            "a single-member group must retain its only fallback"
        );
    }

    #[test]
    fn urltest_late_failure_does_not_overwrite_a_newer_selection() {
        let state = UrlTestSelectionState::new(3, 0, true);
        *state.histories_millis.write() = vec![Some(10), Some(20), Some(30)];
        state.selected_tcp.store(2, Ordering::Release);

        assert_eq!(state.handle_connection_failure(0, 0..3, false), Some(2));
        assert_eq!(state.histories_millis.read()[0], None);
        assert_eq!(state.selected_tcp.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn urltest_sends_head_through_complete_direct_chain() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("HEAD /health?probe=1 HTTP/1.1\r\n"));
            assert!(request.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")));
            assert!(request.contains("\r\nUser-Agent: Go-http-client/1.1\r\n"));
            assert!(request.contains("\r\nAuthorization: Basic dXNlcjpuYW1lOnBAc3M=\r\n"));
            assert!(!request.contains("\r\nConnection:"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!(
            "http://user%3Aname:p%40ss@127.0.0.1:{port}/health?probe=1"
        ))
        .unwrap();
        let delay = tokio::time::timeout(
            Duration::from_secs(2),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(delay < 2_000);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_accepts_lf_only_response_lines_like_go_transport() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 204 OK\nX-Test: yes\n\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();

        probe_chain_http_head(&chain, &resolver, &url, false)
            .await
            .unwrap();
        server.await.unwrap();
    }

    async fn probe_urltest_raw_response(response: &'static [u8]) -> std::io::Result<u64> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream.write_all(response).await.unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();

        let result = probe_chain_http_head(&chain, &resolver, &url, false).await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn urltest_accepts_empty_and_mixed_line_ending_headers_like_go_transport() {
        for response in [
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\n\n".as_slice(),
            b"HTTP/1.1 204 No Content\nX-Test: yes\n\r\n".as_slice(),
            b"HTTP/1.2 204 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 OK\r\nTransfer-Encoding:\r\n chunked\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 \xff\r\n\r\n".as_slice(),
        ] {
            probe_urltest_raw_response(response).await.unwrap();
        }
    }

    #[tokio::test]
    async fn urltest_http_zero_zero_uses_go_http_one_one_transfer_semantics() {
        let error =
            probe_urltest_raw_response(b"HTTP/0.0 204 OK\r\nTransfer-Encoding: gzip\r\n\r\n")
                .await
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn urltest_skips_informational_responses_and_accepts_go_sized_headers() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </warmup>\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut final_response = b"HTTP/1.1 204 No Content\r\nX-Fill: ".to_vec();
            final_response.extend(std::iter::repeat_n(b'a', 70 * 1024));
            final_response.extend_from_slice(b"\r\n\r\n");
            stream.write_all(&final_response).await.unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();
        let delay = tokio::time::timeout(
            Duration::from_secs(2),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(delay >= 20, "103 must not complete the URLTest probe");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_rejects_malformed_response_headers_like_go_transport() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nBad Header\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_rejects_invalid_head_transfer_metadata_like_go_transport() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: nope\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();
        let error = probe_chain_http_head(&chain, &resolver, &url, false)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_header_limit_is_cumulative_across_informational_responses() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            let mut responses = Vec::with_capacity(11 * 1_000_000);
            for _ in 0..11 {
                responses.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nX-Fill: ");
                responses.extend(std::iter::repeat_n(b'a', 1_000_000));
                responses.extend_from_slice(b"\r\n\r\n");
            }
            responses.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
            let _ = stream.write_all(&responses).await;
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn urltest_rejects_an_unterminated_header_at_the_exact_go_limit() {
        const HEADER_LIMIT: usize = 10 * 1024 * 1024;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            let mut response = b"HTTP/1.1 204 No Content\r\nX-Fill: ".to_vec();
            response.resize(HEADER_LIMIT, b'a');
            let _ = stream.write_all(&response).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let url = Url::parse(&format!("http://127.0.0.1:{port}/health")).unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            probe_chain_http_head(&chain, &resolver, &url, false),
        )
        .await
        .expect("the exact header limit must fail without waiting for another network read")
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        server.abort();
    }

    #[tokio::test]
    async fn urltest_invalid_url_clears_history_asynchronously() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let state = Arc::new(UrlTestSelectionState::new(1, 0, false));
        state.store_history(0, 25);
        let probe_permits = Arc::new(Semaphore::new(MAX_GENERATION_URLTEST_PROBES));
        let (shutdown, _) = watch::channel(false);
        let control = Arc::new(UrlTestWorkerControl {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            shutdown,
        });

        run_urltest_round(UrlTestRoundParams {
            chains: Arc::new(vec![chain]),
            resolver,
            state: state.clone(),
            udp_chain_indices: &[],
            url: "relative-probe",
            use_native_roots: false,
            interval: Duration::from_secs(60),
            probe_permits: &probe_permits,
            control: &control,
        })
        .await;

        assert_eq!(state.history(0), None);
        assert!(parse_urltest_probe_url("ftp://example.com/file").is_err());
    }

    #[tokio::test]
    async fn urltest_round_cancels_while_waiting_for_generation_probe_permit() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let state = Arc::new(UrlTestSelectionState::new(1, 0, false));
        let probe_permits = Arc::new(Semaphore::new(MAX_GENERATION_URLTEST_PROBES));
        let held_permits = probe_permits
            .clone()
            .acquire_many_owned(MAX_GENERATION_URLTEST_PROBES as u32)
            .await
            .unwrap();
        let (shutdown, _) = watch::channel(false);
        let control = Arc::new(UrlTestWorkerControl {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            shutdown,
        });
        let round_control = control.clone();
        let round = tokio::spawn(async move {
            run_urltest_round(UrlTestRoundParams {
                chains: Arc::new(vec![chain]),
                resolver,
                state,
                udp_chain_indices: &[],
                url: "http://127.0.0.1:9/health",
                use_native_roots: false,
                interval: Duration::from_secs(60),
                probe_permits: &probe_permits,
                control: &round_control,
            })
            .await;
        });

        tokio::task::yield_now().await;
        control.close();
        tokio::time::timeout(Duration::from_secs(1), round)
            .await
            .expect("closed URLTest round must not remain queued on the semaphore")
            .unwrap();
        drop(held_permits);
    }

    #[test]
    fn urltest_header_parser_does_not_retain_unrelated_fields() {
        let mut headers = Vec::with_capacity(80_000);
        for _ in 0..10_000 {
            headers.extend_from_slice(b"X-Unrelated: ignored\r\n");
        }

        let parsed = parse_urltest_http_headers(&headers).unwrap();
        assert!(parsed.content_length.is_none());
        assert!(parsed.transfer_encoding.is_none());
        assert!(!parsed.multiple_transfer_encodings);
        assert!(!parsed.forbidden_trailer_key);
    }

    #[test]
    fn urltest_folded_transfer_encoding_preserves_go_whitespace_semantics() {
        let parsed = parse_urltest_http_headers(b"Transfer-Encoding:\r\n chunked\r\n").unwrap();
        assert_eq!(
            parsed.transfer_encoding.as_deref(),
            Some(b"chunked".as_slice())
        );
        assert!(validate_urltest_http_transfer_headers((1, 1), &parsed).is_ok());

        let parsed = parse_urltest_http_headers(b"Transfer-Encoding: chunked\r\n \r\n").unwrap();
        assert_eq!(
            parsed.transfer_encoding.as_deref(),
            Some(b"chunked ".as_slice())
        );
        assert!(validate_urltest_http_transfer_headers((1, 1), &parsed).is_err());
        assert!(validate_urltest_http_transfer_headers((1, 0), &parsed).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn urltest_latency_starts_at_final_write_handshake_boundary() {
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                DelayedHttpSocketConnector {
                    connect_delay: Duration::from_millis(100),
                    response_delay: Duration::from_millis(15),
                },
            ))],
            vec![
                // This hop has the same marker as Trojan/VLESS, but only the
                // final outbound may reset URLTest's timer.
                vec![Box::new(TimedBoundaryProxyConnector::new(
                    1080,
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                    true,
                ))],
                vec![Box::new(TimedBoundaryProxyConnector::new(
                    1081,
                    Duration::from_millis(40),
                    Duration::from_millis(25),
                    true,
                ))],
            ],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let url = Url::parse("http://example.com/health").unwrap();

        let wall_started = Instant::now();
        let delay = probe_chain_http_head(&chain, &resolver, &url, false)
            .await
            .unwrap();

        assert_eq!(wall_started.elapsed(), Duration::from_millis(210));
        assert_eq!(delay, 40, "only final header + HEAD RTT should be measured");
    }

    #[tokio::test(start_paused = true)]
    async fn write_handshake_boundary_follows_the_selected_final_pool_member() {
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                DelayedHttpSocketConnector {
                    connect_delay: Duration::from_millis(5),
                    response_delay: Duration::ZERO,
                },
            ))],
            vec![vec![
                Box::new(TimedBoundaryProxyConnector::new(
                    1080,
                    Duration::from_millis(7),
                    Duration::from_millis(11),
                    false,
                )),
                Box::new(TimedBoundaryProxyConnector::new(
                    1081,
                    Duration::from_millis(13),
                    Duration::from_millis(17),
                    true,
                )),
            ]],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let target: ResolvedLocation =
            NetLocation::new(Address::from("example.com").unwrap(), 80).into();

        let (_, first_boundary) = chain
            .connect_tcp_with_write_handshake_boundary(target.clone(), &resolver)
            .await
            .unwrap();
        assert!(
            first_boundary.is_none(),
            "the first selected member has no write handshake"
        );

        let (_, second_boundary) = chain
            .connect_tcp_with_write_handshake_boundary(target, &resolver)
            .await
            .unwrap();
        let second_boundary = second_boundary.expect("second pool member should set a boundary");
        assert_eq!(second_boundary.elapsed(), Duration::from_millis(17));
    }

    #[tokio::test]
    async fn urltest_background_does_not_keep_replaced_group_alive() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let group = ClientChainGroup::new_with_selection(
            vec![chain],
            ClientChainSelectionConfig::UrlTest {
                shared_id: None,
                history_keys: Vec::new(),
                failure_history_keys: Vec::new(),
                url: format!("http://127.0.0.1:{port}/health"),
                use_native_roots: false,
                reselect_on_connection_failure: false,
                interval_millis: 60_000,
                tolerance_millis: 50,
                idle_timeout_millis: DEFAULT_URLTEST_IDLE_TIMEOUT_MILLIS,
            },
            resolver,
        );
        let weak_chains = Arc::downgrade(&group.chains);
        let weak_state = match &group.selection {
            ClientChainGroupSelection::UrlTest(state) => Arc::downgrade(state),
            ClientChainGroupSelection::RoundRobin => panic!("expected urltest selection"),
        };
        let weak_worker = Arc::downgrade(
            group
                .urltest_worker
                .as_ref()
                .expect("URLTest group must own its worker control"),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let measured = weak_state
                    .upgrade()
                    .is_some_and(|state| state.histories_millis.read()[0].is_some());
                if measured {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        server.await.unwrap();
        drop(group);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if weak_chains.upgrade().is_none()
                    && weak_state.upgrade().is_none()
                    && weak_worker.upgrade().is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("URLTest worker retained a dropped chain group");
    }

    #[tokio::test]
    async fn urltest_periodic_checks_start_on_touch_and_stop_when_idle() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let server_requests = server_requests.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 1024];
                    if stream.read(&mut request).await.unwrap_or(0) == 0 {
                        return;
                    }
                    server_requests.fetch_add(1, Ordering::Relaxed);
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
                });
            }
        });

        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let chain = crate::tcp::chain_builder::build_client_proxy_chain(
            crate::option_util::OneOrSome::One(crate::config::ClientChainHop::Single(
                crate::config::ConfigSelection::Config(crate::config::ClientConfig::default()),
            )),
            resolver.clone(),
        );
        let group = ClientChainGroup::new_with_selection(
            vec![chain],
            ClientChainSelectionConfig::UrlTest {
                shared_id: None,
                history_keys: Vec::new(),
                failure_history_keys: Vec::new(),
                url: format!("http://127.0.0.1:{port}/health"),
                use_native_roots: false,
                reselect_on_connection_failure: false,
                interval_millis: 50,
                tolerance_millis: 0,
                idle_timeout_millis: 150,
            },
            resolver,
        );
        let state = match &group.selection {
            ClientChainGroupSelection::UrlTest(state) => state,
            ClientChainGroupSelection::RoundRobin => panic!("expected urltest selection"),
        };
        let control = group.urltest_worker.as_deref().unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            requests.load(Ordering::Relaxed),
            1,
            "PostStart must not start the periodic ticker"
        );

        state.touch(control);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_millis(350)).await;
        let after_idle = requests.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            requests.load(Ordering::Relaxed),
            after_idle,
            "periodic URLTest probes must stop after idle_timeout"
        );

        state.touch(control);
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::Relaxed) <= after_idle {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("touch did not wake an idle URLTest group");

        drop(group);
        server.abort();
    }

    /// Mock SocketConnector that fails on connect (for unit testing structure).
    #[derive(Debug)]
    struct MockSocketConnector;

    #[async_trait]
    impl SocketConnector for MockSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            Err(std::io::Error::other(
                "MockSocketConnector::connect not implemented",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other(
                "MockSocketConnector::connect_udp_bidirectional not implemented",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    /// Mock ProxyConnector for testing.
    #[derive(Debug)]
    struct MockProxyConnector {
        location: NetLocation,
        supports_udp: bool,
        dns_resolver: Option<String>,
    }

    impl MockProxyConnector {
        fn new(port: u16, supports_udp: bool) -> Self {
            Self {
                location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
                supports_udp,
                dns_resolver: None,
            }
        }
    }

    #[async_trait]
    impl ProxyConnector for MockProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn dns_resolver(&self) -> Option<&str> {
            self.dns_resolver.as_deref()
        }

        fn supports_udp_over_tcp(&self) -> bool {
            self.supports_udp
        }

        async fn setup_tcp_stream(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Err(std::io::Error::other(
                "MockProxyConnector::setup_tcp_stream not implemented",
            ))
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::other(
                "MockProxyConnector::setup_udp_bidirectional not implemented",
            ))
        }
    }

    #[derive(Debug)]
    struct FixedResolver(std::net::SocketAddr);

    impl Resolver for FixedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            let address = self.0;
            Box::pin(async move { Ok(vec![address]) })
        }
    }

    #[derive(Debug)]
    struct TaggedResolver {
        expected_tag: &'static str,
        addresses: Vec<std::net::SocketAddr>,
        calls: AtomicUsize,
    }

    impl Resolver for TaggedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            Box::pin(async {
                Err(std::io::Error::other(
                    "the default resolver must not serve a tagged hop lookup",
                ))
            })
        }

        fn resolve_location_via(
            &self,
            upstream_tag: &str,
            _location: &NetLocation,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            assert_eq!(upstream_tag, self.expected_tag);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[derive(Debug)]
    struct NestedTaggedResolver {
        inner_tag: &'static str,
        inner_addresses: Vec<std::net::SocketAddr>,
        outer_tag: &'static str,
        outer_addresses: Vec<std::net::SocketAddr>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl Resolver for NestedTaggedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            Box::pin(async { Err(std::io::Error::other("unexpected default DNS lookup")) })
        }

        fn resolve_location_via(
            &self,
            upstream_tag: &str,
            _location: &NetLocation,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            self.calls.lock().push(upstream_tag.to_string());
            let result = if upstream_tag == self.inner_tag {
                Ok(self.inner_addresses.clone())
            } else if upstream_tag == self.outer_tag {
                Ok(self.outer_addresses.clone())
            } else {
                Err(std::io::Error::other(format!(
                    "unexpected DNS upstream tag {upstream_tag:?}"
                )))
            };
            Box::pin(async move { result })
        }
    }

    #[derive(Debug)]
    struct SerialAddressSocketConnector {
        attempts: Arc<Mutex<Vec<std::net::SocketAddr>>>,
        rejected: std::net::SocketAddr,
    }

    #[async_trait]
    impl SocketConnector for SerialAddressSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            let address = address
                .resolved_addr()
                .expect("named hop targets must be pre-resolved");
            self.attempts.lock().push(address);
            if address == self.rejected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "mock rejected first address",
                ));
            }
            let (stream, peer) = tokio::io::duplex(128);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            Ok(Box::new(TestDuplexStream(stream)))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "serial-address mock has no UDP support",
            ))
        }
    }

    #[derive(Debug)]
    struct PassThroughProxyConnector {
        location: NetLocation,
        dns_resolver: String,
        setup_calls: Arc<AtomicUsize>,
        fail_setup: bool,
        rejected_target: Option<std::net::SocketAddr>,
    }

    #[async_trait]
    impl ProxyConnector for PassThroughProxyConnector {
        fn proxy_location(&self) -> &NetLocation {
            &self.location
        }

        fn dns_resolver(&self) -> Option<&str> {
            Some(&self.dns_resolver)
        }

        fn supports_udp_over_tcp(&self) -> bool {
            false
        }

        async fn setup_tcp_stream(
            &self,
            stream: Box<dyn AsyncStream>,
            target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            self.setup_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_setup
                || self
                    .rejected_target
                    .is_some_and(|rejected| Some(rejected) == target.resolved_addr())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "mock proxy authentication failed",
                ));
            }
            Ok(TcpClientSetupResult {
                client_stream: stream,
                early_data: None,
            })
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pass-through mock has no UDP support",
            ))
        }
    }

    #[tokio::test]
    async fn subsequent_proxy_uses_its_named_resolver_before_the_preceding_hop() {
        let proxy = MockProxyConnector {
            location: NetLocation::new(Address::Hostname("next-hop.example".to_string()), 443),
            supports_udp: false,
            dns_resolver: Some("private-profile".to_string()),
        };
        let concrete = Arc::new(TaggedResolver {
            expected_tag: "private-profile",
            addresses: vec!["203.0.113.44:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let resolver: Arc<dyn Resolver> = concrete.clone();

        let targets = preceding_hop_targets(&proxy, &resolver).await.unwrap();
        assert_eq!(targets.len(), 1);
        let target = &targets[0];

        assert_eq!(
            target.location().to_socket_addr_nonblocking(),
            Some("203.0.113.44:443".parse().unwrap())
        );
        assert_eq!(
            target.resolved_addr(),
            Some("203.0.113.44:443".parse().unwrap())
        );
        assert_eq!(concrete.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            proxy.proxy_location().address().hostname(),
            Some("next-hop.example")
        );
    }

    #[tokio::test]
    async fn named_subsequent_proxy_retries_all_addresses_through_a_fresh_prefix() {
        let rejected = "203.0.113.40:443".parse().unwrap();
        let accepted = "203.0.113.41:443".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let setup_calls = Arc::new(AtomicUsize::new(0));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                SerialAddressSocketConnector {
                    attempts: attempts.clone(),
                    rejected,
                },
            ))],
            vec![vec![Box::new(PassThroughProxyConnector {
                location: NetLocation::new(
                    Address::Hostname("multi-address-hop.example".to_string()),
                    443,
                ),
                dns_resolver: "private-profile".to_string(),
                setup_calls: setup_calls.clone(),
                fail_setup: false,
                rejected_target: None,
            })]],
        );
        let concrete = Arc::new(TaggedResolver {
            expected_tag: "private-profile",
            addresses: vec![rejected, accepted],
            calls: AtomicUsize::new(0),
        });
        let resolver: Arc<dyn Resolver> = concrete.clone();
        let destination = ResolvedLocation::from(NetLocation::from_ip_addr(
            Ipv4Addr::new(198, 51, 100, 10).into(),
            80,
        ));

        let result = chain.connect_tcp(destination, &resolver).await;

        assert!(result.is_ok());
        assert_eq!(&*attempts.lock(), &[rejected, accepted]);
        assert_eq!(setup_calls.load(Ordering::SeqCst), 1);
        assert_eq!(concrete.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_protocol_failure_does_not_retry_its_server_addresses() {
        let first = "203.0.113.42:443".parse().unwrap();
        let second = "203.0.113.43:443".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let setup_calls = Arc::new(AtomicUsize::new(0));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                SerialAddressSocketConnector {
                    attempts: attempts.clone(),
                    rejected: "192.0.2.1:1".parse().unwrap(),
                },
            ))],
            vec![vec![Box::new(PassThroughProxyConnector {
                location: NetLocation::new(
                    Address::Hostname("auth-failure-hop.example".to_string()),
                    443,
                ),
                dns_resolver: "private-profile".to_string(),
                setup_calls: setup_calls.clone(),
                fail_setup: true,
                rejected_target: None,
            })]],
        );
        let concrete = Arc::new(TaggedResolver {
            expected_tag: "private-profile",
            addresses: vec![first, second],
            calls: AtomicUsize::new(0),
        });
        let resolver: Arc<dyn Resolver> = concrete;
        let destination = ResolvedLocation::from(NetLocation::from_ip_addr(
            Ipv4Addr::new(198, 51, 100, 11).into(),
            80,
        ));

        let error = chain
            .connect_tcp(destination, &resolver)
            .await
            .err()
            .expect("proxy setup must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(&*attempts.lock(), &[first]);
        assert_eq!(setup_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn outer_proxy_address_retry_rebuilds_and_reresolves_its_detour_prefix() {
        let inner_first = "203.0.113.50:8443".parse().unwrap();
        let inner_second = "203.0.113.51:8443".parse().unwrap();
        let outer_first = "203.0.113.60:9443".parse().unwrap();
        let outer_second = "203.0.113.61:9443".parse().unwrap();
        let socket_attempts = Arc::new(Mutex::new(Vec::new()));
        let resolver_calls = Arc::new(Mutex::new(Vec::new()));
        let inner_setup_calls = Arc::new(AtomicUsize::new(0));
        let outer_setup_calls = Arc::new(AtomicUsize::new(0));
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Box::new(
                SerialAddressSocketConnector {
                    attempts: socket_attempts.clone(),
                    rejected: inner_first,
                },
            ))],
            vec![
                vec![Box::new(PassThroughProxyConnector {
                    location: NetLocation::new(
                        Address::Hostname("inner-hop.example".to_string()),
                        8443,
                    ),
                    dns_resolver: "inner-profile".to_string(),
                    setup_calls: inner_setup_calls.clone(),
                    fail_setup: false,
                    rejected_target: Some(outer_first),
                })],
                vec![Box::new(PassThroughProxyConnector {
                    location: NetLocation::new(
                        Address::Hostname("outer-hop.example".to_string()),
                        9443,
                    ),
                    dns_resolver: "outer-profile".to_string(),
                    setup_calls: outer_setup_calls.clone(),
                    fail_setup: false,
                    rejected_target: None,
                })],
            ],
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NestedTaggedResolver {
            inner_tag: "inner-profile",
            inner_addresses: vec![inner_first, inner_second],
            outer_tag: "outer-profile",
            outer_addresses: vec![outer_first, outer_second],
            calls: resolver_calls.clone(),
        });
        let destination = ResolvedLocation::from(NetLocation::from_ip_addr(
            Ipv4Addr::new(198, 51, 100, 12).into(),
            80,
        ));

        let result = chain.connect_tcp(destination, &resolver).await;

        assert!(
            result.is_ok(),
            "nested proxy connection failed: {}",
            result.err().expect("failed result must contain an error")
        );
        assert_eq!(
            &*socket_attempts.lock(),
            &[inner_first, inner_second, inner_first, inner_second]
        );
        assert_eq!(
            &*resolver_calls.lock(),
            &["outer-profile", "inner-profile", "inner-profile"]
        );
        assert_eq!(inner_setup_calls.load(Ordering::SeqCst), 2);
        assert_eq!(outer_setup_calls.load(Ordering::SeqCst), 1);
    }

    fn mock_socket(_id: usize) -> Box<dyn SocketConnector> {
        Box::new(MockSocketConnector)
    }

    fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
        Box::new(MockProxyConnector::new(port, supports_udp))
    }

    fn direct_entry(id: usize) -> InitialHopEntry {
        InitialHopEntry::Direct(mock_socket(id))
    }

    fn proxy_entry(id: usize, port: u16, supports_udp: bool) -> InitialHopEntry {
        InitialHopEntry::Proxy {
            socket: mock_socket(id),
            proxy: mock_proxy(port, supports_udp),
        }
    }

    #[test]
    fn test_initial_hop_entry_direct_supports_udp() {
        let entry = direct_entry(0);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_supports_udp() {
        let entry = proxy_entry(0, 1080, true);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_no_udp() {
        let entry = proxy_entry(0, 1080, false);
        assert!(!entry.supports_udp());
    }

    #[test]
    fn test_chain_single_direct() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy_no_udp() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, true)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent_no_udp() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, false)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp()); // Subsequent doesn't support UDP
    }

    #[test]
    fn test_chain_proxy_with_subsequent() {
        let chain = ClientProxyChain::new(
            vec![proxy_entry(0, 1080, true)],
            vec![vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_mixed_initial_pool() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // VMess proxy
                proxy_entry(1, 1081, true), // VLESS proxy
                direct_entry(2),            // Direct
            ],
            vec![],
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
        // All 3 entries support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_chain_mixed_initial_pool_partial_udp() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // No UDP
                proxy_entry(1, 1081, true),  // Has UDP
                direct_entry(2),             // Has UDP
            ],
            vec![],
        );
        assert!(chain.supports_udp());
        // Only entries 1 and 2 support UDP (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_two_subsequent_hops() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pool_at_subsequent_hop() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(1080, true),
                mock_proxy(1081, false),
                mock_proxy(1082, true),
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp()); // At least one in pool supports UDP
    }

    #[test]
    #[should_panic(expected = "must have at least one initial hop entry")]
    fn test_chain_empty_initial_hop_panics() {
        ClientProxyChain::new(vec![], vec![]);
    }

    #[test]
    fn test_group_single_chain() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        let group = ClientChainGroup::new(vec![chain]);
        assert!(group.supports_udp());
    }

    #[test]
    #[should_panic(expected = "must have at least one chain")]
    fn test_group_empty_chains_panics() {
        ClientChainGroup::new(vec![]);
    }

    #[test]
    fn test_group_mixed_udp_support() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0]);
    }

    #[test]
    fn test_group_all_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![direct_entry(1)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0, 1]);
    }

    #[test]
    fn test_group_none_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(!group.supports_udp());
        assert!(group.udp_chain_indices.is_empty());
    }

    #[test]
    fn test_pool_pairing_fix_socket_proxy_always_paired() {
        // Create a mixed pool simulating: vmess@1080, vless@1081, direct
        // Each with a unique socket ID matching its position
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // socket_id=0, proxy_port=1080
                proxy_entry(1, 1081, true), // socket_id=1, proxy_port=1081
                direct_entry(2),            // socket_id=2, no proxy
            ],
            vec![],
        );

        // Select entries multiple times and verify pairing
        // Round-robin should cycle: 0, 1, 2, 0, 1, 2, ...
        for iteration in 0..6 {
            let entry = chain.select_initial_hop_entry();
            let expected_idx = iteration % 3;

            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 0: should be vmess proxy at port 1080
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1080,
                        "Iteration {}: expected proxy port 1080, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    // Entry 1: should be vless proxy at port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "Iteration {}: expected proxy port 1081, got {}",
                        iteration,
                        proxy.proxy_location().port()
                    );
                }
                (2, InitialHopEntry::Direct(_)) => {
                    // Entry 2: should be direct (no proxy)
                    // This is correct - direct has no proxy to mismatch
                }
                (idx, entry) => {
                    panic!(
                        "Iteration {}: unexpected entry type at index {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_pool_pairing_fix_udp_selection_also_paired() {
        // Create a mixed pool where only some support UDP
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // socket_id=0, NO UDP
                proxy_entry(1, 1081, true),  // socket_id=1, HAS UDP, port 1081
                direct_entry(2),             // socket_id=2, HAS UDP (direct always does)
            ],
            vec![],
        );

        // UDP selection should only return entries 1 and 2 (initial hop IS final hop)
        assert!(chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify UDP selection cycles through UDP-capable entries only
        // Manually select using the new logic
        for iteration in 0..4 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let entry = &chain.initial_hop[pool_idx];
            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_initial_hop_indices

            match (expected_udp_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    // UDP index 0 -> initial_hop[1] -> port 1081
                    assert_eq!(
                        proxy.proxy_location().port(),
                        1081,
                        "UDP iteration {}: expected proxy port 1081",
                        iteration
                    );
                }
                (1, InitialHopEntry::Direct(_)) => {
                    // UDP index 1 -> initial_hop[2] -> direct
                    // Correct!
                }
                (idx, entry) => {
                    panic!(
                        "UDP iteration {}: unexpected at udp_idx {}. Entry: {:?}",
                        iteration, idx, entry
                    );
                }
            }
        }
    }

    #[test]
    fn test_udp_selection_with_subsequent_hops() {
        // Test that when udp_uses_initial_hop = false, we select:
        // - Initial hop normally (from all entries)
        // - Final hop from udp_final_hop_indices
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP (but should be usable for UDP!)
                proxy_entry(1, 1081, false), // Another HTTP
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert!(!chain.udp_uses_initial_hop);
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

        // Verify that initial hop selection would use all entries (indices 0 and 1)
        // We can't easily test this without calling connect_udp_bidirectional(), but we can verify
        // that the normal round-robin will cycle through both
        for i in 0..4 {
            let entry = chain.select_initial_hop_entry();
            let expected_idx = i % 2;
            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1080);
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1081);
                }
                _ => panic!("Unexpected entry"),
            }
        }

        // Verify that final hop selection cycles through udp_final_hop_indices only
        let final_hop = chain.subsequent_hops.last().unwrap();
        for iteration in 0..6 {
            let idx = chain
                .udp_final_hop_next_index
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
            let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
            let proxy = &final_hop[pool_idx];

            let expected_udp_idx = iteration % 2; // 0 or 1 in udp_final_hop_indices
            match expected_udp_idx {
                0 => {
                    // udp_final_hop_indices[0] = 1 -> VMess at port 443
                    assert_eq!(proxy.proxy_location().port(), 443);
                }
                1 => {
                    // udp_final_hop_indices[1] = 2 -> VLESS at port 444
                    assert_eq!(proxy.proxy_location().port(), 444);
                }
                _ => panic!("Unexpected index"),
            }
        }
    }

    #[test]
    fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
        // Test the key insight: when has subsequent hops, udp_final_hop_indices
        // points to the FINAL subsequent hop, not the initial hop
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false), // HTTP - no UDP
                proxy_entry(1, 1081, true),  // SOCKS5 - has UDP (irrelevant!)
            ],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP (index 0)
                mock_proxy(443, true),   // VMess - has UDP (index 1)
                mock_proxy(444, true),   // VLESS - has UDP (index 2)
            ]],
        );

        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());

        // Key: udp_uses_initial_hop should be FALSE
        assert!(!chain.udp_uses_initial_hop);

        // udp_final_hop_indices should point to indices in the FINAL subsequent hop
        // NOT the initial hop! Only indices 1 and 2 (VMess, VLESS) support UDP
        assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
        // direct -> http (no UDP) -> vmess (has UDP)
        // Should support UDP because only final hop matters
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_all_intermediate_no_udp_final_has_udp() {
        // direct -> http -> socks5 -> vmess
        // Three intermediate hops, none with UDP, but final has UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![mock_proxy(443, true)],   // VMess - has UDP
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[test]
    fn test_chain_intermediate_has_udp_final_no_udp() {
        // direct -> vmess (has UDP) -> http (no UDP)
        // Should NOT support UDP because final hop doesn't
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(443, true)],   // VMess - has UDP
                vec![mock_proxy(8080, false)], // HTTP - no UDP
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_partial_udp() {
        // direct -> [http (no UDP), vmess (has UDP), vless (has UDP)]
        // Should support UDP because final hop pool has UDP-capable connectors
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(443, true),   // VMess - has UDP
                mock_proxy(444, true),   // VLESS - has UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_no_udp() {
        // direct -> [http, socks5] (neither has UDP)
        // Should NOT support UDP
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false), // HTTP - no UDP
                mock_proxy(1080, false), // SOCKS5 - no UDP
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_complex_multi_hop_mixed_udp() {
        // direct -> http (no UDP) -> socks5 (no UDP) -> [http (no), vmess (yes)]
        // Should support UDP: intermediate hops don't matter, final pool has vmess
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)], // HTTP - no UDP
                vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
                vec![
                    mock_proxy(8081, false), // HTTP - no UDP
                    mock_proxy(443, true),   // VMess - has UDP
                ],
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp()); // This was the bug - old code returned false
    }

    #[tokio::test]
    async fn proxy_candidate_fallback_preserves_hostname_and_returns_second_peer() {
        let first: std::net::SocketAddr = "192.0.2.1:53".parse().unwrap();
        let second: std::net::SocketAddr = "192.0.2.2:53".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let proxy = CandidateFallbackProxy {
            location: NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 1080),
            rejected: first,
            requires_literal_udp_target: false,
            attempts: Arc::clone(&attempts),
        };
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket: Box::new(PassTcpSocketConnector),
                proxy: Box::new(proxy),
            }],
            Vec::new(),
        );
        let group = ClientChainGroup::new(vec![chain]);
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let original = NetLocation::new(Address::Hostname("candidate.example".to_string()), 53);
        let mut target = ResolvedLocation::from(original.clone());
        target.set_resolved_addrs(vec![first, second]);

        let result = group
            .connect_udp_bidirectional_with_peer(&resolver, target)
            .await
            .unwrap();

        assert_eq!(result.remote_addr, second);
        assert_eq!(
            attempts.lock().as_slice(),
            &[(original.clone(), first), (original, second)]
        );
    }

    #[tokio::test]
    async fn proxy_with_ip_only_udp_wire_receives_literal_candidate() {
        let candidate: std::net::SocketAddr = "192.0.2.8:53".parse().unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let proxy = CandidateFallbackProxy {
            location: NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 1080),
            rejected: "192.0.2.9:53".parse().unwrap(),
            requires_literal_udp_target: true,
            attempts: Arc::clone(&attempts),
        };
        let chain = ClientProxyChain::new(
            vec![InitialHopEntry::Proxy {
                socket: Box::new(PassTcpSocketConnector),
                proxy: Box::new(proxy),
            }],
            Vec::new(),
        );
        let group = ClientChainGroup::new(vec![chain]);
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let original = NetLocation::new(Address::Hostname("candidate.example".to_string()), 53);
        let target = ResolvedLocation::with_resolved(original, candidate);

        let result = group
            .connect_udp_bidirectional_with_peer(&resolver, target)
            .await
            .unwrap();

        assert_eq!(result.remote_addr, candidate);
        assert_eq!(
            attempts.lock().as_slice(),
            &[(
                NetLocation::from_ip_addr(candidate.ip(), candidate.port()),
                candidate
            )]
        );
    }
}
