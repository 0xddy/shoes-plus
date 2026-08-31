//! TUN device support for shoes.
//!
//! This module provides VPN functionality by accepting IP packets from a TUN
//! device and routing TCP/UDP traffic through configured proxy chains.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │   TUN Device    │ ←→  │  shoes/smoltcp  │ ←→  │  Proxy Chain    │
//! │ (IP packets)    │     │ (our TCP stack) │     │ (VLESS, etc.)   │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! The smoltcp stack runs in a dedicated OS thread with direct fd access,
//! using `select()` for efficient event-driven I/O.
//!
//! # Platform Support
//!
//! - **Linux**: Creates TUN device with specified name/address. Requires root
//!   privileges or `CAP_NET_ADMIN` capability.
//!
//! - **Android**: Accepts raw FD from `VpnService.Builder.establish()`. The
//!   VPN configuration (routes, DNS, etc.) is handled by the Android VpnService.
//!   You must pass the FD via `TunServerConfig::raw_fd()`.
//!
//! - **iOS/macOS**: Accepts raw FD from `NEPacketTunnelProvider.packetFlow`.
//!   Use `TunServerConfig::packet_information(true)` if using the socket FD
//!   directly, or `false` if using the readPackets/writePackets API.

mod tcp_conn;
mod tcp_stack_direct;
mod tun_server;
mod udp_handler;
mod udp_manager;

// Platform module only needed for mobile FFI targets
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
mod platform;
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub use platform::{
    FnSocketProtector, NoOpPlatformCallbacks, NoOpSocketProtector, PlatformCallbacks,
    PlatformInterface, SocketProtector, get_global_socket_protector, protect_socket,
    set_global_socket_protector,
};

pub use tun_server::TunServerConfig;

use std::net::SocketAddr;
use std::os::unix::io::IntoRawFd;
use std::sync::Arc;

use log::{debug, info, warn};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::config::TunConfig;
use crate::config::selection::ConfigSelection;
use crate::resolver::{NativeResolver, Resolver};
use crate::routing::protocol::sniff_tcp;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

use tcp_stack_direct::{NewTcpConnection, TcpStackDirect};
use udp_manager::TunUdpManager;

type PacketBuffer = Vec<u8>;

/// Run the TUN server with the given configuration.
///
/// This function:
/// 1. Creates/wraps a TUN device
/// 2. Sets up our smoltcp-based TCP/IP stack with direct fd access
/// 3. The stack thread reads packets directly from TUN using select()
/// 4. Handles TCP connections through the proxy chain
/// 5. Handles UDP packets through tokio (forwarded from stack thread)
pub async fn run_tun_server(
    config: TunServerConfig,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    info!(
        "Starting TUN server (direct mode): mtu={}, tcp={}, udp={}, icmp={}",
        config.mtu, config.tcp_enabled, config.udp_enabled, config.icmp_enabled
    );

    let fd = if let Some(fd) = config.raw_fd {
        info!("Using provided raw FD: {}", fd);
        fd
    } else {
        let tun_device = config.create_sync_device()?;
        let fd = tun_device.into_raw_fd();
        info!("Created TUN device with FD: {}", fd);
        fd
    };

    let mtu = config.mtu as usize;

    // Create the direct TCP stack (runs smoltcp in dedicated thread with select())
    let mut tcp_stack = TcpStackDirect::new(fd, mtu);

    // Get UDP receiver (stack thread filters UDP and sends here)
    let udp_from_stack_rx = tcp_stack.take_udp_rx().expect("udp_rx already taken");

    // Channel for sending UDP responses back (stack thread will write to TUN)
    let (udp_to_stack_tx, udp_to_stack_rx) = mpsc::unbounded_channel::<PacketBuffer>();
    tcp_stack.set_udp_response_tx(udp_to_stack_rx);

    let (tcp_conn_tx, mut tcp_conn_rx) = mpsc::unbounded_channel::<NewTcpConnection>();
    tcp_stack.set_new_conn_tx(tcp_conn_tx);

    let tcp_task: Option<JoinHandle<()>> = if config.tcp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();

        Some(tokio::spawn(async move {
            info!("Starting TCP connection handler");

            while let Some(new_conn) = tcp_conn_rx.recv().await {
                let proxy_selector = proxy_selector.clone();
                let resolver = resolver.clone();

                tokio::spawn(async move {
                    let remote_addr = new_conn.remote_addr;
                    let target = socket_addr_to_net_location(remote_addr);

                    debug!("Handling TCP connection to {:?}", target);

                    if let Err(e) =
                        handle_tcp_connection(new_conn.connection, target, proxy_selector, resolver)
                            .await
                    {
                        debug!("TCP connection to {} failed: {}", remote_addr, e);
                    }
                });
            }

            debug!("TCP connection handler ended");
        }))
    } else {
        None
    };

    let udp_task = if config.udp_enabled {
        let proxy_selector = proxy_selector.clone();
        let resolver = resolver.clone();

        Some(tokio::spawn(async move {
            handle_udp_packets(udp_from_stack_rx, udp_to_stack_tx, proxy_selector, resolver).await;
        }))
    } else {
        None
    };

    info!("TUN server started successfully");

    // Wait for shutdown signal or stack thread exit
    tokio::select! {
        _ = &mut shutdown_rx => {
            info!("TUN server shutdown requested");
        }
        _ = async {
            // Poll until stack stops running
            while tcp_stack.is_running() {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        } => {
            warn!("Stack thread ended unexpectedly");
        }
    }

    if let Some(t) = tcp_task {
        t.abort();
    }
    if let Some(t) = udp_task {
        t.abort();
    }

    // tcp_stack is dropped here, which stops the stack thread

    info!("TUN server stopped");
    Ok(())
}

/// Convert a SocketAddr to a NetLocation.
fn socket_addr_to_net_location(addr: SocketAddr) -> NetLocation {
    let address = match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
        std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
    };
    NetLocation::new(address, addr.port())
}

/// Handle a TCP connection by forwarding it through the proxy chain.
async fn handle_tcp_connection(
    connection: tcp_conn::TcpConnection,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let mut connection: Box<dyn AsyncStream> = Box::new(connection);
    let mut replay = Vec::new();
    let sniffed = if proxy_selector.needs_tcp_sniff() {
        sniff_tcp(&mut connection, &mut replay).await?
    } else {
        None
    };

    let decision = match sniffed {
        Some(metadata) => {
            proxy_selector
                .judge_sniffed_tcp(target.into(), &resolver, metadata.protocol, metadata.domain)
                .await?
        }
        None => proxy_selector.judge_tcp(target.into(), &resolver).await?,
    };
    let (chain_group, remote_location) = match decision {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => (chain_group, remote_location),
        ConnectDecision::Block => {
            debug!("TCP connection blocked by rules");
            return Ok(());
        }
    };

    debug!(
        "TCP: connecting to {} via chain",
        remote_location.location()
    );
    let setup_result = chain_group
        .connect_tcp(remote_location.clone(), &resolver)
        .await
        .inspect_err(|error| {
            warn!(
                "Failed to connect to {}: {error}",
                remote_location.location()
            );
        })?;
    let mut remote = setup_result.client_stream;
    if let Some(early_data) = setup_result.early_data {
        connection.write_all(&early_data).await?;
        connection.flush().await?;
    }

    // Every byte consumed by the bounded sniffer is replayed before the normal
    // relay starts, exactly as it is for socket and QUIC inbounds.
    if !replay.is_empty() {
        remote.write_all(&replay).await?;
        remote.flush().await?;
    }

    debug!(
        "TCP: connected to {}, starting bidirectional copy",
        remote_location.location()
    );
    match tokio::io::copy_bidirectional(&mut connection, &mut remote).await {
        Ok((client_to_remote, remote_to_client)) => {
            debug!(
                "TCP connection to {} completed: {client_to_remote} bytes sent, \
                 {remote_to_client} bytes received",
                remote_location.location()
            );
        }
        Err(error) => {
            debug!(
                "TCP connection to {} error: {error}",
                remote_location.location()
            );
        }
    }

    Ok(())
}

/// Handle UDP packets from the stack thread.
///
/// Uses the session-based TunUdpManager which:
/// - Keys sessions by local (app) address, not by destination
/// - Stores the return address in each session
/// - Routes responses using the stored address (no NAT table lookup)
async fn handle_udp_packets(
    from_stack_rx: mpsc::UnboundedReceiver<PacketBuffer>,
    to_stack_tx: mpsc::UnboundedSender<PacketBuffer>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) {
    info!("Starting UDP handler (session-based)");

    let udp_handler = udp_handler::UdpHandler::new(from_stack_rx, to_stack_tx);
    let (reader, writer) = udp_handler.split();

    let manager = TunUdpManager::new(reader, writer, proxy_selector, resolver);

    if let Err(e) = manager.run().await {
        warn!("UDP handler error: {}", e);
    }

    info!("UDP handler stopped");
}

/// Start TUN server based on the provided configuration.
pub async fn start_tun_server(
    mut config: TunConfig,
    resolver: std::sync::Arc<dyn crate::resolver::Resolver>,
) -> std::io::Result<JoinHandle<()>> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // Build the selector before spawning: Tokio task-local embedder state is not
    // inherited by child tasks, and logical URLTest outbounds must join the same
    // generation-scoped registry as ordinary listeners and DNS detours.
    let client_proxy_selector = take_client_proxy_selector(&mut config, resolver.clone());

    let handle = tokio::spawn(async move {
        let _keep_alive = shutdown_tx;
        if let Err(e) = run_tun_from_config_with_selector(
            config,
            client_proxy_selector,
            resolver,
            shutdown_rx,
            true,
        )
        .await
        {
            warn!("TUN server error: {}", e);
        }
    });

    Ok(handle)
}

/// Run TUN server from config with external shutdown control.
pub async fn run_tun_from_config(
    mut config: TunConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let client_proxy_selector = take_client_proxy_selector(&mut config, resolver.clone());
    run_tun_from_config_with_selector(
        config,
        client_proxy_selector,
        resolver,
        shutdown_rx,
        close_fd_on_drop,
    )
    .await
}

fn take_client_proxy_selector(
    config: &mut TunConfig,
    resolver: Arc<dyn Resolver>,
) -> Arc<ClientProxySelector> {
    let rules = std::mem::take(&mut config.rules)
        .map(ConfigSelection::unwrap_config)
        .into_vec();
    Arc::new(create_tcp_client_proxy_selector(rules, resolver))
}

async fn run_tun_from_config_with_selector(
    config: TunConfig,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    close_fd_on_drop: bool,
) -> std::io::Result<()> {
    let mut tun_server_config = TunServerConfig::new()
        .mtu(config.mtu)
        .tcp_enabled(config.tcp_enabled)
        .udp_enabled(config.udp_enabled)
        .icmp_enabled(config.icmp_enabled)
        .close_fd_on_drop(close_fd_on_drop);

    if let Some(ref name) = config.device_name {
        tun_server_config = tun_server_config.tun_name(name.clone());
        println!("Starting TUN server on device {}", name);
    }
    if let Some(fd) = config.device_fd {
        tun_server_config = tun_server_config.raw_fd(fd);
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            tun_server_config = tun_server_config.packet_information(true);
        }
        println!("Starting TUN server from device FD {}", fd);
    }
    if let Some(addr) = config.address {
        tun_server_config = tun_server_config.address(addr);
    }
    if let Some(mask) = config.netmask {
        tun_server_config = tun_server_config.netmask(mask);
    }
    if let Some(dest) = config.destination {
        tun_server_config = tun_server_config.destination(dest);
    }

    run_tun_server(
        tun_server_config,
        client_proxy_selector,
        resolver,
        shutdown_rx,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_proxy_chain::{ClientChainGroupRegistry, with_client_chain_group_registry};

    #[tokio::test]
    async fn tun_selector_joins_the_embedder_urltest_registry_before_spawn() {
        let mut config: TunConfig = serde_yaml::from_str("{}").unwrap();
        let mut rule = crate::config::RuleConfig::default();
        let crate::config::RuleActionConfig::Allow {
            client_chain_selection,
            ..
        } = &mut rule.action
        else {
            unreachable!("the default rule allows direct traffic")
        };
        *client_chain_selection = crate::config::ClientChainSelectionConfig::UrlTest {
            shared_id: Some("node-agent-urltest-v1:tun-shared".to_string()),
            history_keys: Vec::new(),
            failure_history_keys: Vec::new(),
            url: "http://127.0.0.1:9/generate_204".to_string(),
            use_native_roots: false,
            reselect_on_connection_failure: false,
            interval_millis: 60_000,
            tolerance_millis: 0,
            idle_timeout_millis: 1_800_000,
        };
        config.rules = crate::option_util::NoneOrSome::One(ConfigSelection::Config(rule));
        let registry = ClientChainGroupRegistry::default();
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        registry
            .bind_probe_resolver([4; 32], resolver.clone())
            .unwrap();

        let selector = with_client_chain_group_registry(registry.clone(), async {
            take_client_proxy_selector(&mut config, resolver)
        })
        .await;

        assert_eq!(registry.active_group_count(), 1);
        assert!(config.rules.is_empty());
        registry.start_pending();
        drop(selector);
        assert_eq!(registry.active_group_count(), 1);
    }
}
