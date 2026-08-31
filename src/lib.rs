// This library shares code with the shoes binary. Server-side code appears "unused"
// in lib builds but is used by: (1) the binary for server mode, (2) FFI for mobile.
// The client/server code is intermingled within modules - a proper fix would require
// splitting into separate client/server modules or using feature flags.
#![allow(dead_code)]

//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the core functionality for shoes, enabling it to be
//! embedded in mobile applications (Android/iOS) as a VPN backend.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! The embedding node-agent reports this value in ACP's historical
//! `sing_box_version` field.
//!
//! # Mobile Integration
//!
//! For Android, use the FFI module:
//!
//! ```kotlin
//! // Load native library
//! System.loadLibrary("shoes")
//!
//! // Initialize
//! ShoesNative.init("info")
//!
//! // Start VPN with TUN fd from VpnService
//! val handle = ShoesNative.startTun(tunFd, configYaml, protectCallback)
//!
//! // Stop VPN
//! ShoesNative.stop(handle)
//! ```
//!
//! For iOS, use the C FFI module from Swift:
//!
//! ```swift
//! // Initialize
//! shoes_init("info")
//!
//! // Start VPN with packet tunnel fd
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Android (arm64-v8a, armeabi-v7a, x86_64)
//! - iOS (arm64)

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Modules are declared here (mirroring main.rs) so the library crate can
// expose them for FFI/mobile integration.
mod address;
mod anytls;
mod async_stream;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
pub mod dns;
pub mod dynamic;
mod h2mux;
mod http_handler;
pub mod hysteria2;
mod hysteria2_client;
mod hysteria2_masquerade;
/// Salamander, Hysteria2's UDP obfuscation.
///
/// Public for the same reason [`dynamic::credential`] is: it is a wire format,
/// and anything speaking to or standing in for a Hysteria2 peer -- a client, a
/// test harness -- has to derive exactly the same bytes.
pub mod hysteria2_obfs;
mod hysteria2_server;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod replay_filter;
pub mod resolver;
mod routing;

/// Validate a sing-box route rule-set with the exact parser and support policy
/// used by shoes selectors. Control-plane adapters use this before publishing
/// remotely downloaded bytes as a durable last-good resource.
pub fn validate_route_rule_set(format: &str, bytes: &[u8]) -> Result<(), String> {
    let parsed =
        routing::srs::parse_bytes_named(format, bytes).map_err(|error| error.to_string())?;
    if parsed.is_fully_supported() {
        Ok(())
    } else {
        Err("rule-set contains predicates shoes cannot evaluate without widening it".into())
    }
}
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
pub mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
mod stream_reader;
mod sync_adapter;
pub mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
pub mod tun;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
