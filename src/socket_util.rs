use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(unix)]
use std::mem::ManuallyDrop;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_family = "unix")]
use std::path::Path;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Per-direction kernel buffer target used by high-throughput QUIC endpoints.
///
/// This is the value passed to `SO_RCVBUF` / `SO_SNDBUF`. FreeBSD and Darwin
/// may require their system-wide `kern.ipc.maxsockbuf` ceiling to be about 15%
/// larger, but that padding is not part of the socket's requested buffer size.
#[cfg(not(target_os = "openbsd"))]
pub(crate) const QUIC_UDP_SOCKET_BUFFER_TARGET: usize = 8 * 1024 * 1024;

/// OpenBSD rejects socket-buffer requests above its fixed 2 MiB `SB_MAX`
/// instead of clamping them, and that limit is not a runtime sysctl.
#[cfg(target_os = "openbsd")]
pub(crate) const QUIC_UDP_SOCKET_BUFFER_TARGET: usize = 2 * 1024 * 1024;

/// Socket-level options shared by direct TCP and UDP outbound dials.
///
/// QUIC intentionally continues to use its existing endpoint setup. Configuration
/// validation rejects these options for QUIC transports until that path can provide
/// identical behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundSocketOptions {
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<Ipv4Addr>,
    pub inet6_bind_address: Option<Ipv6Addr>,
    pub routing_mark: u32,
    pub bind_address_no_port: bool,
}

impl OutboundSocketOptions {
    fn bind_address(&self, is_ipv6: bool) -> Option<SocketAddr> {
        if is_ipv6 {
            self.inet6_bind_address
                .map(|address| SocketAddr::new(IpAddr::V6(address), 0))
        } else {
            self.inet4_bind_address
                .map(|address| SocketAddr::new(IpAddr::V4(address), 0))
        }
    }
}

fn validate_platform_options(options: &OutboundSocketOptions) -> std::io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        if options.routing_mark != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "routing_mark is only supported on Linux",
            ));
        }
        if options.bind_address_no_port {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "bind_address_no_port is only supported on Linux",
            ));
        }
    }
    let _ = options;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_routing_mark(socket: &Socket, routing_mark: u32) -> std::io::Result<()> {
    if routing_mark != 0 {
        socket.set_mark(routing_mark)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_routing_mark(_socket: &Socket, _routing_mark: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_bind_address_no_port(socket: &Socket) -> std::io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // Match sing-box: old kernels and address families that do not expose the
    // option fall back to ordinary source-port reservation.
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOPROTOOPT) | Some(libc::EINVAL)
    ) {
        Ok(())
    } else {
        Err(error)
    }
}

/// Create an outbound TCP socket, applying source-address and Linux dial options
/// before the source bind and connect.
pub fn new_outbound_tcp_socket(
    is_ipv6: bool,
    options: &OutboundSocketOptions,
) -> std::io::Result<tokio::net::TcpSocket> {
    validate_platform_options(options)?;

    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;

    if let Some(ref _interface) = options.bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(_interface.as_bytes()))?;

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bind_interface is only available on Android, Fuchsia, or Linux",
        ));
    }

    apply_routing_mark(&socket, options.routing_mark)?;
    #[cfg(target_os = "linux")]
    if options.bind_address_no_port {
        // Linux only applies IP_BIND_ADDRESS_NO_PORT to TCP dial sockets;
        // unconnected UDP listener sockets intentionally retain normal binding.
        set_bind_address_no_port(&socket)?;
    }
    if let Some(bind_address) = options.bind_address(is_ipv6) {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    let stream: std::net::TcpStream = socket.into();
    Ok(tokio::net::TcpSocket::from_std_stream(stream))
}

/// Create a direct outbound UDP socket bound to the configured source address
/// for the destination address family.
pub fn new_outbound_udp_socket(
    is_ipv6: bool,
    options: &OutboundSocketOptions,
) -> std::io::Result<tokio::net::UdpSocket> {
    new_outbound_udp_socket_inner(is_ipv6, options, None)
}

/// Create an outbound UDP socket with an explicit best-effort kernel buffer
/// request, while preserving all source-address and Linux routing options.
pub(crate) fn new_outbound_udp_socket_with_buffer_size(
    is_ipv6: bool,
    options: &OutboundSocketOptions,
    buffer_size: usize,
) -> std::io::Result<tokio::net::UdpSocket> {
    new_outbound_udp_socket_inner(is_ipv6, options, Some(buffer_size))
}

fn new_outbound_udp_socket_inner(
    is_ipv6: bool,
    options: &OutboundSocketOptions,
    buffer_size: Option<usize>,
) -> std::io::Result<tokio::net::UdpSocket> {
    validate_platform_options(options)?;
    let socket = new_socket2_udp_socket_with_buffer_size(
        is_ipv6,
        options.bind_interface.clone(),
        None,
        false,
        buffer_size,
    )?;
    apply_routing_mark(&socket, options.routing_mark)?;
    let bind_address = options
        .bind_address(is_ipv6)
        .unwrap_or_else(|| get_unspecified_socket_addr(is_ipv6));
    socket.bind(&SockAddr::from(bind_address))?;
    into_tokio_udp_socket(socket)
}

pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
        false,
    )?;

    into_tokio_udp_socket(socket)
}

fn get_unspecified_socket_addr(is_ipv6: bool) -> SocketAddr {
    if !is_ipv6 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    } else {
        "[::]:0".parse().unwrap()
    }
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    new_socket2_udp_socket_with_buffer_size(is_ipv6, bind_interface, bind_address, reuse_port, None)
}

/// Whether this platform can put more than one socket on a single UDP port.
///
/// QUIC servers use `SO_REUSEPORT` to run an endpoint per thread on one port, and
/// asking for it where it does not exist is a panic below rather than an error.
/// Windows' `SO_REUSEADDR` is not a substitute: the binds would succeed and then
/// every datagram would go to just one of the sockets, so the only safe number of
/// endpoints on such a platform is one.
pub const fn supports_reuse_port() -> bool {
    cfg!(all(
        unix,
        not(any(target_os = "solaris", target_os = "illumos"))
    ))
}

#[derive(Clone, Copy)]
enum UdpBufferDirection {
    Receive,
    Send,
}

impl UdpBufferDirection {
    fn name(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Send => "send",
        }
    }

    fn set(self, socket: &Socket, size: usize) -> std::io::Result<()> {
        match self {
            Self::Receive => socket.set_recv_buffer_size(size),
            Self::Send => socket.set_send_buffer_size(size),
        }
    }

    fn get(self, socket: &Socket) -> std::io::Result<usize> {
        match self {
            Self::Receive => socket.recv_buffer_size(),
            Self::Send => socket.send_buffer_size(),
        }
    }

    fn warn_once(self, warning: impl FnOnce()) {
        static RECEIVE_WARNING: std::sync::Once = std::sync::Once::new();
        static SEND_WARNING: std::sync::Once = std::sync::Once::new();

        match self {
            Self::Receive => RECEIVE_WARNING.call_once(warning),
            Self::Send => SEND_WARNING.call_once(warning),
        }
    }
}

fn udp_buffer_is_large_enough(actual: usize, requested: usize) -> bool {
    actual >= requested
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_udp_buffer_size(
    socket: &Socket,
    direction: UdpBufferDirection,
    size: usize,
) -> std::io::Result<()> {
    let size = libc::c_int::try_from(size).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP socket buffer size does not fit in c_int",
        )
    })?;
    let option = match direction {
        UdpBufferDirection::Receive => libc::SO_RCVBUFFORCE,
        UdpBufferDirection::Send => libc::SO_SNDBUFFORCE,
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&size).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Best-effort socket-buffer setup for high-throughput UDP transports.
///
/// Linux silently caps a successful `SO_RCVBUF`/`SO_SNDBUF` call at the
/// corresponding `net.core.*mem_max`. Verify the effective size and, when the
/// process has `CAP_NET_ADMIN`, retry with the force option just as quic-go
/// does. Socket creation remains best effort on every platform, but a capped
/// buffer is no longer invisible to operators.
fn configure_udp_buffer(socket: &Socket, direction: UdpBufferDirection, requested: usize) {
    // Preserve an operator- or platform-provided buffer that already exceeds our
    // target. Calling setsockopt unconditionally could silently shrink it.
    if direction
        .get(socket)
        .is_ok_and(|actual| udp_buffer_is_large_enough(actual, requested))
    {
        return;
    }

    let set_error = direction.set(socket, requested).err();
    let actual = direction.get(socket);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let actual = if actual
        .as_ref()
        .is_ok_and(|actual| !udp_buffer_is_large_enough(*actual, requested))
    {
        // This commonly fails for an unprivileged process. The effective size
        // below is authoritative, so keep this attempt quiet and emit one
        // actionable warning only if the socket is still undersized.
        let _ = force_udp_buffer_size(socket, direction, requested);
        direction.get(socket)
    } else {
        actual
    };

    match actual {
        Ok(actual) if udp_buffer_is_large_enough(actual, requested) => {}
        Ok(actual) => {
            direction.warn_once(|| {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                log::warn!(
                    "UDP {} buffer is smaller than requested (wanted at least {} bytes, got {} bytes); high-throughput QUIC may drop packets. Increase net.core.{}mem_max or grant CAP_NET_ADMIN",
                    direction.name(),
                    requested,
                    actual,
                    if matches!(direction, UdpBufferDirection::Receive) {
                        "r"
                    } else {
                        "w"
                    },
                );

                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                log::warn!(
                    "UDP {} buffer is smaller than requested (wanted at least {} bytes, got {} bytes); high-throughput QUIC may drop packets",
                    direction.name(),
                    requested,
                    actual,
                );
            });
        }
        Err(error) => direction.warn_once(|| match set_error {
            Some(set_error) => log::warn!(
                "could not configure or verify UDP {} buffer after requesting {} bytes: setsockopt failed: {}; getsockopt failed: {}",
                direction.name(),
                requested,
                set_error,
                error,
            ),
            None => log::warn!(
                "could not verify UDP {} buffer after requesting {} bytes: {}",
                direction.name(),
                requested,
                error,
            ),
        }),
    }
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    // Set socket buffer sizes if specified.
    // This helps prevent packet drops during bursts for high-throughput connections.
    if let Some(size) = buffer_size {
        configure_udp_buffer(&socket, UdpBufferDirection::Receive, size);
        configure_udp_buffer(&socket, UdpBufferDirection::Send, size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        panic!("Cannot support reuse sockets");
    }

    if let Some(ref _interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(_interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

fn into_tokio_udp_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        let raw_fd = socket.into_raw_fd();
        let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
    #[cfg(windows)]
    {
        let std_udp_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
}

pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    new_outbound_tcp_socket(
        is_ipv6,
        &OutboundSocketOptions {
            bind_interface,
            ..Default::default()
        },
    )
}

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: std::time::Duration,
    send_interval: std::time::Duration,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let raw_fd = tcp_stream.as_raw_fd();
        let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
        if idle_time.is_zero() && send_interval.is_zero() {
            socket2_socket.set_keepalive(false)?;
        } else {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(idle_time)
                .with_interval(send_interval);
            socket2_socket.set_keepalive(true)?;
            socket2_socket.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (tcp_stream, idle_time, send_interval);
        Ok(())
    }
}

// TODO: change backlog to Option<u32> and make configuration, backlog -1 uses somaxconn on linux
// https://github.com/rust-lang/rust/blob/3534594029ed1495290e013647a1f53da561f7f1/library/std/src/os/unix/net/listener.rs#L93
pub fn new_tcp_listener(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if bind_address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    if let Some(ref _interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(_interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    socket.bind(&SockAddr::from(bind_address))?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(target_family = "unix")]
pub fn new_unix_listener<P: AsRef<Path>>(
    path: P,
    backlog: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    let path = path.as_ref();

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    socket.bind(&addr)?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::os::unix::net::UnixListener = socket.into();
    tokio::net::UnixListener::from_std(std_listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_source_address_follows_target_family() {
        let options = OutboundSocketOptions {
            inet4_bind_address: Some(Ipv4Addr::new(192, 0, 2, 10)),
            inet6_bind_address: Some("2001:db8::10".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            options.bind_address(false).unwrap().ip(),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            options.bind_address(true).unwrap().ip(),
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn udp_buffer_capacity_is_compared_to_the_requested_minimum() {
        assert!(!udp_buffer_is_large_enough(
            425_984,
            QUIC_UDP_SOCKET_BUFFER_TARGET
        ));
        assert!(udp_buffer_is_large_enough(
            QUIC_UDP_SOCKET_BUFFER_TARGET,
            QUIC_UDP_SOCKET_BUFFER_TARGET
        ));
        assert!(udp_buffer_is_large_enough(
            QUIC_UDP_SOCKET_BUFFER_TARGET * 2,
            QUIC_UDP_SOCKET_BUFFER_TARGET
        ));
    }

    #[test]
    fn udp_socket_applies_a_reachable_buffer_request() {
        let requested = 64 * 1024;
        let socket = new_socket2_udp_socket_with_buffer_size(
            false,
            None,
            Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            false,
            Some(requested),
        )
        .unwrap();

        assert!(socket.recv_buffer_size().unwrap() >= requested);
        assert!(socket.send_buffer_size().unwrap() >= requested);
    }

    #[test]
    fn udp_buffer_configuration_preserves_larger_existing_capacity() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let receive_before = socket.recv_buffer_size().unwrap();
        let send_before = socket.send_buffer_size().unwrap();

        configure_udp_buffer(
            &socket,
            UdpBufferDirection::Receive,
            (receive_before / 4).max(1),
        );
        configure_udp_buffer(&socket, UdpBufferDirection::Send, (send_before / 4).max(1));

        assert!(socket.recv_buffer_size().unwrap() >= receive_before);
        assert!(socket.send_buffer_size().unwrap() >= send_before);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_force_udp_buffer_path_works_or_reports_missing_capability() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

        for direction in [UdpBufferDirection::Receive, UdpBufferDirection::Send] {
            let before = direction.get(&socket).unwrap();
            let requested = before.saturating_add(1);
            match force_udp_buffer_size(&socket, direction, requested) {
                Ok(()) => assert!(
                    direction.get(&socket).unwrap() >= requested,
                    "SO_{}BUFFORCE succeeded without applying the requested size",
                    if matches!(direction, UdpBufferDirection::Receive) {
                        "RCV"
                    } else {
                        "SND"
                    },
                ),
                Err(error) => assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "the force option should either work or require CAP_NET_ADMIN",
                ),
            }
        }
    }

    #[tokio::test]
    async fn outbound_tcp_and_udp_bind_configured_ipv4_source() {
        let options = OutboundSocketOptions {
            inet4_bind_address: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        };
        let tcp = new_outbound_tcp_socket(false, &options).unwrap();
        assert_eq!(
            tcp.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_ne!(tcp.local_addr().unwrap().port(), 0);

        let udp = new_outbound_udp_socket(false, &options).unwrap();
        assert_eq!(
            udp.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_ne!(udp.local_addr().unwrap().port(), 0);

        let requested = 64 * 1024;
        let buffered_udp =
            new_outbound_udp_socket_with_buffer_size(false, &options, requested).unwrap();
        let socket = socket2::SockRef::from(&buffered_udp);
        assert!(socket.recv_buffer_size().unwrap() >= requested);
        assert!(socket.send_buffer_size().unwrap() >= requested);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn linux_only_outbound_options_fail_in_socket_layer() {
        for options in [
            OutboundSocketOptions {
                routing_mark: 1,
                ..Default::default()
            },
            OutboundSocketOptions {
                bind_address_no_port: true,
                ..Default::default()
            },
        ] {
            let error = new_outbound_tcp_socket(false, &options).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_sets_bind_address_no_port_before_source_bind() {
        let options = OutboundSocketOptions {
            inet4_bind_address: Some(Ipv4Addr::LOCALHOST),
            bind_address_no_port: true,
            ..Default::default()
        };
        let socket = new_outbound_tcp_socket(false, &options).unwrap();
        let mut enabled: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&enabled) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_BIND_ADDRESS_NO_PORT,
                std::ptr::from_mut(&mut enabled).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(enabled, 1);
    }
}
