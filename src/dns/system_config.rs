//! Platform-aware system DNS discovery for wire-aware `system` resolution.
//!
//! On Unix and Windows, configured `system` transports use this module even
//! without advanced query controls. Keeping the DNS exchange visible is what
//! lets the process-wide question cache retain authoritative wire TTLs.

use std::io;
use std::net::IpAddr;
#[cfg(any(target_os = "windows", test))]
use std::net::Ipv6Addr;
#[cfg(any(unix, target_os = "windows"))]
use std::path::PathBuf;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};

const SYSTEM_HOSTS_FINGERPRINT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const GO_RESOLV_INTEGER_MAX: u32 = 0x00ff_ffff;

#[derive(Debug)]
struct RecognizedSystemdResolvedError {
    source: io::Error,
}

impl std::fmt::Display for RecognizedSystemdResolvedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for RecognizedSystemdResolvedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Preserve that `/etc/resolv.conf` was already identified as owned by
/// systemd-resolved even when subsequent link/transport discovery fails.
/// Consumers use this metadata to avoid retaining a stale ordinary plaintext
/// resolver across a transition to a possibly strict DNS-over-TLS profile.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn mark_systemd_resolved_error(error: io::Error) -> io::Error {
    if error_recognized_systemd_resolved(&error) {
        return error;
    }
    io::Error::new(
        error.kind(),
        RecognizedSystemdResolvedError { source: error },
    )
}

pub(crate) fn error_recognized_systemd_resolved(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<RecognizedSystemdResolvedError>())
}

/// Whether this target exposes enough platform DNS state to construct raw DNS
/// exchanges. Other targets retain the opaque native resolver as an explicit
/// compatibility boundary.
pub(crate) const fn wire_system_resolver_supported() -> bool {
    cfg!(any(unix, target_os = "windows"))
}

#[derive(Clone, Debug)]
pub(crate) enum SystemConfiguration {
    Resolver(OrdinarySystemConfiguration),
    SystemdResolved(SystemdResolvedConfiguration),
}

/// A conventional platform resolver configuration. Options which Hickory
/// exposes directly remain in `ResolverOpts`; request-header behavior which it
/// does not model is carried beside the nameserver configuration instead.
#[derive(Clone, Debug)]
pub(crate) struct OrdinarySystemConfiguration {
    pub(crate) resolver: ResolverConfig,
    /// Mirror resolv.conf's `trust-ad`: set the AD bit on outbound questions.
    /// This is intentionally absent from the systemd-resolved path, just like
    /// sing-box, which forwards the caller's question directly once resolved
    /// transport discovery is active.
    pub(crate) trust_ad: bool,
}

impl OrdinarySystemConfiguration {
    pub(crate) fn new(resolver: ResolverConfig) -> Self {
        Self {
            resolver,
            trust_ad: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ResolvedDnsOverTlsMode {
    No,
    Yes,
    Opportunistic,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ResolvedNameServer {
    pub(crate) address: IpAddr,
    /// `None` retains systemd-resolved's transport-specific default: 53 for
    /// plaintext DNS and 853 for DNS-over-TLS.
    pub(crate) port: Option<u16>,
    pub(crate) server_name: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct SystemdResolvedConfiguration {
    pub(crate) interface: String,
    pub(crate) dns_over_tls: ResolvedDnsOverTlsMode,
    pub(crate) servers: Vec<ResolvedNameServer>,
    /// Domain/search state parsed from the primary resolv.conf. Its nameserver
    /// list is replaced by one ordered direct transport per resolved server.
    pub(crate) base_config: ResolverConfig,
}

/// One value snapshot of the platform DNS configuration and system hosts-file
/// state tracked when constructing an advanced `system` resolver. Direct
/// systemd-resolved transports deliberately bypass hosts, while ordinary
/// platform configurations retain their native hosts policy.
///
/// ResolverConfig/ResolverOpts intentionally do not implement Eq/Hash. The
/// fingerprint therefore hashes their complete Debug representations together
/// with the hosts file bytes. Hashing the bytes is stronger than the mtime/size
/// check used by sing-box and also catches same-size, coarse-mtime rewrites.
pub(crate) struct SystemConfigurationSnapshot {
    pub(crate) configuration: SystemConfiguration,
    pub(crate) options: ResolverOpts,
    pub(crate) fingerprint: String,
}

pub(crate) fn read_system_configuration_snapshot() -> io::Result<SystemConfigurationSnapshot> {
    let (configuration, options) = platform::read_system_configuration()?;
    let fingerprint = system_configuration_fingerprint(&configuration, &options);
    Ok(SystemConfigurationSnapshot {
        configuration,
        options,
        fingerprint,
    })
}

fn system_configuration_fingerprint(
    configuration: &SystemConfiguration,
    options: &ResolverOpts,
) -> String {
    #[cfg(any(unix, target_os = "windows"))]
    let hosts_path = system_hosts_path();
    #[cfg(not(any(unix, target_os = "windows")))]
    let hosts_path = None;

    system_configuration_fingerprint_with_hosts_path(configuration, options, hosts_path.as_deref())
}

fn system_configuration_fingerprint_with_hosts_path(
    configuration: &SystemConfiguration,
    options: &ResolverOpts,
    hosts_path: Option<&std::path::Path>,
) -> String {
    use std::io::Read;

    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("{configuration:?}\0{options:?}").as_bytes());
    hasher.update(b"\0system-hosts\0");

    let Some(path) = hosts_path else {
        hasher.update(b"path-unavailable");
        return hasher.finalize().to_hex().to_string();
    };
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b"\0");

    match std::fs::File::open(path) {
        Ok(mut file) => {
            let metadata = match file.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    hasher.update(b"metadata-error\0");
                    hasher.update(
                        format!("{:?}\0{:?}", error.kind(), error.raw_os_error()).as_bytes(),
                    );
                    return hasher.finalize().to_hex().to_string();
                }
            };
            hasher.update(b"metadata\0");
            hasher.update(&metadata.len().to_le_bytes());
            hasher.update(&[
                u8::from(metadata.is_file()),
                u8::from(metadata.is_dir()),
                u8::from(metadata.file_type().is_symlink()),
            ]);
            match metadata
                .modified()
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            {
                Some(modified) => {
                    hasher.update(b"modified\0");
                    hasher.update(&modified.as_secs().to_le_bytes());
                    hasher.update(&modified.subsec_nanos().to_le_bytes());
                }
                None => {
                    hasher.update(b"modified-unavailable\0");
                }
            }

            if metadata.len() > SYSTEM_HOSTS_FINGERPRINT_MAX_BYTES {
                // Hickory will still decide how to load the hosts file while
                // building, but periodic change detection must not scan an
                // accidentally gigantic file every five seconds. Size/mtime
                // and file state remain in the stable fail-safe fingerprint.
                hasher.update(b"content-skipped-oversized\0");
                return hasher.finalize().to_hex().to_string();
            }

            let mut buffer = [0_u8; 16 * 1024];
            let mut remaining = SYSTEM_HOSTS_FINGERPRINT_MAX_BYTES;
            loop {
                let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
                if read_limit == 0 {
                    hasher.update(b"content-limit-reached\0");
                    break;
                }
                match file.read(&mut buffer[..read_limit]) {
                    Ok(0) => break,
                    Ok(length) => {
                        hasher.update(&buffer[..length]);
                        remaining -= length as u64;
                    }
                    Err(error) => {
                        hasher.update(b"\0read-error\0");
                        hasher.update(
                            format!("{:?}\0{:?}", error.kind(), error.raw_os_error()).as_bytes(),
                        );
                        break;
                    }
                }
            }
        }
        Err(error) => {
            // Hickory treats an unreadable/missing hosts file as an empty hosts
            // table. Fingerprint the failure instead of failing DNS discovery;
            // appearance or recovery of the file will then trigger a rebuild.
            hasher.update(b"open-error\0");
            hasher.update(format!("{:?}\0{:?}", error.kind(), error.raw_os_error()).as_bytes());
        }
    }

    hasher.finalize().to_hex().to_string()
}

#[cfg(unix)]
fn system_hosts_path() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/hosts"))
}

#[cfg(target_os = "windows")]
fn system_hosts_path() -> Option<PathBuf> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32\\drivers\\etc\\hosts"))
}

#[cfg(any(target_os = "linux", test))]
fn is_systemd_resolved_managed(contents: &[u8]) -> bool {
    // Match sing-box's conservative probe: the marker must occur in the
    // leading comment header, before any blank or non-comment line. This avoids
    // treating an arbitrary user resolv.conf comment as ownership metadata.
    for raw_line in contents.split(|byte| *byte == b'\n') {
        let line = trim_ascii(raw_line);
        if line.is_empty() || !line.starts_with(b"#") {
            return false;
        }
        if find_ascii_case_sensitive(line, b"systemd-resolved") {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "linux", test))]
fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(any(target_os = "linux", test))]
fn find_ascii_case_sensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

fn is_directly_usable_nameserver(address: IpAddr) -> bool {
    !address.is_unspecified()
        // resolv-conf understands `%interface` scopes, but Hickory's public
        // ResolverConfig currently reduces a nameserver to IpAddr and drops
        // that scope. Selecting a link-local address here could therefore
        // create a resolver that cannot reach its upstream. Loopback addresses
        // remain valid ordinary upstreams for local dnsmasq/unbound services;
        // a recognized systemd-resolved file takes the dedicated branch before
        // this filter is reached.
        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ipv4_default_interface(routes: &str) -> Option<&str> {
    let mut best: Option<(&str, u32)> = None;
    for line in routes.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let interface = fields[0];
        if !is_safe_linux_interface_name(interface) {
            continue;
        }
        let Some(flags) = u32::from_str_radix(fields[3], 16).ok() else {
            continue;
        };
        const RTF_UP: u32 = 0x0001;
        const RTF_REJECT: u32 = 0x0200;
        if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
            continue;
        }
        let Some(metric) = fields[6].parse::<u32>().ok() else {
            continue;
        };
        if best.is_none_or(|(_, best_metric)| metric < best_metric) {
            best = Some((interface, metric));
        }
    }
    best.map(|(interface, _)| interface)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ipv6_default_interface(routes: &str) -> Option<&str> {
    let mut best: Option<(&str, u32)> = None;
    for line in routes.lines() {
        // /proc/net/ipv6_route has no header:
        // destination/prefix, source/prefix, gateway, metric, ref/use, flags,
        // and interface. A source-specific ::/0 route is not a machine-wide
        // default and therefore must not select systemd-resolved's link.
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 10
            || fields[0] != "00000000000000000000000000000000"
            || fields[1] != "00"
            || fields[2] != "00000000000000000000000000000000"
            || fields[3] != "00"
        {
            continue;
        }
        let interface = fields[fields.len() - 1];
        if !is_safe_linux_interface_name(interface) {
            continue;
        }
        let Some(metric) = u32::from_str_radix(fields[5], 16).ok() else {
            continue;
        };
        let Some(flags) = u32::from_str_radix(fields[8], 16).ok() else {
            continue;
        };
        const RTF_UP: u32 = 0x0001;
        const RTF_REJECT: u32 = 0x0200;
        if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
            continue;
        }
        if best.is_none_or(|(_, best_metric)| metric < best_metric) {
            best = Some((interface, metric));
        }
    }
    best.map(|(interface, _)| interface)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_default_interface<'a>(
    ipv4_routes: &'a str,
    ipv6_routes: &'a str,
) -> Option<&'a str> {
    // Preserve the previous IPv4 choice whenever one exists. Linux metrics are
    // meaningful within a routing family, not necessarily comparable across
    // IPv4 and IPv6. IPv6 discovery is the fallback that makes an IPv6-only
    // host usable without changing dual-stack behavior.
    parse_linux_ipv4_default_interface(ipv4_routes)
        .or_else(|| parse_linux_ipv6_default_interface(ipv6_routes))
}

#[cfg(any(target_os = "linux", test))]
fn is_safe_linux_interface_name(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(any(target_os = "linux", test))]
struct ResolvectlLinkOutput {
    link_index: u32,
    payload: String,
}

#[cfg(any(target_os = "linux", test))]
fn parse_resolvectl_link_output(
    output: &str,
    interface: &str,
    allow_wrapped_values: bool,
) -> Option<ResolvectlLinkOutput> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next()?.trim();
    let (header, payload) = line.split_once(':')?;
    let expected_suffix = format!("({interface})");
    let header = header.trim();
    let link_index = header
        .strip_prefix("Link ")?
        .strip_suffix(&expected_suffix)?
        .trim()
        .parse::<u32>()
        .ok()?;
    if link_index == 0 {
        return None;
    }

    let mut payload = payload.trim().to_string();
    for continuation in lines {
        // `resolvectl dns` uses status_print_strv(), whose wrapped values have
        // exactly the shared eight-column indentation (`strlen("Global: ")`).
        // Accept only that official continuation form; all other extra output
        // remains a strict parse failure.
        if !allow_wrapped_values
            || !continuation.starts_with("        ")
            || continuation.trim().is_empty()
        {
            return None;
        }
        if !payload.is_empty() {
            payload.push(' ');
        }
        payload.push_str(continuation.trim());
    }

    Some(ResolvectlLinkOutput {
        link_index,
        payload,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_resolvectl_resolved_configuration(
    interface: &str,
    dns_over_tls_output: &str,
    dns_output: &str,
) -> Option<(ResolvedDnsOverTlsMode, Vec<ResolvedNameServer>)> {
    let dns_over_tls = parse_resolvectl_link_output(dns_over_tls_output, interface, false)?;
    let dns = parse_resolvectl_link_output(dns_output, interface, true)?;
    if dns_over_tls.link_index != dns.link_index {
        return None;
    }
    let dns_over_tls = match dns_over_tls.payload.as_str() {
        "no" => ResolvedDnsOverTlsMode::No,
        "yes" => ResolvedDnsOverTlsMode::Yes,
        "opportunistic" => ResolvedDnsOverTlsMode::Opportunistic,
        // Empty/inherited and future modes are not safe to guess. The caller
        // retains its last-good direct resolver or fails explicitly.
        _ => return None,
    };
    if dns.payload.is_empty() {
        return None;
    }

    let mut servers = Vec::new();
    for token in dns.payload.split_ascii_whitespace() {
        if let Some(server) = parse_resolvectl_server_token(token, interface, dns.link_index)
            && !servers.contains(&server)
        {
            servers.push(server);
        }
    }
    (!servers.is_empty()).then_some((dns_over_tls, servers))
}

#[cfg(any(target_os = "linux", test))]
fn parse_resolvectl_server_token(
    token: &str,
    interface: &str,
    link_index: u32,
) -> Option<ResolvedNameServer> {
    let (address_port_scope, server_name) = match token.split_once('#') {
        Some((value, server_name))
            if !server_name.is_empty()
                && !server_name.contains('#')
                && server_name.is_ascii()
                && rustls::pki_types::ServerName::try_from(server_name.to_string()).is_ok() =>
        {
            (value, Some(server_name.to_string()))
        }
        Some(_) => return None,
        None => (token, None),
    };

    let (address_port, has_scope) = match address_port_scope.split_once('%') {
        Some((value, scope))
            if (scope == interface || scope.parse::<u32>().ok() == Some(link_index))
                && !value.contains('%') =>
        {
            (value, true)
        }
        Some(_) => return None,
        None => (address_port_scope, false),
    };

    let (address, port) = if let Some(bracketed) = address_port.strip_prefix('[') {
        let (address, suffix) = bracketed.split_once(']')?;
        let address = address.parse::<IpAddr>().ok()?;
        if !address.is_ipv6() {
            return None;
        }
        let port = match suffix.strip_prefix(':') {
            Some(port) => Some(parse_dns_port(port)?),
            None if suffix.is_empty() => None,
            None => return None,
        };
        (address, port)
    } else if let Ok(address) = address_port.parse::<IpAddr>() {
        (address, None)
    } else {
        let (address, port) = address_port.rsplit_once(':')?;
        let address = address.parse::<IpAddr>().ok()?;
        if !address.is_ipv4() {
            return None;
        }
        (address, Some(parse_dns_port(port)?))
    };

    if address.is_unspecified()
        || matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local() && !has_scope)
    {
        return None;
    }

    Some(ResolvedNameServer {
        address,
        port,
        server_name,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_dns_port(value: &str) -> Option<u16> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

#[cfg(any(target_os = "windows", test))]
fn windows_adapter_is_eligible(is_up: bool, is_tunnel: bool, has_gateway: bool) -> bool {
    is_up && !is_tunnel && has_gateway
}

#[cfg(any(target_os = "windows", test))]
fn is_deprecated_ipv6_site_local(address: Ipv6Addr) -> bool {
    // fec0::/10 was deprecated by RFC 3879. Windows can synthesize addresses
    // from this range when no real IPv6 DNS server is configured.
    address.segments()[0] & 0xffc0 == 0xfec0
}

#[cfg(any(target_os = "windows", test))]
fn is_windows_directly_usable_nameserver(address: IpAddr) -> bool {
    // Windows commonly points adapters at a local DNS proxy. Unlike Linux's
    // systemd-resolved stub, those loopback servers are the intended direct
    // upstream and sing-box retains them. Scoped IPv6 link-local servers
    // remain unavailable because Hickory's NameServerConfig stores only an
    // IpAddr and cannot carry the adapter's zone identifier.
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local() || is_deprecated_ipv6_site_local(ip))
}

#[cfg(any(target_os = "linux", test))]
fn parse_ordinary_resolv_conf(
    contents: &[u8],
    source: &str,
) -> io::Result<(OrdinarySystemConfiguration, ResolverOpts)> {
    parse_resolv_conf(contents, source, true)
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_resolv_conf_base(
    contents: &[u8],
    source: &str,
) -> io::Result<(OrdinarySystemConfiguration, ResolverOpts)> {
    // The nameserver list is discarded after resolved's default-link servers
    // are discovered. In particular, a scoped link-local stub is valid here
    // even though Hickory cannot represent that scope in ResolverConfig.
    parse_resolv_conf(contents, source, false)
}

#[cfg(any(target_os = "linux", test))]
fn parse_resolv_conf(
    contents: &[u8],
    source: &str,
    reject_unrepresentable_scope: bool,
) -> io::Result<(OrdinarySystemConfiguration, ResolverOpts)> {
    use std::str::FromStr;
    use std::time::Duration;

    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ServerOrderingStrategy};
    use hickory_resolver::proto::rr::Name;
    use resolv_conf::ScopedIp;

    let normalized_contents = normalize_resolv_conf_aliases(contents, source)?;
    let parsed = resolv_conf::Config::parse(normalized_contents.as_bytes()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {source}: {error}"),
        )
    })?;
    if reject_unrepresentable_scope
        && parsed.nameservers.iter().any(
            |server| matches!(server, ScopedIp::V6(address, _) if address.is_unicast_link_local()),
        )
    {
        // resolv-conf retains `%zone` but Hickory's public ResolverConfig
        // reduces the address to IpAddr. Failing explicitly avoids sending an
        // advanced-profile query to a link-local server with scope 0.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{source} contains an IPv6 link-local nameserver whose scope cannot be represented by Hickory"
            ),
        ));
    }

    let domain = parsed
        .get_system_domain()
        .and_then(|domain| Name::from_str(&domain).ok());
    let mut search = Vec::new();
    for suffix in parsed.get_last_search_or_domain() {
        if suffix == "--" {
            continue;
        }
        search.push(Name::from_str_relaxed(suffix).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse {source}: {error}"),
            )
        })?);
    }
    let name_servers = parsed
        .nameservers
        .iter()
        .map(|server| NameServerConfig::udp_and_tcp(IpAddr::from(server)))
        .collect::<Vec<_>>();
    if name_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {source}: no nameservers found in config"),
        ));
    }
    let mut resolver = ResolverConfig::from_parts(domain, search, name_servers);
    let mut options = ResolverOpts::default();
    options.ndots = parsed.ndots as usize;
    options.timeout = Duration::from_secs(u64::from(parsed.timeout));
    options.attempts = parsed.attempts as usize;
    options.edns0 = parsed.edns0;
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = if parsed.rotate {
        ServerOrderingStrategy::RoundRobin
    } else {
        ServerOrderingStrategy::UserProvidedOrder
    };
    if parsed.use_vc || resolv_conf_has_option(contents, &["usevc", "tcp"]) {
        for server in &mut resolver.name_servers {
            server.connections = vec![ConnectionConfig::tcp()];
        }
    }
    normalize_go_system_options(&mut options);

    Ok((
        OrdinarySystemConfiguration {
            resolver,
            trust_ad: parsed.trust_ad,
        },
        options,
    ))
}

#[cfg(any(target_os = "linux", test))]
fn normalize_resolv_conf_aliases(contents: &[u8], source: &str) -> io::Result<String> {
    let contents = std::str::from_utf8(contents).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {source}: {error}"),
        )
    })?;
    let mut normalized = String::with_capacity(contents.len());
    for raw_line in contents.split_inclusive('\n') {
        let has_newline = raw_line.ends_with('\n');
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let mut fields = line.split_ascii_whitespace();
        if fields.next() != Some("options") {
            normalized.push_str(raw_line);
            continue;
        }
        normalized.push_str("options");
        for field in fields.take_while(|field| !field.starts_with('#') && !field.starts_with(';')) {
            normalized.push(' ');
            match field {
                "usevc" | "tcp" => normalized.push_str("use-vc"),
                value => normalize_go_resolv_option(value, &mut normalized),
            }
        }
        if has_newline {
            normalized.push('\n');
        }
    }
    Ok(normalized)
}

#[cfg(any(target_os = "linux", test))]
fn normalize_go_resolv_option(value: &str, output: &mut String) {
    let (name, raw, minimum, maximum) = if let Some(raw) = value.strip_prefix("ndots:") {
        ("ndots", raw, 0, 15)
    } else if let Some(raw) = value.strip_prefix("timeout:") {
        ("timeout", raw, 1, GO_RESOLV_INTEGER_MAX)
    } else if let Some(raw) = value.strip_prefix("attempts:") {
        ("attempts", raw, 1, GO_RESOLV_INTEGER_MAX)
    } else {
        output.push_str(value);
        return;
    };

    let parsed = parse_go_resolv_integer(raw).clamp(minimum, maximum);
    use std::fmt::Write as _;
    write!(output, "{name}:{parsed}").expect("writing to String cannot fail");
}

#[cfg(any(target_os = "linux", test))]
fn parse_go_resolv_integer(value: &str) -> u32 {
    let mut parsed = 0_u32;
    for byte in value.bytes().take_while(u8::is_ascii_digit) {
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'));
        if parsed >= GO_RESOLV_INTEGER_MAX {
            return GO_RESOLV_INTEGER_MAX;
        }
    }
    parsed
}

fn normalize_go_system_options(options: &mut ResolverOpts) {
    // Go caps dtoi at 0xFFFFFF, clamps ndots to 15, and treats timeout and
    // attempts as at least one. ResolverOpts::attempts, unlike Go, is the
    // number of retries after the initial exchange.
    options.ndots = options.ndots.min(15);
    let timeout_seconds = options
        .timeout
        .as_secs()
        .clamp(1, u64::from(GO_RESOLV_INTEGER_MAX));
    options.timeout = std::time::Duration::from_secs(timeout_seconds);
    options.attempts = options.attempts.clamp(1, GO_RESOLV_INTEGER_MAX as usize) - 1;
}

#[cfg(any(target_os = "linux", test))]
fn resolv_conf_has_option(contents: &[u8], expected: &[&str]) -> bool {
    contents.split(|byte| *byte == b'\n').any(|raw_line| {
        let line = trim_ascii(raw_line);
        if line.starts_with(b"#") || line.starts_with(b";") {
            return false;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return false;
        };
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("options") && fields.any(|field| expected.contains(&field))
    })
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const PRIMARY_RESOLV_CONF: &str = "/etc/resolv.conf";
    const PROC_NET_ROUTE: &str = "/proc/net/route";
    const PROC_NET_IPV6_ROUTE: &str = "/proc/net/ipv6_route";
    const RESOLVECTL_TIMEOUT: Duration = Duration::from_secs(1);
    const RESOLVECTL_MAX_OUTPUT: u64 = 64 * 1024;

    pub(super) fn read_system_configuration() -> io::Result<(SystemConfiguration, ResolverOpts)> {
        let primary_bytes = fs::read(PRIMARY_RESOLV_CONF).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to read {PRIMARY_RESOLV_CONF}: {error}"),
            )
        })?;

        if is_systemd_resolved_managed(&primary_bytes) {
            // Probe ownership before applying ordinary nameserver validation:
            // resolved-managed files may contain scoped link-local stubs such
            // as `fe80::53%eth0`, which are replaced below and never passed to
            // a Hickory transport without its link binding.
            let (primary_config, primary_options) =
                parse_systemd_resolv_conf_base(&primary_bytes, PRIMARY_RESOLV_CONF)
                    .map_err(mark_systemd_resolved_error)?;
            let configuration = read_systemd_default_link(primary_config.resolver)
                .map_err(mark_systemd_resolved_error)?;
            return Ok((
                SystemConfiguration::SystemdResolved(configuration),
                primary_options,
            ));
        }
        let (primary_config, primary_options) =
            parse_ordinary_resolv_conf(&primary_bytes, PRIMARY_RESOLV_CONF)?;
        Ok((
            SystemConfiguration::Resolver(primary_config),
            primary_options,
        ))
    }

    fn read_systemd_default_link(
        primary_config: ResolverConfig,
    ) -> io::Result<SystemdResolvedConfiguration> {
        let ipv4_routes = fs::read_to_string(PROC_NET_ROUTE);
        let ipv6_routes = fs::read_to_string(PROC_NET_IPV6_ROUTE);
        let interface = parse_linux_default_interface(
            ipv4_routes.as_deref().unwrap_or_default(),
            ipv6_routes.as_deref().unwrap_or_default(),
        )
        .ok_or_else(|| {
            let ipv4_status = ipv4_routes
                .as_ref()
                .err()
                .map_or_else(|| "readable".to_string(), ToString::to_string);
            let ipv6_status = ipv6_routes
                .as_ref()
                .err()
                .map_or_else(|| "readable".to_string(), ToString::to_string);
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no safe IPv4 or IPv6 default-route interface found ({PROC_NET_ROUTE}: {ipv4_status}; {PROC_NET_IPV6_ROUTE}: {ipv6_status})"
                ),
            )
        })?;
        let resolvectl = find_resolvectl().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "resolvectl not found at /usr/bin/resolvectl or /bin/resolvectl",
            )
        })?;
        let dns_over_tls = run_resolvectl(&resolvectl, "dnsovertls", interface)?;
        let dns = run_resolvectl(&resolvectl, "dns", interface)?;
        let (dns_over_tls, servers) = parse_resolvectl_resolved_configuration(
            interface,
            &dns_over_tls,
            &dns,
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "default-link DNS/DoT output was not strictly parseable or used an unknown mode",
            )
        })?;

        log::debug!(
            "advanced system DNS discovered {} ordered upstream(s) on default link {} with DNSOverTLS={:?}",
            servers.len(),
            interface,
            dns_over_tls
        );
        Ok(SystemdResolvedConfiguration {
            interface: interface.to_string(),
            dns_over_tls,
            servers,
            base_config: primary_config,
        })
    }

    fn find_resolvectl() -> Option<PathBuf> {
        ["/usr/bin/resolvectl", "/bin/resolvectl"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }

    fn run_resolvectl(path: &Path, verb: &str, interface: &str) -> io::Result<String> {
        debug_assert!(path.is_absolute());
        debug_assert!(matches!(verb, "dns" | "dnsovertls"));
        debug_assert!(is_safe_linux_interface_name(interface));

        let mut child = Command::new(path)
            .args(["--no-pager", "--no-ask-password", verb, interface])
            .env_clear()
            .env("LC_ALL", "C")
            .env("COLUMNS", "65535")
            .env("SYSTEMD_COLORS", "0")
            .env("SYSTEMD_URLIFY", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                io::Error::new(error.kind(), format!("failed to start resolvectl: {error}"))
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("resolvectl stdout pipe was unavailable"))?;
        let reader = thread::spawn(move || {
            let mut output = Vec::new();
            stdout
                .take(RESOLVECTL_MAX_OUTPUT + 1)
                .read_to_end(&mut output)
                .map(|_| output)
        });

        let deadline = Instant::now() + RESOLVECTL_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("resolvectl {verb} exceeded {RESOLVECTL_TIMEOUT:?}"),
                    ));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(io::Error::new(
                        error.kind(),
                        format!("failed waiting for resolvectl {verb}: {error}"),
                    ));
                }
            }
        };
        let output = reader
            .join()
            .map_err(|_| io::Error::other("resolvectl output reader panicked"))??;
        if !status.success() {
            return Err(io::Error::other(format!(
                "resolvectl {verb} exited with {status}"
            )));
        }
        if output.len() as u64 > RESOLVECTL_MAX_OUTPUT {
            return Err(io::Error::other(format!(
                "resolvectl {verb} output exceeded {RESOLVECTL_MAX_OUTPUT} bytes"
            )));
        }
        String::from_utf8(output).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("resolvectl {verb} output was not UTF-8: {error}"),
            )
        })
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::collections::HashSet;
    use std::str::FromStr;

    use hickory_resolver::config::NameServerConfig;
    use hickory_resolver::proto::rr::Name;
    use ipconfig::{IfType, OperStatus};

    use super::*;

    pub(super) fn read_system_configuration() -> io::Result<(SystemConfiguration, ResolverOpts)> {
        let adapters = ipconfig::get_adapters().map_err(|error| {
            io::Error::other(format!("failed to enumerate DNS adapters: {error}"))
        })?;
        let mut seen = HashSet::new();
        let mut name_servers = Vec::new();

        for adapter in adapters {
            if !windows_adapter_is_eligible(
                adapter.oper_status() == OperStatus::IfOperStatusUp,
                adapter.if_type() == IfType::Tunnel,
                !adapter.gateways().is_empty(),
            ) {
                continue;
            }

            for &address in adapter.dns_servers() {
                if !is_windows_directly_usable_nameserver(address) || !seen.insert(address) {
                    continue;
                }
                name_servers.push(NameServerConfig::udp_and_tcp(address));
            }
        }

        if name_servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no usable DNS server found on an up, non-tunnel Windows adapter with a gateway",
            ));
        }

        let search = ipconfig::computer::get_search_list()
            .map_err(|error| io::Error::other(format!("failed to read DNS search list: {error}")))?
            .into_iter()
            .filter_map(|suffix| match Name::from_str(&suffix) {
                Ok(name) => Some(name),
                Err(error) => {
                    log::debug!("ignoring invalid Windows DNS search suffix {suffix:?}: {error}");
                    None
                }
            })
            .collect();
        let domain = ipconfig::computer::get_domain()
            .map_err(|error| io::Error::other(format!("failed to read DNS domain: {error}")))?
            .and_then(|domain| match Name::from_str(&domain) {
                Ok(name) => Some(name),
                Err(error) => {
                    log::debug!("ignoring invalid Windows DNS domain {domain:?}: {error}");
                    None
                }
            });

        let mut options = ResolverOpts::default();
        normalize_go_system_options(&mut options);
        Ok((
            SystemConfiguration::Resolver(OrdinarySystemConfiguration::new(
                ResolverConfig::from_parts(domain, search, name_servers),
            )),
            options,
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;

    pub(super) fn read_system_configuration() -> io::Result<(SystemConfiguration, ResolverOpts)> {
        hickory_resolver::system_conf::read_system_conf()
            .map_err(|error| {
                io::Error::other(format!("failed to read system DNS configuration: {error}"))
            })
            .map(|(config, mut options)| {
                normalize_go_system_options(&mut options);
                (
                    SystemConfiguration::Resolver(OrdinarySystemConfiguration::new(config)),
                    options,
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_fingerprint_tracks_hosts_contents_and_file_state() {
        let directory = tempfile::tempdir().unwrap();
        let hosts = directory.path().join("hosts");
        let configuration = SystemConfiguration::Resolver(OrdinarySystemConfiguration::new(
            ResolverConfig::from_parts(None, Vec::new(), Vec::new()),
        ));
        let options = ResolverOpts::default();

        let missing = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        std::fs::write(&hosts, b"192.0.2.1 same-size.example\n").unwrap();
        let first = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        let unchanged = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        std::fs::write(&hosts, b"192.0.2.2 same-size.example\n").unwrap();
        let rewritten = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );

        assert_ne!(missing, first, "appearance of hosts file must be observed");
        assert_eq!(first, unchanged, "unchanged hosts bytes must be stable");
        assert_ne!(
            first, rewritten,
            "same-size hosts rewrites must trigger a resolver rebuild"
        );
    }

    #[test]
    fn oversized_hosts_fingerprint_is_bounded_and_stable() {
        let directory = tempfile::tempdir().unwrap();
        let hosts = directory.path().join("oversized-hosts");
        std::fs::File::create(&hosts)
            .unwrap()
            .set_len(SYSTEM_HOSTS_FINGERPRINT_MAX_BYTES + 1)
            .unwrap();
        let configuration = SystemConfiguration::Resolver(OrdinarySystemConfiguration::new(
            ResolverConfig::from_parts(None, Vec::new(), Vec::new()),
        ));
        let options = ResolverOpts::default();

        let first = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        let unchanged = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        assert_eq!(first, unchanged);

        std::fs::OpenOptions::new()
            .write(true)
            .open(&hosts)
            .unwrap()
            .set_len(SYSTEM_HOSTS_FINGERPRINT_MAX_BYTES + 2)
            .unwrap();
        let resized = system_configuration_fingerprint_with_hosts_path(
            &configuration,
            &options,
            Some(&hosts),
        );
        assert_ne!(first, resized, "oversized file metadata must remain live");
    }

    #[test]
    fn systemd_marker_must_be_in_the_leading_comment_header() {
        assert!(is_systemd_resolved_managed(
            b"# This is /run/systemd/resolve/stub-resolv.conf managed by systemd-resolved\n\
              nameserver 127.0.0.53\n"
        ));
        assert!(!is_systemd_resolved_managed(
            b"# generated locally\nnameserver 127.0.0.53\n# systemd-resolved\n"
        ));
        assert!(!is_systemd_resolved_managed(
            b"\n# managed by systemd-resolved\nnameserver 127.0.0.53\n"
        ));
    }

    #[test]
    fn systemd_marker_precedes_scoped_nameserver_validation() {
        let contents = b"# managed by systemd-resolved\n\
                         nameserver fe80::53%eth0\n\
                         search internal.example\n";
        assert!(is_systemd_resolved_managed(contents));
        let (configuration, _) =
            parse_systemd_resolv_conf_base(contents, "resolved-resolv.conf").unwrap();
        assert_eq!(configuration.resolver.search.len(), 1);
        assert!(
            parse_ordinary_resolv_conf(contents, "ordinary-resolv.conf")
                .unwrap_err()
                .to_string()
                .contains("scope cannot be represented")
        );
    }

    #[test]
    fn ordinary_nameserver_filter_retains_local_proxies_and_rejects_unscoped_addresses() {
        assert!(is_directly_usable_nameserver("127.0.0.53".parse().unwrap()));
        assert!(is_directly_usable_nameserver("::1".parse().unwrap()));
        assert!(!is_directly_usable_nameserver("0.0.0.0".parse().unwrap()));
        assert!(!is_directly_usable_nameserver("fe80::53".parse().unwrap()));
        assert!(is_directly_usable_nameserver("192.0.2.53".parse().unwrap()));
        assert!(is_directly_usable_nameserver(
            "2001:db8::53".parse().unwrap()
        ));
    }

    #[test]
    fn linux_default_route_parser_selects_the_lowest_safe_up_route() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                      eth9 00000000 010200C0 0201 0 0 1 00000000 0 0 0\n\
                      bad/name 00000000 010200C0 0001 0 0 1 00000000 0 0 0\n\
                      eth0 00000000 010200C0 0001 0 0 100 00000000 0 0 0\n\
                      eth1 00000000 010200C0 0001 0 0 20 00000000 0 0 0\n\
                      eth2 0002A8C0 00000000 0001 0 0 1 00FFFFFF 0 0 0\n";
        assert_eq!(parse_linux_default_interface(routes, ""), Some("eth1"));
        assert_eq!(
            parse_linux_default_interface(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask\n\
                 eth0 00000000 00000000 broken 0 0 0 00000000\n",
                ""
            ),
            None
        );
        assert!(!is_safe_linux_interface_name("eth0;shutdown"));
        assert!(!is_safe_linux_interface_name("../../eth0"));
        assert!(!is_safe_linux_interface_name("--help"));
    }

    #[test]
    fn linux_default_route_parser_falls_back_to_an_ipv6_only_default() {
        let ipv6_routes = "00000000000000000000000000000000 00 \
                           00000000000000000000000000000000 00 \
                           fe800000000000000000000000000001 00000064 00000000 00000000 00000001 eth6\n\
                           00000000000000000000000000000000 00 \
                           00000000000000000000000000000000 00 \
                           fe800000000000000000000000000002 00000014 00000000 00000000 00000001 wan6\n\
                           00000000000000000000000000000000 00 \
                           00000000000000000000000000000000 00 \
                           00000000000000000000000000000000 00000001 00000000 00000000 00000201 reject6\n";
        assert_eq!(parse_linux_default_interface("", ipv6_routes), Some("wan6"));

        let ipv4_routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n\
                           eth4 00000000 010200C0 0001 0 0 500 00000000\n";
        assert_eq!(
            parse_linux_default_interface(ipv4_routes, ipv6_routes),
            Some("eth4"),
            "a dual-stack host must preserve the pre-existing IPv4 selection"
        );
    }

    #[test]
    fn ordinary_resolv_conf_keeps_order_rotation_tcp_and_trust_ad() {
        use hickory_resolver::config::{ProtocolConfig, ServerOrderingStrategy};

        let (configuration, options) = parse_ordinary_resolv_conf(
            b"nameserver 192.0.2.53\n\
              nameserver 198.51.100.53\n\
              options rotate use-vc single-request trust-ad\n",
            "test-resolv.conf",
        )
        .unwrap();

        assert_eq!(options.num_concurrent_reqs, 1);
        assert_eq!(
            options.server_ordering_strategy,
            ServerOrderingStrategy::RoundRobin
        );
        assert!(configuration.trust_ad);
        assert_eq!(
            configuration
                .resolver
                .name_servers
                .iter()
                .map(|server| server.ip)
                .collect::<Vec<_>>(),
            vec![
                "192.0.2.53".parse::<IpAddr>().unwrap(),
                "198.51.100.53".parse::<IpAddr>().unwrap()
            ]
        );
        assert!(configuration.resolver.name_servers.iter().all(|server| {
            matches!(server.connections.as_slice(), [connection] if matches!(connection.protocol, ProtocolConfig::Tcp))
        }));

        for alias in ["usevc", "tcp"] {
            let input = format!("nameserver 192.0.2.53\noptions {alias}\n");
            let (configuration, _) =
                parse_ordinary_resolv_conf(input.as_bytes(), "alias-resolv.conf").unwrap();
            assert!(matches!(
                configuration.resolver.name_servers[0].connections.as_slice(),
                [connection] if matches!(connection.protocol, ProtocolConfig::Tcp)
            ));
        }
    }

    #[test]
    fn ordinary_resolv_conf_uses_go_clamps_and_hickory_retry_units() {
        let (_, minimums) = parse_ordinary_resolv_conf(
            b"nameserver 192.0.2.53\noptions ndots:-1 timeout:0 attempts:0\n",
            "minimum-resolv.conf",
        )
        .unwrap();
        assert_eq!(minimums.ndots, 0);
        assert_eq!(minimums.timeout, std::time::Duration::from_secs(1));
        assert_eq!(minimums.attempts, 0, "one Go round means no Hickory retry");

        let (_, maximums) = parse_ordinary_resolv_conf(
            b"nameserver 192.0.2.53\noptions ndots:999 timeout:999999999 attempts:3junk\n",
            "maximum-resolv.conf",
        )
        .unwrap();
        assert_eq!(maximums.ndots, 15);
        assert_eq!(
            maximums.timeout,
            std::time::Duration::from_secs(u64::from(GO_RESOLV_INTEGER_MAX))
        );
        assert_eq!(maximums.attempts, 2, "three Go rounds mean two retries");
    }

    #[test]
    fn ordinary_resolv_conf_rejects_unrepresentable_link_local_scope() {
        let error = parse_ordinary_resolv_conf(b"nameserver fe80::53%eth0\n", "scoped-resolv.conf")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("scope cannot be represented"));
    }

    #[test]
    fn resolvectl_parser_preserves_modes_ports_names_and_server_order() {
        let (mode, servers) = parse_resolvectl_resolved_configuration(
            "eth0",
            "Link 2 (eth0): opportunistic\n",
            "Link 2 (eth0): 192.0.2.53\n        [2001:db8::53]:5353%2#dns.example 192.0.2.53\n",
        )
        .unwrap();
        assert_eq!(mode, ResolvedDnsOverTlsMode::Opportunistic);
        assert_eq!(
            servers,
            vec![
                ResolvedNameServer {
                    address: "192.0.2.53".parse().unwrap(),
                    port: None,
                    server_name: None,
                },
                ResolvedNameServer {
                    address: "2001:db8::53".parse().unwrap(),
                    port: Some(5353),
                    server_name: Some("dns.example".to_string()),
                },
            ]
        );

        for (raw_mode, expected) in [
            ("no", ResolvedDnsOverTlsMode::No),
            ("yes", ResolvedDnsOverTlsMode::Yes),
            ("opportunistic", ResolvedDnsOverTlsMode::Opportunistic),
        ] {
            let (mode, _) = parse_resolvectl_resolved_configuration(
                "eth0",
                &format!("Link 2 (eth0): {raw_mode}\n"),
                "Link 2 (eth0): 192.0.2.53\n",
            )
            .unwrap();
            assert_eq!(mode, expected);
        }
        for mode in ["", "future-mode", "YES"] {
            assert!(
                parse_resolvectl_resolved_configuration(
                    "eth0",
                    &format!("Link 2 (eth0): {mode}\n"),
                    "Link 2 (eth0): 192.0.2.53\n",
                )
                .is_none()
            );
        }
    }

    #[test]
    fn resolvectl_unknown_output_fails_but_bound_link_local_is_retained() {
        let (_, scoped) = parse_resolvectl_resolved_configuration(
            "eth0",
            "Link 2 (eth0): no\n",
            "Link 2 (eth0): fe80::53%2\n",
        )
        .unwrap();
        assert_eq!(scoped[0].address, "fe80::53".parse::<IpAddr>().unwrap());

        for dns_output in [
            "Link 2 (eth0): fe80::53\n",
            "Link 2 (eth0): fe80::53%3\n",
            "Link 3 (eth1): 192.0.2.53\n",
            "Link 2 (eth0): 192.0.2.53\ncontinuation\n",
            "Link 2 (eth0): 192.0.2.53:0\n",
        ] {
            assert!(
                parse_resolvectl_resolved_configuration("eth0", "Link 2 (eth0): no\n", dns_output,)
                    .is_none(),
                "unexpectedly accepted {dns_output:?}"
            );
        }
        assert!(
            parse_resolvectl_resolved_configuration(
                "eth0",
                "Link 2 (eth0): no\nunknown\n",
                "Link 2 (eth0): 192.0.2.53\n",
            )
            .is_none()
        );
    }

    #[test]
    fn resolvectl_parser_retains_loopback_and_skips_bad_tokens() {
        let (_, servers) = parse_resolvectl_resolved_configuration(
            "eth0",
            "Link 2 (eth0): no\n",
            "Link 2 (eth0): invalid-server 127.0.0.1 ::1 0.0.0.0 fe80::53 192.0.2.53\n",
        )
        .unwrap();

        assert_eq!(
            servers,
            vec![
                ResolvedNameServer {
                    address: "127.0.0.1".parse().unwrap(),
                    port: None,
                    server_name: None,
                },
                ResolvedNameServer {
                    address: "::1".parse().unwrap(),
                    port: None,
                    server_name: None,
                },
                ResolvedNameServer {
                    address: "192.0.2.53".parse().unwrap(),
                    port: None,
                    server_name: None,
                },
            ]
        );
    }

    #[test]
    fn resolvectl_parser_fails_when_all_server_tokens_are_invalid() {
        assert!(
            parse_resolvectl_resolved_configuration(
                "eth0",
                "Link 2 (eth0): no\n",
                "Link 2 (eth0): invalid-server 0.0.0.0 fe80::53\n",
            )
            .is_none()
        );
    }

    #[test]
    fn windows_adapter_filter_matches_go_safety_criteria() {
        assert!(windows_adapter_is_eligible(true, false, true));
        assert!(!windows_adapter_is_eligible(false, false, true));
        assert!(!windows_adapter_is_eligible(true, true, true));
        assert!(!windows_adapter_is_eligible(true, false, false));
    }

    #[test]
    fn windows_nameserver_filter_retains_local_dns_proxies_without_losing_scope_safety() {
        assert!(is_windows_directly_usable_nameserver(
            "127.0.0.1".parse().unwrap()
        ));
        assert!(is_windows_directly_usable_nameserver(
            "::1".parse().unwrap()
        ));
        assert!(is_windows_directly_usable_nameserver(
            "192.0.2.53".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "0.0.0.0".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "::".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "224.0.0.251".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "ff02::fb".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "fe80::53".parse().unwrap()
        ));
        assert!(!is_windows_directly_usable_nameserver(
            "fec0::53".parse().unwrap()
        ));
    }

    #[test]
    fn deprecated_windows_ipv6_dns_range_is_rejected() {
        assert!(is_deprecated_ipv6_site_local("fec0::1".parse().unwrap()));
        assert!(is_deprecated_ipv6_site_local("feff::1".parse().unwrap()));
        assert!(!is_deprecated_ipv6_site_local("fe80::1".parse().unwrap()));
        assert!(!is_deprecated_ipv6_site_local(
            "2001:db8::1".parse().unwrap()
        ));
    }
}
