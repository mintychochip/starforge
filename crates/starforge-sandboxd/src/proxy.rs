//! Per-sandbox MITM egress proxy (plan M6b B7).
//!
//! Each sandbox gets its own proxy process-light (a spawned task) with its
//! own self-signed CA ([`CaMaterial`]) whose X.509 **name constraints**
//! cover only the allowlisted destinations. The sandbox trusts that CA
//! (installed by the daemon, see `lib.rs`), points HTTP(S) clients at the
//! proxy, and the proxy intercepts `CONNECT`, terminates TLS with a leaf
//! minted under the sandbox CA for the requested host, and forwards to the
//! real host with DNS resolved once and pinned.
//!
//! Security invariants:
//!
//! - Default-deny: only [`EgressPolicy::host_allowed`] destinations (and
//!   CIDR-allowlisted IPs for non-HTTP ports) are tunneled. Everything else
//!   gets `403 Forbidden` before any upstream connection is attempted.
//! - Header injection: a secret value is injected only when the `CONNECT`
//!   host matches that binding's host exactly. [`SecretBinding`] never
//!   implements `Display`/`Debug` for its value, and the proxy log buffer
//!   ([`ProxyLog`]) records only method/host/header-name/status — never the
//!   secret. Tests assert the secret never appears in the logs.
//! - The CA cannot sign an unbound host: [`CaMaterial::mint_leaf`] refuses
//!   any host the policy denies, and the name constraints in the CA cert
//!   are a second, verifiable layer.
//! - CA keys are written `0600` ([`write_ca_key`]) and destroyed with the
//!   sandbox ([`destroy_ca_key`], called by the daemon on kill/expire).

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, GeneralSubtree,
    IsCa, KeyPair, NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bind a secret to exactly one host + header name. The value is opaque.
#[derive(Clone)]
pub struct SecretBinding {
    pub host: String,
    pub header: String,
    pub value: String,
}

impl fmt::Debug for SecretBinding {
    // The value is a secret: never render it (nor any prefix/suffix).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBinding")
            .field("host", &self.host)
            .field("header", &self.header)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// One CIDR (IPv4 only in v1; IPv6 literals resolve but cannot match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: u32,
    prefix: u8,
}

impl IpNet {
    /// Parse `192.168.0.0/24` or a bare `192.168.0.1` (/32).
    pub fn parse(text: &str) -> Result<Self, ProxyError> {
        let (ip, prefix) = match text.split_once('/') {
            Some((ip, p)) => {
                let prefix: u8 = p
                    .parse()
                    .map_err(|_| ProxyError::InvalidCidr(text.to_owned()))?;
                if prefix > 32 {
                    return Err(ProxyError::InvalidCidr(text.to_owned()));
                }
                (ip, prefix)
            }
            None => (text, 32),
        };
        let addr = match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => u32::from(v4),
            _ => return Err(ProxyError::InvalidCidr(text.to_owned())),
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let bits: u32 = match ip {
            IpAddr::V4(v4) => u32::from(*v4),
            IpAddr::V6(v6) => {
                let o = v6.octets();
                // Match IPv4-mapped addresses against their IPv4 form so
                // a `127.0.0.1/32` operator CIDR also covers
                // `::ffff:127.0.0.1`.
                if o[..10] == [0u8; 10] && o[10..12] == [0xff, 0xff] {
                    u32::from(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]))
                } else {
                    return false;
                }
            }
        };
        if self.prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix);
        bits & mask == self.addr & mask
    }
}

/// Whether `ip` is in a special-use (non-public) range that may only be
/// dialed via an operator CIDR or the forge exact match. Covers IPv4
/// loopback/private/link-local/CGNAT/0/8/broadcast/multicast/reserved/
/// documentation addresses, IPv6 loopback/unspecified/link-local/
/// unique-local/multicast, and IPv4-mapped/compatible forms of any
/// blocked IPv4 address.
pub fn is_special_use(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // reserved 240.0.0.0/4
                || o[0] >= 240
                // 0.0.0.0/8 ("this network")
                || o[0] == 0
                // 100.64.0.0/10 CGNAT
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // 198.18.0.0/15 benchmarking
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                // documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped/compatible: ::ffff:a.b.c.d (first 80 bits zero,
            // next 16 ones) or ::a.b.c.d (first 96 zero).
            let o = v6.octets();
            let v4_mapped = o[..10] == [0u8; 10] && o[10..12] == [0xff, 0xff];
            let v4_compat =
                o[..12] == [0u8; 12] && !(o[12] == 0 && o[13] == 0 && o[14] == 0 && o[15] <= 1);
            if v4_mapped || v4_compat {
                return is_special_use(&IpAddr::V4(std::net::Ipv4Addr::new(
                    o[12], o[13], o[14], o[15],
                )));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // link-local fe80::/10 (IPv6 `is_link_local` is unstable)
                || (seg[0] & 0xffc0) == 0xfe80
                // unique-local fc00::/7 (IPv6 `is_unique_local` is unstable)
                || (seg[0] & 0xfe00) == 0xfc00
                // documentation 2001:db8::/32
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        }
    }
}

/// Egress policy enforced by the proxy. Built per-sandbox from the create
/// request's [`starforge_sandbox_protocol::NetworkPolicy`] plus the daemon's
/// configured secret bindings (values never travel on the wire).
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allow_out: Vec<String>,
    pub deny_out: Vec<String>,
    pub bindings: Vec<SecretBinding>,
    pub forge: Option<String>,
    pub cidr_allow: Vec<IpNet>,
    /// Ports the proxy treats as HTTPS and MITMs for allowlisted hosts.
    /// `443` is the default; operators can add a private HTTPS port.
    pub https_ports: Vec<u16>,
}

impl EgressPolicy {
    /// Split an allow/deny entry into `(host, Option<port>)`. Bracketed IPv6
    /// (`[::1]:8080`) is handled; a bare IPv6 literal without brackets has no
    /// port suffix.
    fn parse_entry(entry: &str) -> (&str, Option<u16>) {
        if let Some(rest) = entry.strip_prefix('[') {
            if let Some((host, port_str)) = rest.split_once("]:")
                && let Ok(port) = port_str.parse::<u16>()
            {
                return (host, Some(port));
            }
            return (entry, None);
        }
        match entry.rsplit_once(':') {
            Some((host, port_str)) if host.matches(':').count() == 0 => {
                match port_str.parse::<u16>() {
                    Ok(port) => (host, Some(port)),
                    Err(_) => (entry, None),
                }
            }
            _ => (entry, None),
        }
    }

    /// Allow/deny entry match. A `host:port` entry matches exactly that
    /// port. A bare `host` entry matches ports 80/443 for *allow* entries
    /// (the pre-existing rule); a bare *deny* entry matches every port.
    fn entry_matches_port(entry: &str, host: &str, port: u16, is_deny: bool) -> bool {
        let (entry_host, entry_port) = Self::parse_entry(entry);
        match entry_port {
            Some(want_port) => {
                if want_port != port {
                    return false;
                }
            }
            None => {
                if !is_deny && !matches!(port, 80 | 443) {
                    return false;
                }
            }
        }
        if let Some(suffix) = entry_host.strip_prefix("*.") {
            host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        } else {
            entry_host == host
        }
    }

    /// Whether `host:port` is allowlisted. A bare `host` entry permits only
    /// ports 80/443; a `host:port` entry permits exactly that port. Deny
    /// wins over allow.
    pub fn host_port_allowed(&self, host: &str, port: u16) -> bool {
        if self
            .deny_out
            .iter()
            .any(|e| Self::entry_matches_port(e, host, port, true))
        {
            return false;
        }
        self.allow_out
            .iter()
            .any(|e| Self::entry_matches_port(e, host, port, false))
    }

    /// Whether the policy may tunnel to `host` on a default HTTP(S) port.
    pub fn host_allowed(&self, host: &str) -> bool {
        self.host_port_allowed(host, 443) || self.host_port_allowed(host, 80)
    }

    /// Secret header to inject for `host`, if a binding matches. A binding
    /// host may carry a `:port` suffix; it matches the bare host.
    pub fn binding_for(&self, host: &str) -> Option<&SecretBinding> {
        self.bindings
            .iter()
            .find(|b| b.host == host || Self::parse_entry(&b.host).0 == host)
    }

    /// Whether `ip` is CIDR-allowlisted (non-HTTP egress escape hatch).
    pub fn ip_allowed(&self, ip: &IpAddr) -> bool {
        self.cidr_allow.iter().any(|net| net.contains(ip))
    }

    /// Whether the request's `host:port` equals the policy's forge entry
    /// exactly (host compared case-insensitively, port exactly). This is
    /// the only per-sandbox allow entry that may resolve to a
    /// loopback/private address without an operator CIDR.
    pub fn forge_exact(&self, host: &str, port: u16) -> bool {
        let Some(forge) = self.forge.as_deref() else {
            return false;
        };
        let (fhost, fport) = Self::parse_entry(forge);
        match fport {
            Some(want) => want == port && fhost.eq_ignore_ascii_case(host),
            None => false,
        }
    }

    /// Whether `host` is the policy's forge host, on any port. Used by the
    /// CA minting re-check; the port gate is [`Self::forge_exact`].
    pub fn forge_host_matches(&self, host: &str) -> bool {
        self.forge.as_deref().is_some_and(|forge| {
            let (fhost, _) = Self::parse_entry(forge);
            fhost.eq_ignore_ascii_case(host)
        })
    }

    /// Whether one resolved address passes the policy for `host:port`.
    /// Special-use addresses pass only via an operator CIDR or the forge
    /// exact match; every other address passes only if the name (or the
    /// literal IP) is allowed (or CIDR-allowed).
    pub fn addr_passes(&self, host: &str, port: u16, ip: &IpAddr) -> bool {
        if is_special_use(ip) {
            self.ip_allowed(ip) || self.forge_exact(host, port)
        } else {
            self.host_port_allowed(host, port) || self.ip_allowed(ip)
        }
    }

    /// Keep only the resolved addresses that pass the policy, preserving
    /// order. The caller dials from this set only (never a raw `pinned[0]`
    /// that the policy did not vet).
    pub fn filter_passing(
        &self,
        host: &str,
        port: u16,
        resolved: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        resolved
            .iter()
            .copied()
            .filter(|addr| self.addr_passes(host, port, &addr.ip()))
            .collect()
    }
}

/// Errors raised by the proxy / CA layer. Never contains secret material.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid CIDR `{0}`")]
    InvalidCidr(String),
    #[error("host `{0}` is not allowed by the egress policy")]
    HostDenied(String),
    #[error("CA operation failed: {0}")]
    Ca(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

// --------------------------------------------------------------------- CA --

/// Per-sandbox CA. The private key is held in memory only for leaf minting;
/// the daemon additionally persists it `0600` ([`write_ca_key`]) so the
/// proxy could restart, and destroys it with the sandbox.
pub struct CaMaterial {
    pub cert_pem: String,
    pub cert_der: Vec<u8>,
    pub key_pem: String,
    pub key_der: Vec<u8>,
    /// Signing key (in-memory; the DER above is the on-disk form).
    key_pair: KeyPair,
    params: CertificateParams,
}

impl fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the key.
        f.debug_struct("CaMaterial")
            .field("cert_pem", &self.cert_pem)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Default CA key filename inside the daemon's CA dir.
pub const CA_KEY_FILE: &str = "ca.key";
/// Default CA cert filename inside the daemon's CA dir.
pub const CA_CERT_FILE: &str = "ca.pem";

fn san_for(host: &str) -> rcgen::SanType {
    match host.parse::<IpAddr>() {
        Ok(ip) => rcgen::SanType::IpAddress(ip),
        Err(_) => rcgen::SanType::DnsName(
            host.to_owned()
                .try_into()
                .unwrap_or_else(|_| "invalid".to_owned().try_into().unwrap()),
        ),
    }
}

impl CaMaterial {
    /// Generate a fresh self-signed CA (ECDSA P-256) with name constraints
    /// covering only `allow_hosts` (as DNS subtrees; IP literals become IP
    /// subtrees). An empty allowlist constrains to nothing (`invalid.`),
    /// so chain validation fails for every name — belt and braces over the
    /// proxy's own default-deny.
    pub fn generate(allow_hosts: &[String]) -> Result<Self, ProxyError> {
        let hosts: Vec<String> = allow_hosts
            .iter()
            .map(|h| h.split(':').next().unwrap_or(h).to_owned())
            .collect();
        let mut params = CertificateParams::default();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "starforge sandbox egress CA");
            dn
        };
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let permitted: Vec<GeneralSubtree> = if hosts.is_empty() {
            vec![GeneralSubtree::DnsName("invalid.".to_owned())]
        } else {
            hosts
                .iter()
                .map(|h| match h.parse::<IpAddr>() {
                    Ok(ip) => {
                        let prefix = if ip.is_ipv4() { 32 } else { 128 };
                        GeneralSubtree::IpAddress(rcgen::CidrSubnet::from_addr_prefix(ip, prefix))
                    }
                    Err(_) => GeneralSubtree::DnsName(h.clone()),
                })
                .collect()
        };
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: Vec::new(),
        });
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Ca(format!("key generation: {e}")))?;
        let cert: Certificate = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Ca(format!("self-sign: {e}")))?;
        Ok(Self {
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            key_pem: key_pair.serialize_pem(),
            key_der: key_pair.serialize_der(),
            key_pair,
            params,
        })
    }

    /// Mint a leaf for `host` iff the policy allows it. This is the runtime
    /// guarantee behind "the CA cannot sign an unbound host": the proxy
    /// calls this only after the allow check, and this method re-checks.
    pub fn mint_leaf(&self, policy: &EgressPolicy, host: &str) -> Result<LeafMaterial, ProxyError> {
        if !policy.host_allowed(host) && !policy.forge_host_matches(host) {
            return Err(ProxyError::HostDenied(host.to_owned()));
        }
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san_for(host)];
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, host);
            dn
        };
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Ca(format!("leaf key: {e}")))?;
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key_pair);
        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| ProxyError::Ca(format!("leaf sign: {e}")))?;
        Ok(LeafMaterial {
            cert_der: cert.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        })
    }
}

/// A leaf certificate + key for one destination host.
#[derive(Debug)]
pub struct LeafMaterial {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Persist the CA key at `path` with mode `0600` (via rename so readers
/// never see a partial file). The value is a private key — mode-checked.
pub fn write_ca_key(path: &Path, key_pem: &str) -> Result<(), ProxyError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("key.tmp");
    {
        use std::io::Write as _;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(key_pem.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, key_pem)?;
        }
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ProxyError::Ca(format!(
                "CA key file mode is {mode:03o}, require 0600"
            )));
        }
    }
    Ok(())
}

/// Destroy the CA key (best effort; missing file is fine).
pub fn destroy_ca_key(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Resolve the daemon CA dir + per-sandbox file names.
pub fn ca_paths(ca_dir: &Path, sandbox_id: &str) -> (PathBuf, PathBuf) {
    (
        ca_dir.join(format!("{sandbox_id}-{CA_CERT_FILE}")),
        ca_dir.join(format!("{sandbox_id}-{CA_KEY_FILE}")),
    )
}

// --------------------------------------------------------------- proxy log --

/// In-memory proxy log. Lines carry only method, host, header *names* and
/// status — never a secret value (the injection path never logs headers
/// wholesale). Tests assert `lines()` never contains a secret.
#[derive(Debug, Default)]
pub struct ProxyLog {
    lines: Mutex<Vec<String>>,
}

impl ProxyLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, line: String) {
        // Paranoia: strip any binding value a caller could have pasted in is
        // impossible here — callers only pass metadata. Keep lines bounded.
        let mut lines = self.lines.lock().unwrap();
        if lines.len() < 10_000 {
            lines.push(line);
        }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------------- proxy --

/// A running per-sandbox egress proxy.
pub struct EgressProxy {
    addr: Option<SocketAddr>,
    unix_path: Option<PathBuf>,
    logs: Arc<ProxyLog>,
    handle: tokio::task::AbortHandle,
}

impl EgressProxy {
    /// TCP listen address (only when started via [`start_proxy`]).
    pub fn addr(&self) -> SocketAddr {
        self.addr.expect("proxy started on a TCP address")
    }

    /// Unix socket path (only when started via [`start_proxy_unix`]).
    pub fn unix_path(&self) -> Option<&Path> {
        self.unix_path.as_deref()
    }

    pub fn logs(&self) -> Arc<ProxyLog> {
        Arc::clone(&self.logs)
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.handle.abort();
        if let Some(path) = &self.unix_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

const MAX_HEAD_BYTES: usize = 64 * 1024;

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn upstream_client_config(roots: Option<RootCertStore>) -> Result<Arc<ClientConfig>, ProxyError> {
    let store = match roots {
        Some(store) => store,
        None => {
            let native = rustls_native_certs::load_native_certs();
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(native.certs);
            store
        }
    };
    let config = ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| ProxyError::Ca(format!("client config: {e}")))?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Default DNS resolver: system lookup for one host:port.
async fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs as _;
    let host_port = (host.to_owned(), port);
    tokio::task::spawn_blocking(move || host_port.to_socket_addrs().map(|it| it.collect()))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?
}

/// Start a proxy on `listen` (use `127.0.0.1:0` for ephemeral). `dns_override`
/// maps host → pinned address and bypasses system DNS (used by tests to give
/// two synthetic hosts the same local origin). `upstream_roots` overrides the
/// native root store (tests point it at the local origin's CA).
pub async fn start_proxy(
    listen: SocketAddr,
    ca: Arc<CaMaterial>,
    policy: Arc<EgressPolicy>,
    credential: Option<String>,
    dns_override: Option<BTreeMap<String, SocketAddr>>,
    upstream_roots: Option<RootCertStore>,
) -> Result<EgressProxy, ProxyError> {
    let client_config = upstream_client_config(upstream_roots)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let logs = Arc::new(ProxyLog::new());
    let logs_clone = Arc::clone(&logs);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let ca = Arc::clone(&ca);
            let policy = Arc::clone(&policy);
            let client_config = Arc::clone(&client_config);
            let dns_override = dns_override.clone();
            let logs = Arc::clone(&logs_clone);
            let credential = credential.clone();
            tokio::spawn(async move {
                handle_connection(
                    stream,
                    ca,
                    policy,
                    client_config,
                    credential,
                    dns_override,
                    logs,
                )
                .await;
            });
        }
    });
    Ok(EgressProxy {
        addr: Some(addr),
        unix_path: None,
        logs,
        handle: handle.abort_handle(),
    })
}

/// Start a proxy on the Unix socket at `path` (mode `0666`, so the in-sandbox
/// forwarder — a different mount namespace — can connect). The socket file is
/// removed when the returned [`EgressProxy`] is dropped. Same policy, DNS
/// pinning, and secret injection as the TCP variant.
pub async fn start_proxy_unix(
    path: &Path,
    ca: Arc<CaMaterial>,
    policy: Arc<EgressPolicy>,
    credential: Option<String>,
    dns_override: Option<BTreeMap<String, SocketAddr>>,
    upstream_roots: Option<RootCertStore>,
) -> Result<EgressProxy, ProxyError> {
    let client_config = upstream_client_config(upstream_roots)?;
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    let logs = Arc::new(ProxyLog::new());
    let logs_clone = Arc::clone(&logs);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let ca = Arc::clone(&ca);
            let policy = Arc::clone(&policy);
            let client_config = Arc::clone(&client_config);
            let dns_override = dns_override.clone();
            let logs = Arc::clone(&logs_clone);
            let credential = credential.clone();
            tokio::spawn(async move {
                handle_connection(
                    stream,
                    ca,
                    policy,
                    client_config,
                    credential,
                    dns_override,
                    logs,
                )
                .await;
            });
        }
    });
    Ok(EgressProxy {
        addr: None,
        unix_path: Some(path.to_path_buf()),
        logs,
        handle: handle.abort_handle(),
    })
}

// --------------------------------------------------------- connection pool --
//
// Reverse-direction transport: the in-sandbox forwarder *creates* the Unix
// socket (`<egress-dir>/<id>/shim.sock`, mode `0666`) and the daemon (host)
// connects to it — the container never connects to a host-owned socket
// (denied under SELinux). Each pooled connection is served by the same
// [`handle_connection`] policy path as a directly accepted connection.

/// Idle host connections kept open per sandbox.
pub const POOL_SIZE: usize = 4;
/// How long [`start_connection_pool`] retries connecting to the forwarder's
/// socket while it starts up.
pub const POOL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A running per-sandbox connection pool: `POOL_SIZE` idle connections to
/// the in-sandbox forwarder's Unix socket, each served by
/// [`handle_connection`]. Dropping the pool aborts every slot task.
pub struct EgressPool {
    logs: Arc<ProxyLog>,
    socket_path: PathBuf,
    handles: Vec<tokio::task::AbortHandle>,
}

impl EgressPool {
    pub fn logs(&self) -> Arc<ProxyLog> {
        Arc::clone(&self.logs)
    }

    /// Forwarder socket this pool connects to (`<egress-dir>/<id>/shim.sock`).
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for EgressPool {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

struct PoolCtx {
    socket_path: PathBuf,
    ca: Arc<CaMaterial>,
    policy: Arc<EgressPolicy>,
    client_config: Arc<ClientConfig>,
    credential: Option<String>,
    dns_override: Option<BTreeMap<String, SocketAddr>>,
    logs: Arc<ProxyLog>,
}

/// Connect one idle pooled connection, retrying until `ctx` is aborted
/// (the slot task is cancelled on pool drop).
async fn connect_idle(socket_path: &Path) -> tokio::net::UnixStream {
    loop {
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// One pool slot: wait for the first byte on the idle connection, hand it
/// to [`handle_connection`], and immediately open a replacement so
/// `POOL_SIZE` connections stay idle.
async fn pool_slot(ctx: Arc<PoolCtx>, mut stream: tokio::net::UnixStream) {
    loop {
        // `readable` fires on the first forwarded byte (or on close).
        let _ = stream.readable().await;
        tokio::spawn(handle_connection(
            stream,
            Arc::clone(&ctx.ca),
            Arc::clone(&ctx.policy),
            Arc::clone(&ctx.client_config),
            ctx.credential.clone(),
            ctx.dns_override.clone(),
            Arc::clone(&ctx.logs),
        ));
        stream = connect_idle(&ctx.socket_path).await;
    }
}

/// Open the connection pool to the in-sandbox forwarder's socket at
/// `socket_path`, keeping [`POOL_SIZE`] idle connections. Retries for up
/// to [`POOL_CONNECT_TIMEOUT`] while the forwarder starts; fails if it
/// never connects.
pub async fn start_connection_pool(
    socket_path: &Path,
    ca: Arc<CaMaterial>,
    policy: Arc<EgressPolicy>,
    credential: Option<String>,
    dns_override: Option<BTreeMap<String, SocketAddr>>,
    upstream_roots: Option<RootCertStore>,
) -> Result<EgressPool, ProxyError> {
    let client_config = upstream_client_config(upstream_roots)?;
    let logs = Arc::new(ProxyLog::new());
    let deadline = Instant::now() + POOL_CONNECT_TIMEOUT;
    let mut idle = Vec::new();
    while idle.len() < POOL_SIZE {
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(stream) => idle.push(stream),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(ProxyError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("egress forwarder did not accept connections: {e}"),
                    )));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let ctx = Arc::new(PoolCtx {
        socket_path: socket_path.to_path_buf(),
        ca,
        policy,
        client_config,
        credential,
        dns_override,
        logs: Arc::clone(&logs),
    });
    let mut handles = Vec::new();
    for stream in idle {
        handles.push(tokio::spawn(pool_slot(Arc::clone(&ctx), stream)).abort_handle());
    }
    Ok(EgressPool {
        logs,
        socket_path: socket_path.to_path_buf(),
        handles,
    })
}

async fn read_until_header_end<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: Duration,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::other("header block too large"));
        }
        let n = tokio::time::timeout(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::other("proxy head read timed out"))??;
        if n == 0 {
            return Err(io::Error::other("connection closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Split `buf` into the header block and any already-read body bytes.
fn split_head(buf: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (buf[..i + 4].to_vec(), buf[i + 4..].to_vec()))
        .ok_or_else(|| io::Error::other("header block not terminated"))
}

/// Parse a `host` / `host:port` authority (bracketed or bare) into
/// `(host, Option<port>)`. Comparison is case-insensitive on the host.
fn parse_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, maybe_port) = match rest.split_once("]:") {
            Some((h, p)) => (h, p.parse::<u16>().ok()),
            None => {
                let h = rest.strip_suffix(']')?;
                (h, None)
            }
        };
        return Some((host.to_owned(), maybe_port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => {
            let port = p.parse::<u16>().ok()?;
            Some((h.to_owned(), Some(port)))
        }
        Some(_) if authority.contains(':') => {
            // Bare IPv6 literal without brackets: whole thing is the host.
            Some((authority.to_owned(), None))
        }
        _ => Some((authority.to_owned(), None)),
    }
}

/// Whether an inner authority matches the outer `host:port`. A missing
/// inner port means the scheme default (`default_port`) and must equal
/// the outer port; a present port must equal the outer port.
fn authority_matches_outer(
    authority: &str,
    outer_host: &str,
    outer_port: u16,
    default_port: u16,
) -> bool {
    let Some((inner_host, inner_port)) = parse_authority(authority) else {
        return false;
    };
    if !inner_host.eq_ignore_ascii_case(outer_host) {
        return false;
    }
    inner_port.unwrap_or(default_port) == outer_port
}

/// Extract the `Host` header value from a request head, if present.
fn host_header_value(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("host")
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Extract the authority from an absolute-form request target, if the
/// request line is absolute-form (`http://…` / `https://…`). Returns
/// `(authority, default_port)` for scheme comparison.
fn absolute_authority(head: &[u8]) -> Option<(String, u16)> {
    let text = String::from_utf8_lossy(head);
    let request_line = text.lines().next()?;
    let target = request_line.split_whitespace().nth(1)?;
    let (rest, default_port) = if let Some(r) = target.strip_prefix("http://") {
        (r, 80)
    } else {
        (target.strip_prefix("https://")?, 443)
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    Some((authority.to_owned(), default_port))
}

/// I1 check: when a binding applies to the outer host, the inner
/// request's `Host` header (and absolute-form authority, if present)
/// must equal the outer host. Returns `true` if injection may proceed.
fn injection_host_ok(head: &[u8], outer_host: &str, outer_port: u16, default_port: u16) -> bool {
    let Some(host_header) = host_header_value(head) else {
        return false;
    };
    if !authority_matches_outer(&host_header, outer_host, outer_port, default_port) {
        return false;
    }
    if let Some((authority, abs_default)) = absolute_authority(head)
        && !authority_matches_outer(&authority, outer_host, outer_port, abs_default)
    {
        return false;
    }
    true
}
/// Inject (or strip, for unbound hosts) the bound secret header in an HTTP
/// request head. `host` is the CONNECT destination. Returns the rewritten
/// head. Injection replaces any client-supplied header of the same name so
/// the sandbox cannot forge it.
fn inject_binding(head: &[u8], policy: &EgressPolicy, host: &str) -> Vec<u8> {
    let Some(binding) = policy.binding_for(host) else {
        return head.to_vec();
    };
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<String> = Vec::new();
    let mut inserted = false;
    for (i, line) in text.split("\r\n").enumerate() {
        if i == 0 {
            out.push(line.to_owned()); // request line
            continue;
        }
        if line.is_empty() {
            continue; // blank terminator re-added below
        }
        if line.contains(':') {
            let name = line.split(':').next().unwrap_or("").trim();
            if name.eq_ignore_ascii_case(&binding.header) {
                if !inserted {
                    // Strip-then-set: emit the secret once, at the position
                    // of the first occurrence.
                    out.push(format!("{}: {}", binding.header, binding.value));
                    inserted = true;
                }
                continue;
            }
        }
        out.push(line.to_owned());
    }
    if !inserted {
        out.push(format!("{}: {}", binding.header, binding.value));
    }
    let mut bytes = out.join("\r\n").into_bytes();
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes
}

/// Whether the request head carries the expected per-sandbox proxy
/// credential (`Proxy-Authorization: Basic <base64>`). Compared in constant
/// time; a missing or malformed header is a mismatch.
fn proxy_authorized(head: &str, expected: &str) -> bool {
    use base64::Engine as _;
    let Some(value) = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("proxy-authorization") {
            Some(value.trim())
        } else {
            None
        }
    }) else {
        return false;
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    crate::ct_eq(&decoded, expected.as_bytes())
}

async fn handle_connection<S>(
    mut client: S,
    ca: Arc<CaMaterial>,
    policy: Arc<EgressPolicy>,
    client_config: Arc<ClientConfig>,
    credential: Option<String>,
    dns_override: Option<BTreeMap<String, SocketAddr>>,
    logs: Arc<ProxyLog>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. Request line: CONNECT authority-form, or absolute-form plain HTTP.
    // A client may send an unauthenticated request, read the 407, and retry
    // with `Proxy-Authorization` on the same connection (git/libcurl does
    // this); keep the socket open and read the next head instead of closing.
    let (head_bytes, body_start) = {
        let mut attempts = 0;
        loop {
            let head = match read_until_header_end(&mut client, Duration::from_secs(10)).await {
                Ok(head) => head,
                Err(_) => return,
            };
            let (head_bytes, body_start) = match split_head(&head) {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let text = String::from_utf8_lossy(&head_bytes).into_owned();
            if let Some(expected) = credential.as_deref()
                && !proxy_authorized(&text, expected)
            {
                logs.record("auth 407".to_owned());
                if client
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"starforge\"\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                attempts += 1;
                if attempts >= 3 {
                    return;
                }
                continue;
            }
            break (head_bytes, body_start);
        }
    };
    let head_text = String::from_utf8_lossy(&head_bytes).into_owned();
    let Some(request_line) = head_text.lines().next().map(str::to_owned) else {
        return;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let is_connect = method == "CONNECT";
    // `(host, port, origin-form request line for plain HTTP)`.
    let (host, port, plain_request_line): (String, u16, Option<String>) = if is_connect {
        let Some((host, port_str)) = target.rsplit_once(':') else {
            return;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            return;
        };
        (host.trim_matches(['[', ']']).to_owned(), port, None)
    } else {
        // Absolute-form: METHOD http://host[:port]/path HTTP/1.1
        let Some(rest) = target.strip_prefix("http://") else {
            let _ = client
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/".to_owned()),
        };
        let (host, port): (String, u16) = match authority.rsplit_once(':') {
            Some((host, port_str)) => match port_str.parse::<u16>() {
                Ok(port) => (host.trim_matches(['[', ']']).to_owned(), port),
                Err(_) => {
                    return;
                }
            },
            None => (authority.trim_matches(['[', ']']).to_owned(), 80),
        };
        let version = request_line.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
        (host, port, Some(format!("{method} {path} {version}")))
    };

    // 2. Policy gate — before any DNS resolution (resolving an
    // attacker-chosen name leaks data through DNS). A host no allowlist
    // entry names is refused with 403 without resolving it, unless CIDR
    // rules or a forge exact match exist that can only be checked
    // against the resolved address.
    let name_allowed = policy.host_port_allowed(&host, port);
    let forge_exact = policy.forge_exact(&host, port);
    let override_addr = dns_override.as_ref().and_then(|m| m.get(&host)).copied();
    if !name_allowed && !forge_exact && override_addr.is_none() && policy.cidr_allow.is_empty() {
        logs.record(format!("{method} {host}:{port} -> 403 denied"));
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    // Resolve + pin (override map in tests, system DNS otherwise).
    let resolved: Vec<SocketAddr> = match override_addr {
        Some(addr) => vec![addr],
        None => match system_resolve(&host, port).await {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => {
                logs.record(format!("{method} {host}:{port} -> 502 dns"));
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }
        },
    };
    // SSRF gate: dial only addresses that themselves pass the policy.
    // A name that is allowlisted but resolves to a special-use address
    // is refused unless the address is in an operator CIDR or the
    // request host:port is the forge exact match.
    let passing: Vec<SocketAddr> = policy.filter_passing(&host, port, &resolved);
    if passing.is_empty() {
        logs.record(format!(
            "{method} {host}:{port} -> 403 special-use address refused"
        ));
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };

    // I1 (plain HTTP): when a binding applies, the inner Host (and
    // absolute-form authority) must equal the outer host; check before
    // dialing so a mismatch never touches the upstream.
    if !is_connect
        && policy.binding_for(&host).is_some()
        && !injection_host_ok(&head_bytes, &host, port, 80)
    {
        logs.record(format!("{method} {host}:{port} -> 403 host mismatch"));
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    // 3. Connect upstream to the first passing address (never re-resolved).
    // Try every passing address: `localhost` often resolves to `::1`
    // first while the origin listens on IPv4 only.
    let mut upstream = None;
    for addr in &passing {
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            upstream = Some(stream);
            break;
        }
    }
    let Some(upstream) = upstream else {
        logs.record(format!("{method} {host}:{port} -> 502 upstream"));
        let _ = client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };

    if !is_connect {
        // Plain HTTP: rewrite absolute-form to origin-form, inject the bound
        // secret header, forward, and relay the response.
        logs.record(format!("{method} {host}:{port} -> 200 plain"));
        let mut rewritten = {
            let text = head_text.clone();
            let mut lines: Vec<String> = text.split("\r\n").map(str::to_owned).collect();
            if let Some(new_line) = &plain_request_line {
                lines[0] = new_line.clone();
            }
            let mut bytes = lines.join("\r\n").into_bytes();
            if !bytes.ends_with(b"\r\n") {
                bytes.extend_from_slice(b"\r\n");
            }
            bytes
        };
        rewritten = inject_binding(&rewritten, &policy, &host);
        if policy.binding_for(&host).is_some() {
            logs.record(format!("{method} {host} -> inject header"));
        }
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        if upstream_write.write_all(&rewritten).await.is_err() {
            return;
        }
        if !body_start.is_empty() && upstream_write.write_all(&body_start).await.is_err() {
            return;
        }
        let client_to_upstream = async {
            let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
            let _ = upstream_write.shutdown().await;
        };
        let upstream_to_client = async {
            let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
            let _ = client_write.shutdown().await;
        };
        tokio::join!(client_to_upstream, upstream_to_client);
        return;
    }

    // CONNECT: mint the MITM leaf only for allowed HTTPS destinations.
    let leaf = if policy.https_ports.contains(&port) {
        match ca.mint_leaf(&policy, &host) {
            Ok(leaf) => Some(leaf),
            Err(_) => return,
        }
    } else {
        None
    };
    match (port, leaf) {
        (_, Some(leaf)) => {
            let server_config = match server_config_for_leaf(&leaf) {
                Ok(config) => config,
                Err(_) => return,
            };
            let server_name = match ServerName::try_from(host.clone()) {
                Ok(name) => name,
                Err(_) => return,
            };
            logs.record(format!("CONNECT {host}:{port} -> 200 mitm"));
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let acceptor = tokio_rustls::server::TlsAcceptor::from(Arc::new(server_config));
            let client_tls = match acceptor.accept(client).await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let connector = tokio_rustls::client::TlsConnector::from(Arc::clone(&client_config));
            let upstream_tls = match connector.connect(server_name, upstream).await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            relay_http(client_tls, upstream_tls, &policy, &host, port, logs).await;
        }
        (_, _) => {
            logs.record(format!("CONNECT {host}:{port} -> 200 tcp"));
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            if port == 80 {
                relay_http(client, upstream, &policy, &host, 80, logs).await;
            } else {
                relay_raw(client, upstream).await;
            }
        }
    }
}

fn server_config_for_leaf(leaf: &LeafMaterial) -> Result<ServerConfig, ProxyError> {
    ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| ProxyError::Ca(format!("server config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.cert_der.clone())],
            PrivateKeyDer::try_from(leaf.key_der.clone())
                .map_err(|e| ProxyError::Ca(format!("leaf key parse: {e}")))?,
        )
        .map_err(|e| ProxyError::Ca(format!("single cert: {e}")))
}

/// Read one HTTP request through a tunneled stream, inject the binding
/// header, forward to the origin stream, and relay both directions.
async fn relay_http<C, U>(
    client: C,
    upstream: U,
    policy: &EgressPolicy,
    host: &str,
    port: u16,
    logs: Arc<ProxyLog>,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let head = match read_until_header_end(&mut client_read, Duration::from_secs(30)).await {
        Ok(head) => head,
        Err(_) => return,
    };
    let (head_bytes, body_start) = match split_head(&head) {
        Ok(pair) => pair,
        Err(_) => return,
    };
    let first_line = String::from_utf8_lossy(&head_bytes)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    let method = first_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    // I1 (tunneled): when a binding applies, the inner Host (and
    // absolute-form authority) must equal the outer CONNECT host.
    if policy.binding_for(host).is_some() {
        let default_port = if port == 443 { 443 } else { 80 };
        if !injection_host_ok(&head_bytes, host, port, default_port) {
            logs.record(format!("{method} {host}:{port} -> 403 host mismatch"));
            let _ = client_write
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    }
    let rewritten = inject_binding(&head_bytes, policy, host);
    if let Some(binding) = policy.binding_for(host) {
        logs.record(format!("{method} {host} -> inject {}", binding.header));
    }
    let _ = upstream_write.write_all(&rewritten).await;
    if !body_start.is_empty() {
        let _ = upstream_write.write_all(&body_start).await;
    }
    // Relay to EOF in both directions, shutting down the destination
    // write half when a direction ends so the peer sees EOF (instead of
    // waiting forever for the other direction to end too).
    let client_to_upstream = async {
        let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.shutdown().await;
    };
    let upstream_to_client = async {
        let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
    };
    tokio::join!(client_to_upstream, upstream_to_client);
}

async fn relay_raw<C>(client: C, upstream: tokio::net::TcpStream)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let client_to_upstream = async {
        let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.shutdown().await;
    };
    let upstream_to_client = async {
        let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
    };
    tokio::join!(client_to_upstream, upstream_to_client);
}

// ------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Spin up a local TLS origin that echoes received request headers.
    async fn spawn_origin() -> (SocketAddr, RootCertStore, Vec<u8>) {
        use rustls::pki_types::CertificateDer;
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("bound.test".to_owned().try_into().unwrap()),
            rcgen::SanType::DnsName("unbound.test".to_owned().try_into().unwrap()),
        ];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key.serialize_der();
        let mut store = RootCertStore::empty();
        store.add(CertificateDer::from(cert_der.clone())).unwrap();
        let config = ServerConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::try_from(key_der.clone()).unwrap(),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let config = Arc::new(config);
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let acceptor = tokio_rustls::server::TlsAcceptor::from(Arc::clone(&config));
                    let tls = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    let (mut read, mut write) = tokio::io::split(tls);
                    let head = read_until_header_end(&mut read, Duration::from_secs(10))
                        .await
                        .unwrap_or_default();
                    let (head_bytes, _) = split_head(&head).unwrap_or_default();
                    let dump = String::from_utf8_lossy(&head_bytes).into_owned();
                    let body = format!("HEADERS>>> {dump}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = write.write_all(response.as_bytes()).await;
                    let _ = write.shutdown().await;
                });
            }
        });
        (addr, store, cert_der)
    }

    fn test_policy(secret: &str) -> EgressPolicy {
        EgressPolicy {
            allow_out: vec!["bound.test".to_owned(), "unbound.test".to_owned()],
            deny_out: Vec::new(),
            bindings: vec![SecretBinding {
                host: "bound.test".to_owned(),
                header: "Authorization".to_owned(),
                value: secret.to_owned(),
            }],
            forge: None,
            cidr_allow: Vec::new(),
            https_ports: vec![443],
        }
    }

    /// Success-path policy whose override origins sit on loopback: the
    /// operator CIDR admits the loopback origin (SSRF rule still refuses
    /// special addresses without CIDR/forge).
    fn test_policy_with_loopback_cidr(secret: &str) -> EgressPolicy {
        let mut policy = test_policy(secret);
        policy.cidr_allow = vec![IpNet::parse("127.0.0.1/32").unwrap()];
        policy
    }

    async fn start_test_proxy(
        policy: EgressPolicy,
        ca: Arc<CaMaterial>,
        origin: SocketAddr,
        upstream_roots: RootCertStore,
    ) -> EgressProxy {
        let overrides: BTreeMap<String, SocketAddr> = [
            ("bound.test", origin),
            ("unbound.test", origin),
            ("evil.test", origin),
        ]
        .into_iter()
        .map(|(h, a)| (h.to_owned(), a))
        .collect();
        start_proxy(
            (Ipv4Addr::LOCALHOST, 0).into(),
            ca,
            Arc::new(policy),
            None,
            Some(overrides),
            Some(upstream_roots),
        )
        .await
        .unwrap()
    }

    async fn fetch_via_proxy(proxy: SocketAddr, ca: &CaMaterial, host: &str, port: u16) -> String {
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        // Byte-by-byte head read: no over-read into the TLS handshake.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.extend_from_slice(&byte);
            assert!(head.len() < MAX_HEAD_BYTES, "CONNECT response too large");
        }
        let status_line = String::from_utf8_lossy(&head);
        assert!(status_line.contains("200"), "CONNECT failed: {status_line}");
        // TLS through the tunnel, verified against the proxy CA.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert_der.clone()))
            .unwrap();
        let config = ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::client::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect(ServerName::try_from(host.to_owned()).unwrap(), stream)
            .await
            .unwrap();
        let (mut tls_read, mut tls_write) = tokio::io::split(tls);
        tls_write
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(10), tls_read.read_to_end(&mut body)).await;
        String::from_utf8_lossy(&body).into_owned()
    }

    #[tokio::test]
    async fn secret_header_injected_only_for_bound_host() {
        let secret = "s3cr3t-value-that-must-not-leak";
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(
            CaMaterial::generate(&["bound.test".to_owned(), "unbound.test".to_owned()]).unwrap(),
        );
        let proxy = start_test_proxy(
            test_policy_with_loopback_cidr(secret),
            Arc::clone(&ca),
            origin,
            upstream_roots,
        )
        .await;

        // Bound host: secret header arrives at the origin.
        let bound = fetch_via_proxy(proxy.addr(), &ca, "bound.test", 443).await;
        assert!(
            bound
                .to_lowercase()
                .contains(&format!("authorization: {secret}").to_lowercase()),
            "bound host got header: {bound}"
        );

        // Unbound (but allowlisted) host: no secret header.
        let unbound = fetch_via_proxy(proxy.addr(), &ca, "unbound.test", 443).await;
        assert!(
            !unbound.contains(secret),
            "unbound leaked secret: {unbound}"
        );
        assert!(
            !unbound.to_lowercase().contains("authorization:"),
            "unbound got authorization header: {unbound}"
        );
    }

    #[tokio::test]
    async fn default_deny_non_allowlisted_host() {
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(CaMaterial::generate(&["bound.test".to_owned()]).unwrap());
        let proxy = start_test_proxy(
            test_policy("secret-x"),
            Arc::clone(&ca),
            origin,
            upstream_roots,
        )
        .await;
        let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        write
            .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_until_header_end(&mut read, Duration::from_secs(10))
            .await
            .unwrap();
        let (head_bytes, _) = split_head(&head).unwrap();
        assert!(
            String::from_utf8_lossy(&head_bytes).contains("403"),
            "expected 403: {}",
            String::from_utf8_lossy(&head_bytes)
        );
    }

    #[tokio::test]
    async fn non_http_port_denied_without_cidr() {
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(CaMaterial::generate(&["bound.test".to_owned()]).unwrap());
        let proxy = start_test_proxy(
            test_policy("secret-x"),
            Arc::clone(&ca),
            origin,
            upstream_roots,
        )
        .await;
        let stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        write
            .write_all(b"CONNECT bound.test:22 HTTP/1.1\r\nHost: bound.test:22\r\n\r\n")
            .await
            .unwrap();
        let head = read_until_header_end(&mut read, Duration::from_secs(10))
            .await
            .unwrap();
        let (head_bytes, _) = split_head(&head).unwrap();
        assert!(
            String::from_utf8_lossy(&head_bytes).contains("403"),
            "expected 403 for non-HTTP port: {}",
            String::from_utf8_lossy(&head_bytes)
        );
    }

    #[test]
    fn ca_cannot_sign_unbound_host_and_has_name_constraints() {
        let ca = CaMaterial::generate(&["bound.test".to_owned()]).unwrap();
        let policy = test_policy("x");
        // Unbound host: mint refused.
        assert!(matches!(
            ca.mint_leaf(&policy, "evil.test"),
            Err(ProxyError::HostDenied(_))
        ));
        // Bound host: mint works.
        assert!(ca.mint_leaf(&policy, "bound.test").is_ok());
        // Name constraints OID (2.5.29.30) present in the CA cert DER.
        let oid = [0x06, 0x03, 0x55, 0x1d, 0x1e];
        assert!(
            ca.cert_der.windows(oid.len()).any(|w| w == oid),
            "CA cert must carry a name-constraints extension"
        );
    }

    #[tokio::test]
    async fn proxy_logs_carry_no_secret() {
        let secret = "s3cr3t-value-that-must-not-leak";
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(
            CaMaterial::generate(&["bound.test".to_owned(), "unbound.test".to_owned()]).unwrap(),
        );
        let proxy = start_test_proxy(
            test_policy_with_loopback_cidr(secret),
            Arc::clone(&ca),
            origin,
            upstream_roots,
        )
        .await;
        let _ = fetch_via_proxy(proxy.addr(), &ca, "bound.test", 443).await;
        let _ = fetch_via_proxy(proxy.addr(), &ca, "unbound.test", 443).await;
        for line in proxy.logs().lines() {
            assert!(!line.contains(secret), "secret in proxy log: {line}");
        }
        // Debug form of a binding redacts the value too.
        let binding = policy_binding();
        fn policy_binding() -> SecretBinding {
            SecretBinding {
                host: "h".to_owned(),
                header: "Authorization".to_owned(),
                value: "s3cr3t-value-that-must-not-leak".to_owned(),
            }
        }
        assert!(!format!("{binding:?}").contains("s3cr3t"));
    }

    #[test]
    fn ca_key_file_is_0600() {
        let dir = std::env::temp_dir().join(format!("starforge-proxy-test-{}", std::process::id()));
        let path = dir.join("ca.key");
        let ca = CaMaterial::generate(&["bound.test".to_owned()]).unwrap();
        write_ca_key(&path, &ca.key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "CA key must be 0600");
        }
        destroy_ca_key(&path);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Spin up a local plain-HTTP origin that echoes received request heads.
    async fn spawn_plain_origin() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut read, mut write) = tokio::io::split(stream);
                    let head = read_until_header_end(&mut read, Duration::from_secs(10))
                        .await
                        .unwrap_or_default();
                    let (head_bytes, _) = split_head(&head).unwrap_or_default();
                    let dump = String::from_utf8_lossy(&head_bytes).into_owned();
                    let body = format!("HEADERS>>> {dump}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = write.write_all(response.as_bytes()).await;
                    let _ = write.shutdown().await;
                });
            }
        });
        addr
    }

    async fn fetch_plain_via_unix(sock: &Path, target: &str) -> String {
        let mut stream = tokio::net::UnixStream::connect(sock).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                        .strip_prefix("http://")
                        .unwrap_or(target)
                        .split('/')
                        .next()
                        .unwrap_or_default()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut body)).await;
        String::from_utf8_lossy(&body).into_owned()
    }

    #[tokio::test]
    async fn plain_http_forwarded_via_unix_proxy_with_secret() {
        let secret = "plain-secret-xyz";
        let origin = spawn_plain_origin().await;
        let host = "127.0.0.1";
        let entry = format!("{host}:{}", origin.port());
        let policy = EgressPolicy {
            allow_out: vec![entry.clone()],
            deny_out: Vec::new(),
            bindings: vec![SecretBinding {
                host: host.to_owned(),
                header: "Authorization".to_owned(),
                value: secret.to_owned(),
            }],
            forge: Some(entry.clone()),
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        };
        let ca = Arc::new(CaMaterial::generate(&[entry]).unwrap());
        let dir =
            std::env::temp_dir().join(format!("starforge-plain-proxy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        assert!(sock.exists());
        let target = format!("http://{host}:{}/x?y=1", origin.port());
        let response = fetch_plain_via_unix(&sock, &target).await;
        assert!(
            response.contains("200 OK"),
            "plain forward failed: {response}"
        );
        // Origin received origin-form (not absolute-form) …
        assert!(
            response.contains("GET /x?y=1 HTTP/1.1"),
            "origin-form rewrite missing: {response}"
        );
        assert!(
            !response.contains(&format!("GET {target}")),
            "absolute-form leaked to origin: {response}"
        );
        // … and the bound secret header was injected.
        assert!(
            response
                .to_lowercase()
                .contains(&format!("authorization: {secret}").to_lowercase()),
            "secret header not injected: {response}"
        );
        for line in proxy.logs().lines() {
            assert!(!line.contains(secret), "secret in proxy log: {line}");
        }
        drop(proxy);
        assert!(!sock.exists(), "socket removed on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn plain_http_denied_host_gets_403() {
        let origin = spawn_plain_origin().await;
        let entry = format!("127.0.0.1:{}", origin.port());
        let policy = EgressPolicy {
            allow_out: vec![entry.clone()],
            deny_out: Vec::new(),
            bindings: Vec::new(),
            forge: None,
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        };
        let ca = Arc::new(CaMaterial::generate(&[entry]).unwrap());
        let dir =
            std::env::temp_dir().join(format!("starforge-plain-deny-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let response = fetch_plain_via_unix(&sock, "http://evil.test/x").await;
        assert!(
            response.contains("403"),
            "expected 403 for denied host: {response}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn plain_http_close_framed_response_reaches_eof() {
        // Origin answers without Content-Length and closes; the client
        // reading through the plain-HTTP path must see EOF (the relay
        // must shut down the client write half when the origin ends),
        // not hang waiting for the other relay direction.
        let origin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let origin = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = origin_listener.accept().await else {
                return;
            };
            let (mut read, mut write) = tokio::io::split(stream);
            let _head = read_until_header_end(&mut read, Duration::from_secs(10))
                .await
                .unwrap_or_default();
            let _ = write
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello-close")
                .await;
            let _ = write.shutdown().await;
        });
        let entry = format!("127.0.0.1:{}", origin.port());
        let policy = EgressPolicy {
            allow_out: vec![entry.clone()],
            deny_out: Vec::new(),
            bindings: Vec::new(),
            forge: Some(entry.clone()),
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        };
        let ca = Arc::new(CaMaterial::generate(&[entry]).unwrap());
        let dir =
            std::env::temp_dir().join(format!("starforge-plain-eof-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                    origin.port(),
                    origin.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut body))
            .await
            .expect("read to EOF must complete once the origin closes")
            .unwrap();
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(text.contains("200 OK"), "response missing: {text}");
        assert!(text.contains("hello-close"), "body missing: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn port_not_named_by_host_port_entry_is_refused() {
        let origin = spawn_plain_origin().await;
        // Allowlist names only the origin's port; another port must be refused
        // for both plain HTTP and CONNECT.
        let entry = format!("127.0.0.1:{}", origin.port());
        let policy = EgressPolicy {
            allow_out: vec![entry.clone()],
            deny_out: Vec::new(),
            bindings: Vec::new(),
            forge: Some(entry.clone()),
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        };
        let ca = Arc::new(CaMaterial::generate(&[entry]).unwrap());
        let dir =
            std::env::temp_dir().join(format!("starforge-port-deny-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let other = origin.port().saturating_add(1).max(2);
        let response = fetch_plain_via_unix(&sock, &format!("http://127.0.0.1:{other}/x")).await;
        assert!(
            response.contains("403"),
            "plain request to unnamed port must be 403: {response}"
        );
        // CONNECT to the unnamed port is refused too.
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(
                format!("CONNECT 127.0.0.1:{other} HTTP/1.1\r\nHost: 127.0.0.1:{other}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let head = read_until_header_end(&mut stream, Duration::from_secs(10))
            .await
            .unwrap();
        let (head_bytes, _) = split_head(&head).unwrap();
        assert!(
            String::from_utf8_lossy(&head_bytes).contains("403"),
            "CONNECT to unnamed port must be 403: {}",
            String::from_utf8_lossy(&head_bytes)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pool_keeps_four_idle_and_replaces_used_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Local Unix listener standing in for the in-sandbox forwarder.
        let dir = std::env::temp_dir().join(format!("starforge-pool-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("shim.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let streams: Arc<Mutex<Vec<tokio::net::UnixStream>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let accepted = Arc::clone(&accepted);
            let streams = Arc::clone(&streams);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    accepted.fetch_add(1, Ordering::SeqCst);
                    streams.lock().unwrap().push(stream);
                }
            });
        }
        let entry = "bound.test".to_owned();
        let ca = Arc::new(CaMaterial::generate(std::slice::from_ref(&entry)).unwrap());
        let policy = Arc::new(EgressPolicy {
            allow_out: vec![entry],
            deny_out: Vec::new(),
            bindings: Vec::new(),
            forge: None,
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        });
        let pool = start_connection_pool(&sock, ca, policy, None, None, None)
            .await
            .unwrap();
        // 4 idle connections are open.
        for _ in 0..100 {
            if accepted.load(Ordering::SeqCst) >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 4);
        // Use one pooled connection from the forwarder side: send a denied
        // plain request; the proxy handler on that connection answers 403.
        let mut used = {
            let mut guard = streams.lock().unwrap();
            guard.remove(0)
        };
        used.write_all(b"GET http://evil.test/x HTTP/1.1\r\nHost: evil.test\r\n\r\n")
            .await
            .unwrap();
        let head = read_until_header_end(&mut used, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head).contains("403"),
            "pooled connection must go through the proxy policy: {}",
            String::from_utf8_lossy(&head)
        );
        // A replacement idle connection is opened (5th accepted).
        for _ in 0..100 {
            if accepted.load(Ordering::SeqCst) >= 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 5);
        drop(pool);
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------ SSRF (I1/I2) --
    fn policy_allow(name: &str, forge: Option<String>, cidr: Vec<IpNet>) -> EgressPolicy {
        EgressPolicy {
            allow_out: vec![name.to_owned()],
            deny_out: Vec::new(),
            bindings: Vec::new(),
            forge,
            cidr_allow: cidr,
            https_ports: Vec::new(),
        }
    }

    #[test]
    fn selection_skips_blocked_first_and_keeps_allowed_later() {
        let policy = policy_allow("good.test", None, Vec::new());
        let resolved = vec![
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
            SocketAddr::new("93.184.215.14".parse().unwrap(), 443),
        ];
        let passing = policy.filter_passing("good.test", 443, &resolved);
        assert_eq!(
            passing,
            vec![resolved[1]],
            "blocked loopback must be skipped"
        );
    }

    #[test]
    fn mapped_ipv6_loopback_is_special_and_blocked() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_special_use(&mapped));
        let policy = policy_allow("good.test", None, Vec::new());
        assert!(!policy.addr_passes("good.test", 443, &mapped));
        // Operator CIDR covering the IPv4 form also covers the mapped form.
        let with_cidr = policy_allow(
            "good.test",
            None,
            vec![IpNet::parse("127.0.0.1/32").unwrap()],
        );
        assert!(with_cidr.addr_passes("good.test", 443, &mapped));
    }

    #[test]
    fn forge_exact_allows_only_that_port_cidr_allows_loopback() {
        let forge = "127.0.0.1:3000".to_owned();
        let with_forge = policy_allow("127.0.0.1:3000", Some(forge.clone()), Vec::new());
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(with_forge.addr_passes("127.0.0.1", 3000, &loopback));
        assert!(
            !with_forge.addr_passes("127.0.0.1", 3001, &loopback),
            "same host, other port must be refused"
        );
        let with_cidr = policy_allow(
            "127.0.0.1:3000",
            None,
            vec![IpNet::parse("127.0.0.1/32").unwrap()],
        );
        assert!(with_cidr.addr_passes("127.0.0.1", 3000, &loopback));
        assert!(with_cidr.addr_passes("127.0.0.1", 9999, &loopback));
    }

    async fn connect_head(proxy: SocketAddr, target: &str) -> String {
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        write
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until_header_end(&mut read, Duration::from_secs(10))
            .await
            .unwrap();
        let (head_bytes, _) = split_head(&head).unwrap();
        String::from_utf8_lossy(&head_bytes).into_owned()
    }

    #[tokio::test]
    async fn allowlisted_name_resolving_to_loopback_is_refused() {
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(CaMaterial::generate(&["bound.test".to_owned()]).unwrap());
        let proxy =
            start_test_proxy(test_policy("s"), Arc::clone(&ca), origin, upstream_roots).await;
        let head = connect_head(proxy.addr(), "bound.test:443").await;
        assert!(head.contains("403"), "expected 403: {head}");
    }

    #[tokio::test]
    async fn allowlisted_ip_literal_loopback_is_refused_without_forge() {
        let origin = spawn_plain_origin().await;
        let entry = format!("127.0.0.1:{}", origin.port());
        let ca = Arc::new(CaMaterial::generate(std::slice::from_ref(&entry)).unwrap());
        let dir =
            std::env::temp_dir().join(format!("starforge-ip-literal-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let policy = policy_allow(&entry, None, Vec::new());
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(format!("CONNECT {entry} HTTP/1.1\r\nHost: {entry}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until_header_end(&mut stream, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head).contains("403"),
            "expected 403: {}",
            String::from_utf8_lossy(&head)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn forge_exact_is_allowed_other_port_refused() {
        let origin = spawn_plain_origin().await;
        let entry = format!("127.0.0.1:{}", origin.port());
        let ca = Arc::new(CaMaterial::generate(std::slice::from_ref(&entry)).unwrap());
        let dir = std::env::temp_dir().join(format!("starforge-forge-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let policy = policy_allow(&entry, Some(entry.clone()), Vec::new());
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(format!("CONNECT {entry} HTTP/1.1\r\nHost: {entry}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until_header_end(&mut stream, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head).contains("200"),
            "forge exact must be 200: {}",
            String::from_utf8_lossy(&head)
        );
        drop(stream);
        let other_port = origin.port().saturating_add(1).max(2);
        let other = format!("127.0.0.1:{other_port}");
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(format!("CONNECT {other} HTTP/1.1\r\nHost: {other}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until_header_end(&mut stream, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head).contains("403"),
            "same host other port must be 403: {}",
            String::from_utf8_lossy(&head)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cidr_loopback_is_allowed() {
        let origin = spawn_plain_origin().await;
        let entry = format!("127.0.0.1:{}", origin.port());
        let ca = Arc::new(CaMaterial::generate(std::slice::from_ref(&entry)).unwrap());
        let dir = std::env::temp_dir().join(format!("starforge-cidr-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let cidr = vec![IpNet::parse("127.0.0.1/32").unwrap()];
        let policy = policy_allow(&entry, None, cidr);
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(format!("CONNECT {entry} HTTP/1.1\r\nHost: {entry}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until_header_end(&mut stream, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&head).contains("200"),
            "CIDR loopback must be 200: {}",
            String::from_utf8_lossy(&head)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn plain_injection_refused_on_host_mismatch() {
        let secret = "plain-secret-xyz";
        let origin = spawn_plain_origin().await;
        let host = "127.0.0.1";
        let entry = format!("{host}:{}", origin.port());
        let policy = EgressPolicy {
            allow_out: vec![entry.clone()],
            deny_out: Vec::new(),
            bindings: vec![SecretBinding {
                host: host.to_owned(),
                header: "Authorization".to_owned(),
                value: secret.to_owned(),
            }],
            forge: Some(entry.clone()),
            cidr_allow: Vec::new(),
            https_ports: Vec::new(),
        };
        let ca = Arc::new(CaMaterial::generate(&[entry]).unwrap());
        let dir = std::env::temp_dir().join(format!(
            "starforge-plain-mismatch-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let _proxy = start_proxy_unix(&sock, ca, Arc::new(policy), None, None, None)
            .await
            .unwrap();
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n",
                    origin.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut body)).await;
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(text.contains("403"), "host mismatch must be 403: {text}");
        assert!(
            !text.contains(secret),
            "secret must not be injected: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mitm_injection_refused_on_host_mismatch() {
        let secret = "s3cr3t-mismatch";
        let (origin, upstream_roots, _) = spawn_origin().await;
        let ca = Arc::new(CaMaterial::generate(&["bound.test".to_owned()]).unwrap());
        let proxy = start_test_proxy(
            test_policy_with_loopback_cidr(secret),
            Arc::clone(&ca),
            origin,
            upstream_roots,
        )
        .await;
        // CONNECT bound.test:443 then TLS with a mismatched inner Host.
        let mut stream = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
        stream
            .write_all(b"CONNECT bound.test:443 HTTP/1.1\r\nHost: bound.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.extend_from_slice(&byte);
        }
        assert!(
            String::from_utf8_lossy(&head).contains("200"),
            "CONNECT failed: {}",
            String::from_utf8_lossy(&head)
        );
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert_der.clone()))
            .unwrap();
        let config = ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::client::TlsConnector::from(Arc::new(config));
        let tls = connector
            .connect(
                ServerName::try_from("bound.test".to_owned()).unwrap(),
                stream,
            )
            .await
            .unwrap();
        let (mut tls_read, mut tls_write) = tokio::io::split(tls);
        tls_write
            .write_all(b"GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(10), tls_read.read_to_end(&mut body)).await;
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(
            text.contains("403"),
            "MITM host mismatch must be 403: {text}"
        );
        assert!(!text.contains(secret), "secret must not leak: {text}");
    }
}
