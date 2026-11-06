//! Outbound git remote URL policy (M4b): the one gate every import and
//! mirror URL passes at save time and again before every fetch or push.
//!
//! Allowed: `https`, and `ssh` (`ssh://` and scp-like `user@host:path`),
//! plus `http` only when the resolved host is loopback and the test-only
//! `remotes.allow_file_urls` flag is set. Refused: `file://`, local paths,
//! `ext::`, `fd::`, and every other transport — unless the test-only flag
//! is set, which also admits loopback hosts. Hosts are refused by the same
//! SSRF rules as the webhook delivery gate
//! ([`crate::webhooks::host_allowed`]): private, loopback (unless
//! flagged), link-local including the metadata endpoint, unique-local,
//! multicast, and the other non-global ranges. The first allowed resolved
//! address is pinned on the returned [`PinnedRemote`] so git cannot be
//! redirected by a DNS change between the check and the connection.
//!
//! DNS is injectable through [`HostResolver`] so unit tests stub
//! resolution; production uses [`LookupResolver`] (the system resolver).

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

use starforged_git::remote::{PinnedRemote, RemoteScheme};

use crate::webhooks::host_allowed;
use crate::{Core, CoreError, CoreResult};

/// Re-exported so callers of the policy need only `starforged_core`.
pub use starforged_git::remote::{FetchOutcome, LsRemoteHead, RemoteCreds};

/// Resolves a host to candidate addresses. Injectable for tests; the
/// production implementation uses the system resolver.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;
}

/// The system resolver (`ToSocketAddrs`).
pub struct LookupResolver;

impl HostResolver for LookupResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .map_err(|e| format!("{host} does not resolve: {e}"))
    }
}

/// A resolver returning fixed addresses for every host (unit tests).
pub struct FixedResolver {
    pub addrs: Vec<IpAddr>,
}

impl HostResolver for FixedResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        Ok(self.addrs.clone())
    }
}

/// A resolver returning per-host addresses (unit tests).
pub struct MapResolver {
    pub map: HashMap<String, Vec<IpAddr>>,
}

impl HostResolver for MapResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        self.map
            .get(host)
            .cloned()
            .ok_or_else(|| format!("{host} does not resolve"))
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

/// The policy check behind [`Core::check_remote_url`], with an injectable
/// resolver. `allow_file_urls` is the test-only `remotes.allow_file_urls`
/// flag: it admits `file://`/local paths and loopback hosts (and `http` to
/// loopback), and nothing else changes.
pub fn check_url(
    url: &str,
    allow_file_urls: bool,
    resolver: &dyn HostResolver,
) -> CoreResult<PinnedRemote> {
    let url = url.trim();
    if url.is_empty() {
        return Err(invalid("remote url is empty"));
    }
    if url.chars().any(char::is_whitespace) {
        return Err(invalid("remote url contains whitespace"));
    }
    // Transports spelled `ext::`, `fd::`, … (anything of the form
    // `<name>::<command>` with no `/` in the name) run arbitrary commands.
    if let Some((name, _)) = url.split_once("::")
        && !name.is_empty()
        && !name.contains('/')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(invalid(format!(
            "remote url transport `{name}::` is not allowed"
        )));
    }
    if url.starts_with("file://") {
        if !allow_file_urls {
            return Err(invalid("file:// remote urls are not allowed"));
        }
        return Ok(PinnedRemote {
            url: url.to_owned(),
            scheme: RemoteScheme::File,
            host: String::new(),
            port: 0,
            pinned_ip: None,
        });
    }
    // Scp-like SSH syntax (`user@host:path`) has no `://`.
    if !url.contains("://") {
        if let Some(scp) = parse_scp_like(url) {
            return check_host(
                url.to_owned(),
                RemoteScheme::Ssh,
                scp.0,
                scp.1,
                22,
                allow_file_urls,
                resolver,
            );
        }
        // Anything else without a scheme is a local path.
        if !allow_file_urls {
            return Err(invalid("local-path remote urls are not allowed"));
        }
        return Ok(PinnedRemote {
            url: url.to_owned(),
            scheme: RemoteScheme::File,
            host: String::new(),
            port: 0,
            pinned_ip: None,
        });
    }
    let parsed = url::Url::parse(url).map_err(|_| invalid("remote url does not parse"))?;
    let scheme = match parsed.scheme() {
        "https" => RemoteScheme::Https,
        "http" => RemoteScheme::Http,
        "ssh" => RemoteScheme::Ssh,
        other => {
            return Err(invalid(format!(
                "remote url scheme `{other}` is not allowed"
            )));
        }
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("remote url has no host"))?
        .to_owned();
    // `Url::port_or_known_default` does not know `ssh`, so fall back to the
    // scheme default explicitly.
    let port = parsed.port().unwrap_or(match scheme {
        RemoteScheme::Https => 443,
        RemoteScheme::Http => 80,
        RemoteScheme::Ssh => 22,
        RemoteScheme::File => 0,
    });
    // The URL git receives carries no password: credentials travel via the
    // `http.extraHeader` env, never the URL.
    let mut sanitized = parsed.clone();
    let _ = sanitized.set_password(None);
    check_host(
        sanitized.to_string(),
        scheme,
        host,
        String::new(),
        port,
        allow_file_urls,
        resolver,
    )
    .map(|mut pinned| {
        // Preserve the parsed (bracketed-IPv6) host form in the URL; the
        // bare host lives in `pinned.host` for pinning arguments.
        pinned.url = sanitized.to_string();
        pinned
    })
}

/// Parses scp-like `user@host:path` (or bare `host:path`), returning the
/// host and the user. `None` when the string is not scp-like.
fn parse_scp_like(url: &str) -> Option<(String, String)> {
    let (before_colon, _path) = url.split_once(':')?;
    if before_colon.contains('/') {
        return None;
    }
    let (user, host) = match before_colon.rsplit_once('@') {
        Some((user, host)) => (user.to_owned(), host.to_owned()),
        None => (String::new(), before_colon.to_owned()),
    };
    if host.is_empty() || host.contains(['/', '@', ' ']) {
        return None;
    }
    // A bare `host:path` with no `@` and a dotless single label is more
    // likely a Windows path or a typo than SSH; require the `@` form or a
    // dotted host.
    if user.is_empty() && !host.contains('.') && host.parse::<IpAddr>().is_err() {
        return None;
    }
    Some((host, user))
}

/// Applies the SSRF host rules to `host` and pins the first allowed
/// address. `http` additionally requires loopback plus the test flag.
#[allow(clippy::too_many_arguments)]
fn check_host(
    url: String,
    scheme: RemoteScheme,
    host: String,
    _user: String,
    port: u16,
    allow_file_urls: bool,
    resolver: &dyn HostResolver,
) -> CoreResult<PinnedRemote> {
    // `host_str` keeps IPv6 brackets; strip them before parsing.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    let pinned_ip = if let Ok(ip) = bare.parse::<IpAddr>() {
        if !host_allowed(ip, allow_file_urls) {
            return Err(invalid(format!("remote host {host} is not allowed")));
        }
        // IP literals never consult DNS: nothing to pin.
        None
    } else {
        let addrs = resolver.resolve(bare, port).map_err(invalid)?;
        if addrs.is_empty() {
            return Err(invalid(format!("remote host {host} does not resolve")));
        }
        let mut pinned = None;
        for ip in &addrs {
            if host_allowed(*ip, allow_file_urls) {
                pinned = Some(*ip);
                break;
            }
        }
        match pinned {
            Some(ip) => Some(ip),
            None => {
                return Err(invalid(format!(
                    "remote host {host} resolves to no allowed address"
                )));
            }
        }
    };
    if scheme == RemoteScheme::Http {
        // `http` only to loopback, and only under the test flag.
        let ip = pinned_ip.or_else(|| bare.parse::<IpAddr>().ok());
        let is_loopback = ip.is_some_and(|ip| ip.is_loopback());
        if !(allow_file_urls && is_loopback) {
            return Err(invalid(
                "http remote urls are only allowed to loopback in tests",
            ));
        }
    }
    Ok(PinnedRemote {
        url,
        scheme,
        host: bare.to_owned(),
        port,
        pinned_ip,
    })
}

impl Core {
    /// Checks a remote URL against the outbound policy and returns the
    /// pinned remote git should talk to (see the module docs). Uses the
    /// system resolver; see [`Core::check_remote_url_with_resolver`] for
    /// the injectable-resolver form.
    pub fn check_remote_url(&self, url: &str) -> CoreResult<PinnedRemote> {
        check_url(url, self.config().allow_file_urls, &LookupResolver)
    }

    /// Like [`Core::check_remote_url`] with an injectable resolver (tests).
    pub fn check_remote_url_with_resolver(
        &self,
        url: &str,
        resolver: &dyn HostResolver,
    ) -> CoreResult<PinnedRemote> {
        check_url(url, self.config().allow_file_urls, resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn public() -> FixedResolver {
        FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        }
    }

    fn private() -> FixedResolver {
        FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        }
    }

    #[test]
    fn refuses_disallowed_transports_and_hosts() {
        let r = public();
        for url in [
            "file:///srv/repos/x.git",
            "/srv/repos/x.git",
            "./local.git",
            "../local.git",
            "ext::sh -c 'id'",
            "fd::17",
            "git://git.example.com/x.git",
            "ftp://git.example.com/x.git",
            "https://",
            "",
        ] {
            assert!(check_url(url, false, &r).is_err(), "{url} must be refused");
        }
        // Private, loopback (flag off), and metadata IPs are refused.
        assert!(check_url("https://10.0.0.1/x.git", false, &r).is_err());
        assert!(check_url("https://127.0.0.1/x.git", false, &r).is_err());
        assert!(check_url("https://169.254.169.254/x.git", false, &r).is_err());
        assert!(check_url("https://[::1]/x.git", false, &r).is_err());
        // A public hostname resolving only to private addresses is refused.
        assert!(check_url("https://evil.example.com/x.git", false, &private()).is_err());
        // Plain http to a public host is refused.
        assert!(check_url("http://git.example.com/x.git", false, &r).is_err());
    }

    #[test]
    fn accepts_https_and_ssh_to_public_hosts() {
        let r = public();
        let pinned = check_url("https://git.example.com/owner/repo.git", false, &r).unwrap();
        assert_eq!(pinned.scheme, RemoteScheme::Https);
        assert_eq!(pinned.port, 443);
        assert_eq!(
            pinned.pinned_ip,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
        // Pinning arguments are produced.
        let args = pinned.config_args();
        assert!(
            args.iter()
                .any(|a| a == "http.curloptResolve=git.example.com:443:93.184.216.34"),
            "{args:?}"
        );
        let ssh = check_url("ssh://git@git.example.com/owner/repo.git", false, &r).unwrap();
        assert_eq!(ssh.scheme, RemoteScheme::Ssh);
        assert_eq!(ssh.port, 22);
        let scp = check_url("git@git.example.com:owner/repo.git", false, &r).unwrap();
        assert_eq!(scp.scheme, RemoteScheme::Ssh);
        assert_eq!(scp.host, "git.example.com");
        // Passwords are stripped from the URL git receives.
        let with_pw = check_url("https://git:tok@git.example.com/x.git", false, &r).unwrap();
        assert!(!with_pw.url.contains("tok"), "{}", with_pw.url);
    }

    #[test]
    fn test_flag_admits_file_urls_and_loopback() {
        let r = FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        };
        let file = check_url("file:///srv/repos/x.git", true, &r).unwrap();
        assert_eq!(file.scheme, RemoteScheme::File);
        let local = check_url("/srv/repos/x.git", true, &r).unwrap();
        assert_eq!(local.scheme, RemoteScheme::File);
        // Loopback under the flag: https, ssh, and http all pass.
        assert!(check_url("https://127.0.0.1/x.git", true, &r).is_ok());
        assert!(check_url("http://127.0.0.1:8080/x.git", true, &r).is_ok());
        assert!(check_url("ssh://git@127.0.0.1/x.git", true, &r).is_ok());
        // Private addresses stay refused even under the flag.
        let priv_r = private();
        assert!(check_url("https://192.168.1.1/x.git", true, &priv_r).is_err());
        // And http to a non-loopback host stays refused under the flag.
        assert!(check_url("http://git.example.com/x.git", true, &public()).is_err());
    }
}
