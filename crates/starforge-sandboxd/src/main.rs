//! `starforge-sandboxd` binary: binds the control socket, rotates the
//! token file, and serves the daemon router with a peer-credential filter.
//!
//! The token rotates on every start (plan M6b, decision 8): clients read the
//! `0600` token file after each daemon boot. No log subscriber is wired (the
//! crate depends on `tracing` macros only); lifecycle events are logged via
//! `tracing` and become visible once a subscriber is added.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use starforge_sandboxd::podman::PodmanRuntime;
use starforge_sandboxd::{DaemonConfig, DaemonState, now_unix, random_hex, sweep_expired};
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};

#[derive(Debug, Parser)]
#[command(
    name = "starforge-sandboxd",
    about = "Local sandbox provider daemon (rootless podman)"
)]
struct Args {
    /// Unix socket to listen on.
    #[arg(long, default_value = "/run/starforge/sandboxd.sock")]
    socket: PathBuf,
    /// Bearer-token file (mode 0600, rotated on every start).
    #[arg(long, default_value = "/run/starforge/sandboxd.token")]
    token_file: PathBuf,
    /// Image allowlist entries (exact image, or image:tag / image@digest).
    /// Required: the daemon refuses to boot without an allowlist.
    #[arg(long = "image", required = true)]
    images: Vec<String>,
    /// Default sandbox TTL in seconds.
    #[arg(long, default_value_t = 3600)]
    default_ttl: u64,
    /// Max concurrent sandboxes (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    max_sandboxes: usize,
    /// podman binary path.
    #[arg(long, default_value = "podman")]
    podman: PathBuf,
}

/// Peer uid of an accepted Unix-stream connection (SO_PEERCRED on Linux).
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials)
        .map(|cred| cred.uid())
        .ok()
}

/// Peer uid on other Unix platforms ( LOCAL_PEERCRED ); absent → reject.
#[cfg(not(target_os = "linux"))]
fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
        getsockopt(_stream, LocalPeerCred)
            .map(|cred| cred.uid())
            .ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
    {
        None
    }
}

fn own_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// `axum::serve::Listener` wrapper that drops connections whose peer uid is
/// not the daemon's own uid (checked at accept time, before the router).
pub struct PeerCheckedListener {
    inner: UnixListener,
    expected_uid: u32,
}

impl PeerCheckedListener {
    fn new(inner: UnixListener, expected_uid: u32) -> Self {
        Self {
            inner,
            expected_uid,
        }
    }
}

impl axum::serve::Listener for PeerCheckedListener {
    type Io = UnixStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    if peer_uid(&stream) == Some(self.expected_uid) {
                        return (stream, addr);
                    }
                    tracing::warn!("sandboxd: dropped connection from non-matching uid");
                }
                Err(err) => {
                    tracing::warn!("sandboxd: accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

async fn run() -> io::Result<()> {
    let args = Args::parse();

    // Fresh token every boot (rotation), written with 0600 via rename so a
    // reader never sees a partial file.
    let token = random_hex(32)?;
    if let Some(parent) = args.token_file.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = args
        .token_file
        .with_extension(format!("tmp.{}", random_hex(4)?));
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
            file.write_all(token.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, token.as_bytes())?;
        }
    }
    std::fs::rename(&tmp, &args.token_file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&args.token_file)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("token file mode is {mode:03o}, require 0600"),
            ));
        }
    }

    // Stale socket files would make bind fail; the socket is recreated per
    // start. Same-uid clients can connect to the 0600 socket.
    let _ = std::fs::remove_file(&args.socket);
    let listener = UnixListener::bind(&args.socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))?;
    }

    let config = DaemonConfig {
        images: args.images,
        default_ttl_s: args.default_ttl,
        max_sandboxes: args.max_sandboxes,
        ..DaemonConfig::default()
    };
    let runtime = Arc::new(PodmanRuntime::new(args.podman));
    let state = DaemonState::new(runtime, token, config);

    // TTL sweeper: kills sandboxes past their deadline.
    let sweep_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let killed = sweep_expired(&sweep_state, now_unix()).await;
            for id in killed {
                tracing::info!("sandboxd: killed expired sandbox {id}");
            }
        }
    });

    tracing::info!(socket = %args.socket.display(), "sandboxd listening");
    let listener = PeerCheckedListener::new(listener, own_uid());
    axum::serve(listener, starforge_sandboxd::router(state))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    run().await
}
