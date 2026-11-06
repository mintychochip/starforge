//! Git over SSH (spec §8.1, M3c): an embedded russh server that authenticates
//! public keys through [`starforged_core::Core`], authorizes through the same
//! [`Core::git_access`](starforged_core::gitaccess::Core) path as smart HTTP,
//! and spawns `git upload-pack` / `git receive-pack` / `git upload-archive`
//! with pooled channel stdio. Only `git` commands are served: no shell, no
//! pty, no subsystems, no forwarding.

mod command;
mod server;

pub use command::{GitExec, PackKind, ParseError, parse_exec, split_repo_path};

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::{LineEnding, PrivateKey};
use russh::server::Server as _;
use starforged_core::Core;
use tokio::net::TcpListener;

use server::ForgeServer;

/// Server settings (plan D5).
pub struct Config {
    /// Socket address to bind, e.g. `0.0.0.0:2222`.
    pub listen: String,
    /// Host key file; generated with mode `0600` when missing.
    pub host_key_path: PathBuf,
    /// Idle timeout: connections with no traffic this long are closed.
    pub idle_timeout_secs: u64,
    /// Total timeout: every connection is closed this long after auth.
    pub max_connection_secs: u64,
    /// Concurrent connections per user (per deploy key).
    pub max_connections_per_user: usize,
}

impl Config {
    /// The `ssh.*` limits for in-process tests.
    pub fn test_limits(listen: String, host_key_path: PathBuf) -> Config {
        Config {
            listen,
            host_key_path,
            idle_timeout_secs: 1,
            max_connection_secs: 3,
            max_connections_per_user: 1,
        }
    }
}

/// Handle to a running SSH listener.
pub struct SshHandle {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl SshHandle {
    /// The bound address (an ephemeral port when `Config::listen` says `:0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Drives the listener to completion.
    pub async fn wait(self) -> std::io::Result<()> {
        match self.task.await {
            Ok(result) => result,
            Err(err) => Err(std::io::Error::other(err)),
        }
    }
}

/// Starts the SSH listener; returns once bound, with the listener running.
/// Stops up to `max_connection_secs` connections via [`Config`], and on `shutdown`.
pub async fn serve(
    core: Core,
    cfg: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<SshHandle> {
    let listener = TcpListener::bind(&cfg.listen).await?;
    serve_on(core, cfg, listener, shutdown).await
}

/// Starts the SSH listener on a pre-bound `listener`.
pub async fn serve_on(
    core: Core,
    cfg: Config,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<SshHandle> {
    let host_key = ensure_host_key(&cfg.host_key_path)?;
    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::PublicKey);
    let russh_cfg = russh::server::Config {
        methods,
        inactivity_timeout: Some(std::time::Duration::from_secs(cfg.idle_timeout_secs)),
        max_auth_attempts: 3,
        keys: vec![host_key],
        ..Default::default()
    };

    let addr = listener.local_addr()?;
    let listening = core.ssh_listening_guard();
    let shared = server::Shared::new(core, &cfg);
    let russh_cfg = std::sync::Arc::new(russh_cfg);
    listening.store(true, std::sync::atomic::Ordering::Relaxed);
    let task = tokio::spawn(async move {
        struct ClearOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for ClearOnDrop {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let _clear = ClearOnDrop(listening);
        let mut forge = ForgeServer::new(shared);
        let running = forge.run_on_socket(russh_cfg, &listener);
        let shutdown_handle = running.handle();
        tokio::pin!(running);
        tokio::pin!(shutdown);
        tokio::select! {
            () = &mut shutdown => {
                shutdown_handle.shutdown("starforge shutting down".into());
                (&mut running).await
            }
            result = &mut running => result,
        }
    });
    Ok(SshHandle { addr, task })
}

/// Loads the host key at `path`, generating an ed25519 one with mode `0600`
/// when missing (`starforged init` and first start both go through this).
pub fn ensure_host_key(path: &Path) -> anyhow::Result<PrivateKey> {
    if let Ok(text) = std::fs::read(path) {
        return PrivateKey::from_openssh(&text)
            .map_err(|err| anyhow::anyhow!("parsing {}: {err}", path.display()));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| anyhow::anyhow!("reading OS randomness: {err}"))?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(KeypairData::from(keypair), "starforged")
        .map_err(|err| anyhow::anyhow!("generating host key: {err}"))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|err| anyhow::anyhow!("encoding host key: {err}"))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| anyhow::anyhow!("creating {}: {err}", parent.display()))?;
    }
    write_private(path, pem.as_bytes())
        .map_err(|err| anyhow::anyhow!("writing {}: {err}", path.display()))?;
    Ok(key)
}

#[cfg(unix)]
fn write_private(path: &Path, text: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text)
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, text)
}
