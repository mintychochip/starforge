//! The russh server: public-key auth against [`Core::identity_for_key`],
//! authorization through [`Core::git_access`], and `git` spawned per exec
//! with channel stdio. Refusals print a one-line `starforge: …` stderr and
//! exit 1 (D5).

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use russh::server::{Auth, Handler, Msg, Server, Session, VerifiedPublicKey};
use russh::{ChannelId, ChannelOpenFailure, Disconnect};
use starforged_core::gitaccess::{GitActor, GitService};
use starforged_core::jobs::Job;
use starforged_core::sshkeys::KeyIdentity;
use starforged_core::{Core, CoreError};
use starforged_git::http::rpc_env;
use starforged_git::pushsidecar;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::Config;
use crate::command::{GitExec, parse_exec, split_repo_path};

#[derive(Debug)]
pub(crate) struct Shared {
    core: Core,
    max_connection_secs: u64,
    max_connections_per_user: usize,
    counters: Mutex<HashMap<String, usize>>,
}

impl Shared {
    pub(crate) fn new(core: Core, cfg: &Config) -> Shared {
        Shared {
            core,
            max_connection_secs: cfg.max_connection_secs,
            max_connections_per_user: cfg.max_connections_per_user,
            counters: Mutex::new(HashMap::new()),
        }
    }

    fn slot_key(identity: &KeyIdentity) -> String {
        match identity {
            KeyIdentity::User(user) => format!("user:{}", user.id),
            KeyIdentity::Deploy { key_id, .. } => format!("deploy:{key_id}"),
        }
    }

    /// Takes one concurrent-connection slot; `false` when at the limit.
    fn acquire(&self, key: &str) -> bool {
        let mut counters = self.counters.lock().unwrap();
        let count = counters.entry(key.to_owned()).or_insert(0);
        if *count >= self.max_connections_per_user {
            return false;
        }
        *count += 1;
        true
    }

    fn release(&self, key: &str) {
        let mut counters = self.counters.lock().unwrap();
        if let Some(count) = counters.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counters.remove(key);
            }
        }
    }
}

pub(crate) struct ForgeServer {
    shared: Arc<Shared>,
}

impl ForgeServer {
    pub(crate) fn new(shared: Shared) -> ForgeServer {
        ForgeServer {
            shared: Arc::new(shared),
        }
    }
}

impl Server for ForgeServer {
    type Handler = Connection;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Connection {
        starforged_core::metrics::SSH_CONNECTIONS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Connection {
            shared: self.shared.clone(),
            identity: None,
            counter_key: None,
            git_protocol: None,
            channels: HashMap::new(),
            total_timer: None,
        }
    }
}

pub(crate) struct Connection {
    shared: Arc<Shared>,
    identity: Option<KeyIdentity>,
    counter_key: Option<String>,
    git_protocol: Option<String>,
    channels: HashMap<ChannelId, mpsc::Sender<Bytes>>,
    total_timer: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        starforged_core::metrics::SSH_CONNECTIONS
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(timer) = self.total_timer.take() {
            timer.abort();
        }
        if let Some(key) = self.counter_key.take() {
            self.shared.release(&key);
        }
    }
}

/// Sends one-line `starforge: …` stderr, then exit 1 and close.
async fn refuse(session: &mut Session, channel: ChannelId, message: &str) {
    let line = format!("starforge: {message}\n");
    let _ = session.extended_data(channel, 1, line.into_bytes());
    let _ = session.exit_status_request(channel, 1);
    let _ = session.close(channel);
}

fn fingerprint(key: &VerifiedPublicKey<'_>) -> Option<String> {
    let algorithm = key.public_key.algorithm().as_str().to_owned();
    if algorithm.as_str().contains("-cert-") {
        return None;
    }
    let blob = key.public_key.to_bytes().ok()?;
    Some(starforged_core::sshkeys::fingerprint(&blob))
}

impl Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user != "git" {
            return Ok(Auth::reject());
        }
        let Some(fp) = fingerprint(&key) else {
            return Ok(Auth::reject());
        };
        let identity = match self.shared.core.identity_for_key(&fp).await {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                tracing::debug!(fingerprint = %fp, "unknown public key");
                return Ok(Auth::reject());
            }
            Err(err) => {
                tracing::warn!(error = %err, "identity lookup failed");
                return Ok(Auth::reject());
            }
        };
        let counter_key = Shared::slot_key(&identity);
        if !self.shared.acquire(&counter_key) {
            tracing::info!(%counter_key, "connection limit reached");
            return Ok(Auth::reject());
        }
        tracing::info!(fingerprint = %fp, "public key accepted");
        self.counter_key = Some(counter_key);
        self.identity = Some(identity);
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let handle = session.handle();
        let total = std::time::Duration::from_secs(self.shared.max_connection_secs);
        self.total_timer = Some(tokio::spawn(async move {
            tokio::time::sleep(total).await;
            let _ = handle
                .disconnect(
                    Disconnect::ByApplication,
                    "Connection exceeded the maximum allowed duration".to_owned(),
                    String::new(),
                )
                .await;
        }));
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let _ = channel.id();
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<Msg>,
        _host: &str,
        _port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<Msg>,
        _host: &str,
        _port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: russh::Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL" {
            self.git_protocol = Some(variable_value.to_owned());
            session.channel_success(channel)?;
        } else {
            // Ignore unknown env without closing the channel.
            session.channel_success(channel)?;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        refuse(session, channel, "only git commands are supported").await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        refuse(session, channel, "subsystems are not supported").await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let text = String::from_utf8_lossy(data);
        let Some(exec) = parse_exec(&text).ok() else {
            refuse(session, channel, "only git commands are supported").await;
            return Ok(());
        };
        let Ok((owner, name)) = split_repo_path(&exec.path) else {
            refuse(session, channel, "repository not found").await;
            return Ok(());
        };
        let Some(identity) = self.identity.clone() else {
            refuse(session, channel, "authentication required").await;
            return Ok(());
        };
        let service = match exec.kind {
            crate::command::PackKind::UploadPack => GitService::UploadPack,
            crate::command::PackKind::ReceivePack => GitService::ReceivePack,
            crate::command::PackKind::UploadArchive => GitService::UploadArchive,
        };
        let actor = match &identity {
            KeyIdentity::User(user) => GitActor::User {
                user: user.clone(),
                scope_read: true,
                scope_write: true,
            },
            KeyIdentity::Deploy {
                key_id,
                repo_id,
                read_write,
            } => GitActor::Deploy {
                key_id: *key_id,
                repo_id: *repo_id,
                read_write: *read_write,
            },
        };
        let grant = match self
            .shared
            .core
            .git_access(&actor, owner, name, service)
            .await
        {
            Ok(grant) => grant,
            Err(CoreError::NotFound) => {
                refuse(session, channel, "repository not found").await;
                return Ok(());
            }
            Err(CoreError::Forbidden) => {
                refuse(session, channel, "permission denied").await;
                return Ok(());
            }
            Err(CoreError::Unauthenticated) => {
                refuse(session, channel, "permission denied").await;
                return Ok(());
            }
            Err(err) => {
                tracing::warn!(error = %err, "git access failed");
                refuse(session, channel, "internal error").await;
                return Ok(());
            }
        };
        if service == GitService::ReceivePack && grant.access.repo.archived_at.is_some() {
            refuse(session, channel, "repository is archived").await;
            return Ok(());
        }
        let handle = session.handle();
        let git_protocol = self.git_protocol.clone();
        let (stdin_tx, stdin_rx) = mpsc::channel::<Bytes>(64);
        self.channels.insert(channel, stdin_tx);
        let shared = self.shared.clone();
        tokio::spawn(async move {
            spawn_pack_async(shared, handle, channel, exec, grant, git_protocol, stdin_rx).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.channels.get(&channel) {
            let _ = sender.send(Bytes::copy_from_slice(data)).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

async fn spawn_pack_async(
    shared: Arc<Shared>,
    handle: russh::server::Handle,
    channel: ChannelId,
    exec: GitExec,
    grant: starforged_core::gitaccess::GitAccess,
    git_protocol: Option<String>,
    mut stdin_rx: mpsc::Receiver<Bytes>,
) {
    let core = shared.core.clone();
    let repo_path = core.repo_path(grant.access.repo.id);
    let is_receive = exec.kind == crate::command::PackKind::ReceivePack;
    match exec.kind {
        crate::command::PackKind::UploadPack => core.metrics().inc_git_rpc("upload-pack", "ssh"),
        crate::command::PackKind::ReceivePack => core.metrics().inc_git_rpc("receive-pack", "ssh"),
        crate::command::PackKind::UploadArchive => {}
    }
    // receive-pack writes inside the repository: hold the shared lock
    // until the child (and the post-push scan) finishes (plan M5b O1).
    let _repo_lock = if is_receive {
        match core.repo_lock_shared(grant.access.repo.id).await {
            Ok(guard) => Some(guard),
            Err(err) => {
                tracing::warn!(error = %err, "repository lock failed");
                let _ = handle
                    .extended_data(channel, 1, b"starforge: internal error\n".to_vec())
                    .await;
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                return;
            }
        }
    } else {
        None
    };
    let before = if is_receive {
        core.snapshot_refs(&repo_path).await
    } else {
        None
    };
    let mut env: Vec<(&str, String)> = if exec.kind == crate::command::PackKind::UploadArchive {
        Vec::new()
    } else {
        rpc_env(exec.kind.http_service())
    };
    let mut scan_nonce: Option<String> = None;
    if is_receive {
        let nonce = pushsidecar::new_nonce();
        match core
            .git_rpc_env(&grant.access, grant.user.as_ref(), grant.write_path, &nonce)
            .await
        {
            Ok(extra) => env.extend(extra),
            Err(err) => {
                tracing::warn!(error = %err, "git env failed");
                let _ = handle
                    .extended_data(channel, 1, b"starforge: internal error\n".to_vec())
                    .await;
                let _ = handle.exit_status_request(channel, 1).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
                return;
            }
        }
        scan_nonce = Some(nonce);
    }
    let mut command = starforged_git::command::git();
    command
        .arg(exec.kind.subcommand())
        .arg(&repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(protocol) = &git_protocol {
        command.env("GIT_PROTOCOL", protocol);
    }
    for (key, value) in &env {
        command.env(key, value);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(error = %err, "spawning git failed");
            let _ = handle
                .extended_data(channel, 1, b"starforge: internal error\n".to_vec())
                .await;
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
            return;
        }
    };

    let mut stdin = child.stdin.take();
    let stdin_task = tokio::spawn(async move {
        while let Some(chunk) = stdin_rx.recv().await {
            if let Some(stdin) = stdin.as_mut() {
                if stdin.write_all(&chunk).await.is_err() {
                    break;
                }
            } else {
                break;
            }
        }
        drop(stdin);
    });

    let stdout = child.stdout.take();
    let stdout_handle = handle.clone();
    let stdout_task = tokio::spawn(async move {
        pipe(stdout, &stdout_handle, channel, false).await;
    });

    let stderr = child.stderr.take();
    let stderr_handle = handle.clone();
    let stderr_task = tokio::spawn(async move {
        pipe(stderr, &stderr_handle, channel, true).await;
    });

    let repo_id = grant.access.repo.id;
    let pusher = grant.user.clone();
    let repo = repo_path.clone();
    let status = child.wait().await;
    stdin_task.abort();
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    let failed = !matches!(&status, Ok(s) if s.success());
    if failed {
        if let Ok(status) = &status {
            tracing::warn!(?status, "ssh git process failed");
        }
    } else if is_receive {
        if let Err(err) = core.enqueue(&Job::GitMaintenance { repo_id }).await {
            tracing::warn!(error = %err, repo_id, "queueing git maintenance failed");
        }
        core.scan_push_changes(repo_id, repo, pusher, scan_nonce, before)
            .await;
    }
    let code = status.ok().and_then(|s| s.code()).unwrap_or(1);
    let _ = handle.exit_status_request(channel, code as u32).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

async fn pipe(
    reader: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
    handle: &russh::server::Handle,
    channel: ChannelId,
    stderr: bool,
) {
    let Some(mut reader) = reader else { return };
    let mut buffer = [0u8; 8192];
    loop {
        match tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let bytes = Bytes::copy_from_slice(&buffer[..n]);
                let sent = if stderr {
                    handle.extended_data(channel, 1, bytes).await
                } else {
                    handle.data(channel, bytes).await
                };
                if sent.is_err() {
                    break;
                }
            }
        }
    }
}
