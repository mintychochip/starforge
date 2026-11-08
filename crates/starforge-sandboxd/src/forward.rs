//! TCP→Unix forwarder that runs *inside* a sandbox (`--network none`).
//!
//! The sandbox cannot reach the host TCP egress proxy, so the daemon mounts
//! the per-sandbox egress directory at `/run/starforge/egress` and this
//! binary — copied into the container by the daemon — listens on
//! `127.0.0.1:3128` for sandbox HTTP clients while also creating and
//! listening on the Unix socket `/run/starforge/egress/shim.sock` itself.
//! The daemon (host side) connects to that socket: connecting from the
//! container out to a host-owned socket is denied under SELinux, whereas a
//! host process connecting to a container-created socket in a `:Z` mount
//! works. The daemon keeps a pool of idle host connections queued here;
//! for each accepted TCP client this forwarder takes one queued host
//! connection (waiting up to [`DEFAULT_HOST_WAIT`] for one; the client is
//! closed if none arrives) and copies bytes both ways until either side
//! closes. Sandbox HTTP clients use `HTTP_PROXY=http://127.0.0.1:3128` and
//! never know the proxy is one hop away.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

/// How long a TCP client waits for a queued host (daemon) connection before
/// the forwarder closes it. Tests shorten this via [`serve_forward`].
pub const DEFAULT_HOST_WAIT: Duration = Duration::from_secs(10);

/// Bind the Unix listener at `path` (removing a stale file first, mode
/// `0666` after bind so the host-side daemon — a different mount
/// namespace — can connect). The socket is created by this forwarder,
/// never by the host.
fn bind_unix_listener(path: &Path) -> io::Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    Ok(listener)
}

/// Bind `listen` (TCP) and `unix_path` (Unix, created by this forwarder),
/// pairing each TCP client with one queued host connection.
/// Runs until the TCP listener fails; per-connection copy errors are dropped.
pub async fn run_forward(listen: SocketAddr, unix_path: PathBuf) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let unix_listener = bind_unix_listener(&unix_path)?;
    serve_forward(listener, unix_listener, DEFAULT_HOST_WAIT).await
}

/// Serve already-bound TCP and Unix listeners. Accepted Unix connections
/// (from the host) are queued; each TCP client takes one, waiting up to
/// `host_wait`. Split out so callers/tests bind first (learning the
/// ephemeral port / socket existence) and serve afterwards — no
/// sleep-based synchronization.
pub async fn serve_forward(
    listener: tokio::net::TcpListener,
    unix_listener: tokio::net::UnixListener,
    host_wait: Duration,
) -> io::Result<()> {
    let (tx, rx) = mpsc::channel::<tokio::net::UnixStream>(32);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = unix_listener.accept().await else {
                break;
            };
            if tx.send(stream).await.is_err() {
                break;
            }
        }
    });
    let rx = Arc::new(Mutex::new(rx));
    loop {
        let (tcp, _) = listener.accept().await?;
        let rx = Arc::clone(&rx);
        tokio::spawn(async move {
            let host = {
                let mut guard = rx.lock().await;
                tokio::time::timeout(host_wait, guard.recv())
                    .await
                    .ok()
                    .flatten()
            };
            let Some(host) = host else {
                // No queued host connection arrived: close the client
                // (dropping `tcp`) rather than leaving it hanging.
                return;
            };
            pump(tcp, host).await;
        });
    }
}

/// Copy bytes in both directions between a TCP stream and a Unix stream.
async fn pump<T, U>(tcp: T, unix: U)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    let (mut unix_read, mut unix_write) = tokio::io::split(unix);
    let tcp_to_unix = async {
        let _ = tokio::io::copy(&mut tcp_read, &mut unix_write).await;
        let _ = unix_write.shutdown().await;
    };
    let unix_to_tcp = async {
        let _ = tokio::io::copy(&mut unix_read, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
    };
    tokio::join!(tcp_to_unix, unix_to_tcp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "starforge-forward-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn forward_pairs_tcp_client_with_host_connection() {
        let dir = test_dir("pair");
        let sock = dir.join("shim.sock");
        // Bind both listeners first (learning the ephemeral port and
        // creating the socket), then serve — the test connects only once
        // both listeners exist.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen = listener.local_addr().unwrap();
        let unix_listener = bind_unix_listener(&sock).unwrap();
        let forwarder = tokio::spawn(serve_forward(
            listener,
            unix_listener,
            Duration::from_secs(2),
        ));
        // Host-initiated Unix connection (the daemon pool standing in).
        let mut host = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
        // TCP -> host.
        const MESSAGE: &[u8] = b"hello through the forwarder";
        client.write_all(MESSAGE).await.unwrap();
        let mut got = vec![0u8; MESSAGE.len()];
        tokio::time::timeout(Duration::from_secs(5), host.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_slice(), MESSAGE);
        // Host -> TCP.
        const REPLY: &[u8] = b"reply back to the sandbox";
        host.write_all(REPLY).await.unwrap();
        let mut back = vec![0u8; REPLY.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back.as_slice(), REPLY);
        forwarder.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn forward_closes_tcp_client_with_no_host_connection() {
        let dir = test_dir("nohost");
        let sock = dir.join("shim.sock");
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let listen = listener.local_addr().unwrap();
        let unix_listener = bind_unix_listener(&sock).unwrap();
        let wait = Duration::from_millis(100);
        let forwarder = tokio::spawn(serve_forward(listener, unix_listener, wait));
        let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
        let start = Instant::now();
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut [0u8; 16]))
            .await
            .expect("client should be closed after the wait")
            .unwrap();
        assert_eq!(n, 0, "client must see EOF once the wait expires");
        assert!(
            start.elapsed() >= wait,
            "client closed too early: {:?}",
            start.elapsed()
        );
        forwarder.abort();
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
