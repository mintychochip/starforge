//! `starforged serve`: builds the HTTP application and runs it.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::Router;
use axum::routing::get;
use starforged_core::Core;
use tokio::net::TcpListener;

use crate::admin::open_core;
use crate::config::Config;

pub struct App {
    pub router: Router,
    pub core: Core,
}

/// Background job workers per process (forge-basics design §8.2).
const JOB_WORKERS: usize = 2;

/// The whole application: `/healthz`, `/api/v1`, web pages, and git smart HTTP.
pub async fn build(config: &Config, hook_exe: PathBuf) -> anyhow::Result<App> {
    config.validate()?;
    let core = open_core(config, hook_exe).await?;
    let web = starforged_web::router(
        core.clone(),
        starforged_web::WebSettings {
            base_url: config.server.base_url.clone(),
            secure_cookies: config.secure_cookies(),
            ssh_clone_base: config.ssh_clone_base(),
        },
    );
    let api = starforged_api::router(core.clone(), config.server.base_url.clone());
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api/v1", api)
        .merge(web);
    Ok(App { router, core })
}
/// Startup search recovery (plan D5): when opening the index recreated it
/// (missing or corrupt), enqueue a full rebuild. The server never refuses
/// to start because of the index, so a queue failure is only logged.
pub async fn recover_search_index(core: &Core) -> anyhow::Result<()> {
    if !core.search_index_was_recreated() {
        return Ok(());
    }
    if let Err(err) = core
        .enqueue(&starforged_core::jobs::Job::RebuildIndex)
        .await
    {
        tracing::warn!(error = %err, "enqueueing startup search rebuild");
    }
    Ok(())
}

/// Serves `router` with `ConnectInfo<SocketAddr>` available to handlers until `shutdown` resolves.
pub async fn serve_on(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let (major, minor) = starforged_git::command::check_version().await?;
    let app = build(&config, std::env::current_exe()?).await?;
    recover_search_index(&app.core).await?;
    starforged_core::jobs::start_workers(&app.core, JOB_WORKERS).await?;
    let listener = TcpListener::bind(&config.server.http_addr)
        .await
        .with_context(|| format!("binding {}", config.server.http_addr))?;
    tracing::info!(
        addr = %config.server.http_addr,
        base_url = %config.server.base_url,
        git = %format!("{major}.{minor}"),
        "starforged listening"
    );
    let ssh = if config.ssh.enabled {
        let cfg = starforged_ssh::Config {
            listen: config.ssh.listen.clone(),
            host_key_path: config.ssh_host_key_path(),
            idle_timeout_secs: config.ssh.idle_timeout_secs,
            max_connection_secs: config.ssh.max_connection_secs,
            max_connections_per_user: config.ssh.max_connections_per_user,
        };
        let handle = starforged_ssh::serve(app.core.clone(), cfg, shutdown_signal()).await?;
        tracing::info!(addr = %handle.addr(), "starforged ssh listening");
        Some(handle)
    } else {
        None
    };
    match ssh {
        Some(ssh) => {
            tokio::select! {
                result = serve_on(listener, app.router, shutdown_signal()) => result?,
                result = ssh.wait() => result?,
            }
        }
        None => serve_on(listener, app.router, shutdown_signal()).await?,
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
