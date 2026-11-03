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

/// The whole application: `/healthz`, `/api/v1`, web pages, and git smart HTTP.
pub async fn build(config: &Config, hook_exe: PathBuf) -> anyhow::Result<App> {
    let core = open_core(config, hook_exe).await?;
    let web = starforged_web::router(
        core.clone(),
        starforged_web::WebSettings {
            base_url: config.server.base_url.clone(),
            secure_cookies: config.secure_cookies(),
        },
    );
    let api = starforged_api::router(core.clone(), config.server.base_url.clone());
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api/v1", api)
        .merge(web);
    Ok(App { router, core })
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
    let listener = TcpListener::bind(&config.server.http_addr)
        .await
        .with_context(|| format!("binding {}", config.server.http_addr))?;
    tracing::info!(
        addr = %config.server.http_addr,
        base_url = %config.server.base_url,
        git = %format!("{major}.{minor}"),
        "starforged listening"
    );
    serve_on(listener, app.router, shutdown_signal()).await?;
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
