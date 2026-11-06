//! `starforged serve`: builds the HTTP application and runs it.

use std::collections::HashMap as GaugesMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
/// `starforged_ssh_connections` gauge lives in core (the SSH crate bumps it).

#[derive(Clone)]
struct OpsState {
    core: Core,
    metrics_token: Option<String>,
    ssh_enabled: bool,
}

/// The whole application: `/healthz`, `/readyz`, `/metrics`, `/api/v1`,
/// web pages, and git smart HTTP.
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
    let ops = Router::new()
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(OpsState {
            core: core.clone(),
            metrics_token: config
                .metrics
                .token
                .clone()
                .filter(|t| !t.trim().is_empty()),
            ssh_enabled: config.ssh.enabled,
        });
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api/v1", api)
        .merge(web)
        .merge(ops)
        .layer(axum::middleware::from_fn_with_state(
            core.clone(),
            record_metrics,
        ));
    Ok(App { router, core })
}

/// Request class for the metrics labels (D6): only three bounded values.
fn request_class(path: &str) -> &'static str {
    if path.starts_with("/api/v1") {
        "api"
    } else if path.ends_with("/info/refs")
        || path.ends_with("/git-upload-pack")
        || path.ends_with("/git-receive-pack")
    {
        "git"
    } else {
        "web"
    }
}

/// Counts every request (except the ops endpoints themselves) and
/// observes its duration, labelled only by class and status bucket.
async fn record_metrics(State(core): State<Core>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if matches!(path.as_str(), "/healthz" | "/readyz" | "/metrics") {
        return next.run(request).await;
    }
    let class = request_class(&path);
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    core.metrics().inc_http(class, status);
    core.metrics()
        .observe_http(class, start.elapsed().as_secs_f64());
    response
}

async fn readyz(State(state): State<OpsState>) -> Response {
    let core = &state.core;
    let mut failing: Vec<&str> = Vec::new();
    let db_ok = tokio::time::timeout(Duration::from_secs(2), core.db().ping())
        .await
        .is_ok_and(|result| result.is_ok());
    if !db_ok {
        failing.push("database");
    }
    let migration_ok = match core.db().latest_migration().await {
        Ok(Some(latest)) => latest >= core.db().known_migration(),
        Ok(None) => core.db().known_migration() == 0,
        Err(_) => false,
    };
    if !migration_ok {
        failing.push("migration");
    }
    let now = starforged_db::now();
    if now - core.worker_heartbeat() > 30 {
        failing.push("jobs");
    }
    if core.search_index().stats().is_err() {
        failing.push("search");
    }
    if state.ssh_enabled
        && starforged_core::metrics::SSH_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed) < 0
    {
        failing.push("ssh");
    }
    let data_dir_ok = core
        .config()
        .repos_dir
        .parent()
        .is_some_and(|dir| dir.is_dir());
    if !data_dir_ok {
        failing.push("data_dir");
    }
    if failing.is_empty() {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({"status": "ok"})),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"status": "unavailable", "failing": failing})),
        )
            .into_response()
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// One rendered gauge: metric name, labels, value.
type Gauge = (String, Vec<(String, String)>, i64);

async fn metrics(State(state): State<OpsState>, headers: HeaderMap) -> Response {
    let Some(expected) = state.metrics_token.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if bearer_token(&headers) != Some(expected.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut gauges: Vec<Gauge> = Vec::new();
    let mut pending: GaugesMap<String, i64> = GaugesMap::new();
    if let Ok(rows) = starforged_db::jobs::counts_by_kind_state(state.core.db()).await {
        for (kind, state_name, count) in rows {
            if state_name == "queued" {
                *pending.entry(kind).or_insert(0) += count;
            }
        }
    }
    for (kind, count) in &pending {
        gauges.push((
            "starforged_jobs_pending".to_owned(),
            vec![("kind".to_owned(), kind.clone())],
            *count,
        ));
    }
    if let Ok(stats) = state.core.search_index().stats() {
        gauges.push((
            "starforged_index_documents".to_owned(),
            vec![("kind".to_owned(), "trails".to_owned())],
            stats.trails as i64,
        ));
        gauges.push((
            "starforged_index_documents".to_owned(),
            vec![("kind".to_owned(), "events".to_owned())],
            stats.events as i64,
        ));
    }
    gauges.push((
        "starforged_ssh_connections".to_owned(),
        Vec::new(),
        starforged_core::metrics::SSH_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed),
    ));
    let body = state.core.metrics().render(&gauges);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
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
