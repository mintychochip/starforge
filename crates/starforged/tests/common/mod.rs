//! Shared integration-test harness: an in-process server on a random port, plus git helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Output;

use starforged::config::{Config, DatabaseConfig, SecurityConfig, ServerConfig, StorageConfig};
use starforged_core::Core;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::permission::Visibility;
use starforged_core::repos::{CreateRepo, Repo};
use starforged_core::tokens::Scope;

pub const PASSWORD: &str = "correct horse battery";

pub struct TestServer {
    pub base: String,
    pub core: Core,
    pub data: tempfile::TempDir,
    _db: starforged_db::testing::TestDb,
}

impl TestServer {
    pub async fn start() -> TestServer {
        let db = starforged_db::testing::TestDb::new().await;
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let config = Config {
            server: ServerConfig {
                http_addr: addr.to_string(),
                base_url: base.clone(),
            },
            database: DatabaseConfig {
                url: db.url.clone(),
                auto_migrate: true,
            },
            storage: StorageConfig {
                data_dir: data.path().to_path_buf(),
            },
            security: SecurityConfig {
                secret_key: "0".repeat(64),
            },
        };
        let app =
            starforged::serve::build(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
                .await
                .unwrap();
        tokio::spawn(starforged::serve::serve_on(
            listener,
            app.router,
            std::future::pending(),
        ));
        TestServer {
            base,
            core: app.core,
            data,
            _db: db,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A user whose password is [`PASSWORD`].
    pub async fn user(&self, handle: &str) -> User {
        self.core
            .create_user(CreateUser {
                handle: handle.into(),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    pub async fn token(&self, user: &User, scopes: &[Scope]) -> String {
        self.core
            .create_token(user, "test", scopes, 1)
            .await
            .unwrap()
            .secret
    }

    pub async fn repo(&self, owner: &User, name: &str, visibility: Visibility) -> Repo {
        self.core
            .create_repo(
                owner,
                CreateRepo {
                    name: name.into(),
                    description: String::new(),
                    visibility,
                },
            )
            .await
            .unwrap()
    }

    /// `http://host/owner/repo.git`, with `token` as the Basic-auth password when given.
    pub fn git_url(&self, owner: &str, repo: &str, token: Option<&str>) -> String {
        let host = self.base.trim_start_matches("http://");
        match token {
            Some(token) => format!("http://git:{token}@{host}/{owner}/{repo}.git"),
            None => format!("http://{host}/{owner}/{repo}.git"),
        }
    }
}

/// Runs `git` in `dir` on a blocking thread, isolated from the developer's configuration.
/// Defaults to protocol v2; pass `-c protocol.version=0` to override.
pub async fn git(dir: &Path, args: &[&str]) -> Output {
    let dir = dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new("git")
            .args([
                "-c",
                "credential.helper=",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
            ])
            .args(["-c", "init.defaultBranch=main", "-c", "protocol.version=2"])
            .args(&args)
            .current_dir(&dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

/// [`git`] that must succeed; returns stdout.
pub async fn git_ok(dir: &Path, args: &[&str]) -> String {
    let out = git(dir, args).await;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Creates the working copy `dir/name` with one commit, "initial commit", containing `files`.
pub async fn work_repo(dir: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
    git_ok(dir, &["init", "-q", name]).await;
    let work = dir.join(name);
    let files: Vec<(&str, &[u8])> = files.iter().map(|(p, c)| (*p, c.as_bytes())).collect();
    commit_files(&work, &files, "initial commit").await;
    work
}

/// Writes `files` (paths relative to `work`) and commits them.
pub async fn commit_files(work: &Path, files: &[(&str, &[u8])], message: &str) {
    for (path, content) in files {
        let full = work.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    git_ok(work, &["add", "-A"]).await;
    git_ok(work, &["commit", "-q", "-m", message]).await;
}

/// Deterministic, incompressible bytes (xorshift).
pub fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

impl TestServer {
    /// A cookie-keeping client that does not follow redirects.
    pub fn browser(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    /// Signs `handle` in through the login form; returns the client and the session's CSRF token.
    pub async fn login(&self, handle: &str) -> (reqwest::Client, String) {
        let client = self.browser();
        let page = client
            .get(self.url("/login"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let csrf = extract_input(&page, "_csrf");
        let response = client
            .post(self.url("/login"))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("next", "/"),
                ("login", handle),
                ("password", PASSWORD),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303, "signing in as {handle} failed");
        let dashboard = client
            .get(self.url("/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let session_csrf = extract_input(&dashboard, "_csrf");
        (client, session_csrf)
    }
}

/// The value of the first `<input … name="{name}" value="…">` in `html`.
pub fn extract_input(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no input named {name} in:\n{html}"))
        + marker.len();
    html[start..].split('"').next().unwrap().to_owned()
}

/// The text between the first `start` and the next `end`.
pub fn between(html: &str, start: &str, end: &str) -> String {
    let from = html
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} not found in:\n{html}"))
        + start.len();
    let len = html[from..]
        .find(end)
        .unwrap_or_else(|| panic!("{end:?} not found after {start:?}"));
    html[from..from + len].to_owned()
}

/// GET that must succeed; returns the body.
pub async fn get_text(client: &reqwest::Client, url: &str) -> String {
    let response = client.get(url).send().await.unwrap();
    assert!(
        response.status().is_success(),
        "GET {url} returned {}",
        response.status()
    );
    response.text().await.unwrap()
}
