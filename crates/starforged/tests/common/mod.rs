//! Shared integration-test harness: an in-process server on a random port, plus git helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Output;

use starforged::config::{
    Config, DatabaseConfig, MailConfig, RegistrationConfig, SecurityConfig, ServerConfig,
    SessionsConfig, StorageConfig, WebhooksConfig,
};
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
    pub async fn start_with(configure: impl FnOnce(&mut Config)) -> TestServer {
        let db = starforged_db::testing::TestDb::new().await;
        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let mut config = Config {
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
            mail: MailConfig::default(),
            registration: RegistrationConfig::default(),
            sessions: SessionsConfig::default(),
            webhooks: WebhooksConfig::default(),
        };
        configure(&mut config);
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

    pub async fn start() -> TestServer {
        TestServer::start_with(|_| {}).await
    }

    /// Starts a server whose email goes to [`TestServer::mail_dir`] as `.eml` files.
    pub async fn start_with_mail(configure: impl FnOnce(&mut Config)) -> TestServer {
        TestServer::start_with(|config| {
            config.mail.url = format!("file://{}", config.storage.data_dir.join("mail").display());
            config.mail.from = "Starforge <forge@example.test>".into();
            configure(config);
        })
        .await
    }

    pub fn mail_dir(&self) -> PathBuf {
        self.data.path().join("mail")
    }

    /// Runs queued jobs (delivering email), then returns every message so far, oldest first.
    pub async fn inbox(&self) -> Vec<String> {
        self.core.run_due_jobs().await.unwrap();
        starforged_core::mail::testing::read_mailbox(&self.mail_dir())
    }

    /// The newest message to `to`, after running queued jobs.
    pub async fn last_email_to(&self, to: &str) -> String {
        self.inbox()
            .await
            .into_iter()
            .rev()
            .find(|m| m.contains(&format!("To: {to}")))
            .unwrap_or_else(|| panic!("no email to {to}"))
    }

    /// The link in `message` whose path starts with `path_prefix`; it must point at this server.
    pub fn link_in(&self, message: &str, path_prefix: &str) -> String {
        let link = starforged_core::mail::testing::find_link(message, path_prefix)
            .unwrap_or_else(|| panic!("no {path_prefix} link in:\n{message}"));
        assert!(
            link.starts_with(&self.base),
            "{link} does not point at {}",
            self.base
        );
        link
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
                    readme: false,
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
    git_with_env(dir, args, &[]).await
}

/// [`git`] with extra environment variables.
pub async fn git_with_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let dir = dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
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
            .envs(env)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

/// [`git_ok`] with the author and committer (and tagger) dates set to `unix_time`.
pub async fn git_dated(dir: &Path, args: &[&str], unix_time: i64) -> String {
    let date = format!("@{unix_time} +0000");
    let out = git_with_env(
        dir,
        args,
        &[
            ("GIT_AUTHOR_DATE", date.as_str()),
            ("GIT_COMMITTER_DATE", date.as_str()),
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
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

    /// Submits the sign-in form from a fresh browser; returns the browser and the response.
    pub async fn try_login(
        &self,
        login: &str,
        password: &str,
    ) -> (reqwest::Client, reqwest::Response) {
        let client = self.browser();
        let page = get_text(&client, &self.url("/login")).await;
        let csrf = extract_input(&page, "_csrf");
        let response = client
            .post(self.url("/login"))
            .form(&[
                ("_csrf", csrf.as_str()),
                ("next", "/"),
                ("login", login),
                ("password", password),
            ])
            .send()
            .await
            .unwrap();
        (client, response)
    }

    /// Signs `handle` in with [`PASSWORD`]; returns the browser and the session's CSRF token.
    pub async fn login(&self, handle: &str) -> (reqwest::Client, String) {
        let (client, response) = self.try_login(handle, PASSWORD).await;
        assert_eq!(response.status(), 303, "signing in as {handle} failed");
        let dashboard = get_text(&client, &self.url("/")).await;
        (client, extract_input(&dashboard, "_csrf"))
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
