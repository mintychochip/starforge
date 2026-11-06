mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{extract_input, get_text};

const PASSWORD: &str = "a long enough password";

/// Stops the server when the test ends, even when it fails.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_sign_up_verifies_email_through_the_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_starforged");
    let config = tmp.path().join("starforged.toml");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://127.0.0.1:{port}");
    let init = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .args(["init", "--data-dir"])
        .arg(tmp.path().join("data"))
        .args([
            "--base-url",
            &base,
            "--http-addr",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let mail_dir = tmp.path().join("mail");
    // SSH on a free port, not the default 2222, which a real Starforge on
    // this machine may already hold.
    let ssh_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(bin)
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .env("STARFORGE__SSH__LISTEN", format!("127.0.0.1:{ssh_port}"))
        .env("STARFORGE__REGISTRATION__MODE", "open")
        .env(
            "STARFORGE__MAIL__URL",
            format!("file://{}", mail_dir.display()),
        )
        .env("STARFORGE__MAIL__FROM", "Starforge <forge@example.test>")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _server = Server(child);

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut healthy = false;
    for _ in 0..100 {
        let response = client.get(format!("{base}/healthz")).send().await;
        if response.is_ok_and(|r| r.status().is_success()) {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healthy, "starforged did not become healthy");

    let form = get_text(&client, &format!("{base}/join")).await;
    let csrf = extract_input(&form, "_csrf");
    let joined = client
        .post(format!("{base}/join"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("invite", ""),
            ("handle", "dana"),
            ("email", "dana@example.test"),
            ("display_name", "Dana"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(joined.status(), 200);
    assert!(joined.text().await.unwrap().contains("Check your email"));

    // The server's own job workers deliver the message.
    let mut messages = Vec::new();
    for _ in 0..100 {
        messages = starforged_core::mail::testing::read_mailbox(&mail_dir);
        if !messages.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(messages.len(), 1, "the verification email did not arrive");
    let link = starforged_core::mail::testing::find_link(&messages[0], "/verify/").unwrap();
    assert!(link.starts_with(&base), "{link}");

    let confirm = get_text(&client, &link).await;
    let confirm_csrf = extract_input(&confirm, "_csrf");
    let verified = client
        .post(&link)
        .form(&[("_csrf", confirm_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(verified.status(), 200);

    let login = get_text(&client, &format!("{base}/login")).await;
    let login_csrf = extract_input(&login, "_csrf");
    let signed_in = client
        .post(format!("{base}/login"))
        .form(&[
            ("_csrf", login_csrf.as_str()),
            ("next", "/"),
            ("login", "dana"),
            ("password", PASSWORD),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), 303);
    assert!(
        get_text(&client, &format!("{base}/"))
            .await
            .contains("Your repositories")
    );
}
