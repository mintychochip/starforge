use std::path::Path;
use std::process::{Command, Output};

fn starforged(config: &Path, args: &[&str], mail_url: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_starforged"));
    command.arg("--config").arg(config).args(args);
    if let Some(url) = mail_url {
        command
            .env("STARFORGE__MAIL__URL", url)
            .env("STARFORGE__MAIL__FROM", "Starforge <forge@example.test>");
    }
    command.output().unwrap()
}

#[test]
fn admin_mail_test_sends_one_message() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("starforged.toml");
    let data = dir.path().join("data");
    let init = starforged(
        &config,
        &["init", "--data-dir", data.to_str().unwrap()],
        None,
    );
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let not_configured = starforged(
        &config,
        &["admin", "mail", "test", "--to", "ops@example.com"],
        None,
    );
    assert!(!not_configured.status.success());
    assert!(String::from_utf8_lossy(&not_configured.stderr).contains("mail.url is empty"));

    let mail_dir = dir.path().join("mail");
    let url = format!("file://{}", mail_dir.display());
    let sent = starforged(
        &config,
        &["admin", "mail", "test", "--to", "ops@example.com"],
        Some(&url),
    );
    assert!(
        sent.status.success(),
        "{}",
        String::from_utf8_lossy(&sent.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&sent.stdout).trim(),
        "sent a test email to ops@example.com"
    );
    let messages = starforged_core::mail::testing::read_mailbox(&mail_dir);
    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("Subject: Starforge test email"),
        "{}",
        messages[0]
    );
}
