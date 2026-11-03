use std::process::Command;

fn starforged() -> Command {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
}

#[test]
fn init_writes_a_private_config_and_the_data_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    let out = starforged()
        .args([
            "--config",
            config.to_str().unwrap(),
            "init",
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for sub in ["repos", "tmp", "run"] {
        assert!(data.join(sub).is_dir(), "{sub} missing");
    }
    let loaded = starforged::config::Config::load(&config).unwrap();
    assert_eq!(loaded.security.secret_key.len(), 64);
    assert_eq!(loaded.server.base_url, "http://127.0.0.1:3000");
    assert_eq!(loaded.server.http_addr, "127.0.0.1:3000");
    assert_eq!(
        loaded.storage.data_dir,
        std::fs::canonicalize(&data).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn init_refuses_to_overwrite_an_existing_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    std::fs::write(&config, "keep me").unwrap();
    let out = starforged()
        .args([
            "--config",
            config.to_str().unwrap(),
            "init",
            "--data-dir",
            tmp.path().join("d").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "keep me");
}
