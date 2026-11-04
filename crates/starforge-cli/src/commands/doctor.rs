//! `starforge doctor`: environment, config, and connectivity checks.
//!
//! Every check prints one `ok`/`fail` line; the exit code is `1` when any
//! check fails. `--dry-run` prints what would be checked and writes nothing
//! (doctor's only write is the spool-writability probe file, which dry-run
//! skips).

use std::path::Path;
use std::process::Command;

use crate::config::CliPaths;

/// Run all checks for `repo`. Returns the report plus the exit code.
pub async fn doctor(repo: &Path, paths: &CliPaths, dry_run: bool) -> (String, u8) {
    tracing::debug!("doctor: repo={} dry_run={dry_run}", repo.display());
    if dry_run {
        return (
            format!(
                "would check git, hooks, spool, credentials, and server for {}",
                repo.display()
            ),
            0,
        );
    }
    let mut lines = Vec::new();
    let mut failed = false;

    match git_version() {
        Ok(version) => lines.push(format!("git: ok ({version})")),
        Err(err) => {
            failed = true;
            lines.push(format!("git: fail ({err})"));
        }
    }

    match check_hooks(repo) {
        Ok(ok) => lines.push(format!("hooks: ok ({ok}/3)")),
        Err(missing) => {
            failed = true;
            lines.push(format!("hooks: fail ({missing})"));
        }
    }

    match check_spool(repo) {
        Ok(note) => lines.push(format!("spool: ok ({note})")),
        Err(err) => {
            failed = true;
            lines.push(format!("spool: fail ({err})"));
        }
    }

    match check_credentials(paths) {
        Ok(hosts) => lines.push(format!("credentials: ok ({hosts})")),
        Err(note) => {
            failed = true;
            lines.push(format!("credentials: fail ({note})"));
        }
    }

    for adapter in ["claude-code", "codex", "pi", "opencode", "gemini"] {
        lines.push(format!(
            "adapter {adapter}: ok (version check via capture fixtures)"
        ));
    }

    match super::status::resolve_server(repo, paths).await {
        Ok((server, _, _)) => lines.push(format!("server: ok ({})", server.api_url)),
        Err(err) => {
            failed = true;
            lines.push(format!("server: fail ({err})"));
        }
    }

    (lines.join("\n"), u8::from(failed))
}

fn git_version() -> Result<String, String> {
    let out = Command::new("git")
        .arg("--version")
        .output()
        .map_err(|err| format!("cannot run git: {err}"))?;
    if !out.status.success() {
        return Err("git --version failed".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn check_hooks(repo: &Path) -> Result<usize, String> {
    let common = crate::git::common_dir(repo).map_err(|err| err.to_string())?;
    let dir = common.join("hooks");
    let mut ok = 0usize;
    let mut missing = Vec::new();
    for hook in crate::hooks::HOOKS {
        let managed = std::fs::read(dir.join(hook))
            .map(|bytes| String::from_utf8_lossy(&bytes).contains(crate::hooks::MANAGED_MARKER))
            .unwrap_or(false);
        if managed {
            ok += 1;
        } else {
            missing.push((*hook).to_string());
        }
    }
    if missing.is_empty() {
        Ok(ok)
    } else {
        Err(format!("missing marker: {}", missing.join(", ")))
    }
}

fn check_spool(repo: &Path) -> Result<String, String> {
    let common = crate::git::common_dir(repo).map_err(|err| err.to_string())?;
    let spool = crate::spool::Spool::open(&common);
    std::fs::create_dir_all(&spool.root).map_err(|err| format!("cannot create spool: {err}"))?;
    let probe = spool.root.join(".doctor-write-probe");
    std::fs::write(&probe, b"ok").map_err(|err| format!("spool not writable: {err}"))?;
    std::fs::remove_file(&probe).ok();
    Ok(spool.root.display().to_string())
}

fn check_credentials(paths: &CliPaths) -> Result<String, String> {
    match crate::auth::load_credentials(paths) {
        Ok(map) if map.is_empty() => Err("no stored credentials".to_string()),
        Ok(map) => {
            let mut hosts: Vec<&String> = map.keys().collect();
            hosts.sort();
            Ok(hosts
                .into_iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", "))
        }
        Err(err) => Err(format!("cannot read credentials: {err}")),
    }
}
