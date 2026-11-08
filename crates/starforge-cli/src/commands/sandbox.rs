//! `starforge sandbox` subcommands: a local developer loop against
//! `starforge-sandboxd` (create/exec/copy/kill) without a server or a CI
//! job.

use std::collections::BTreeMap;
use std::path::Path;

use starforge_runner::local::LocalSandboxClient;
use starforge_sandbox_protocol::{CreateSandboxRequest, ExecChunk, ExecRequest, NetworkPolicy};

use crate::cli::SandboxCmd;

/// Run one `sandbox` subcommand; returns the process exit code.
pub async fn run(cmd: SandboxCmd, dry_run: bool) -> u8 {
    match cmd {
        SandboxCmd::Run {
            socket,
            token_file,
            image,
            allow_host,
            envs,
            timeout,
            keep,
            command,
        } => {
            if dry_run {
                println!(
                    "sandbox run: image={image} allow_host={allow_host:?} timeout={timeout} keep={keep} command={command:?}\n(dry run: no daemon contact)"
                );
                return 0;
            }
            let envs = match parse_envs(&envs) {
                Ok(envs) => envs,
                Err(err) => {
                    eprintln!("error: {err}");
                    return 2;
                }
            };
            let client = LocalSandboxClient::new(socket, token_file);
            let req = CreateSandboxRequest {
                template: image,
                timeout_s: timeout,
                envs,
                network: NetworkPolicy {
                    allow_out: allow_host,
                    ..Default::default()
                },
                ..Default::default()
            };
            let info = match client.create(&req).await {
                Ok(info) => info,
                Err(err) => {
                    eprintln!("error: sandbox create: {err}");
                    return 1;
                }
            };
            println!("sandbox {} ({:?})", info.id, info.state);
            let code = exec_and_stream(&client, &info.id, command).await;
            if !keep {
                if let Err(err) = client.kill(&info.id).await {
                    eprintln!("warning: killing sandbox {}: {err}", info.id);
                }
            } else {
                println!(
                    "sandbox {} kept; kill it with `starforge sandbox kill {}`",
                    info.id, info.id
                );
            }
            code
        }
        SandboxCmd::Exec {
            socket,
            token_file,
            id,
            command,
        } => {
            if dry_run {
                println!("sandbox exec: id={id} command={command:?}\n(dry run: no daemon contact)");
                return 0;
            }
            let client = LocalSandboxClient::new(socket, token_file);
            exec_and_stream(&client, &id, command).await
        }
        SandboxCmd::Cp {
            socket,
            token_file,
            id,
            path,
            dest,
        } => {
            if dry_run {
                println!(
                    "sandbox cp: id={id} path={path} dest={}\n(dry run: no daemon contact)",
                    dest.display()
                );
                return 0;
            }
            let client = LocalSandboxClient::new(socket, token_file);
            match client.read_file(&id, &path).await {
                Ok(Some(bytes)) => {
                    if let Err(err) = std::fs::write(&dest, &bytes) {
                        eprintln!("error: writing {}: {err}", dest.display());
                        return 1;
                    }
                    println!("wrote {} ({} bytes)", dest.display(), bytes.len());
                    0
                }
                Ok(None) => {
                    eprintln!("error: {path} not found in sandbox {id}");
                    1
                }
                Err(err) => {
                    eprintln!("error: sandbox cp: {err}");
                    1
                }
            }
        }
        SandboxCmd::Kill {
            socket,
            token_file,
            id,
        } => {
            if dry_run {
                println!("sandbox kill: id={id}\n(dry run: no daemon contact)");
                return 0;
            }
            let client = LocalSandboxClient::new(socket, token_file);
            match client.kill(&id).await {
                Ok(()) => {
                    println!("killed {id}");
                    0
                }
                Err(err) => {
                    eprintln!("error: sandbox kill: {err}");
                    1
                }
            }
        }
    }
}

/// Exec `command`, stream stdout/stderr, and return the exit code.
async fn exec_and_stream(client: &LocalSandboxClient, id: &str, command: Vec<String>) -> u8 {
    let req = ExecRequest {
        command,
        ..Default::default()
    };
    let chunks = match client.exec(id, &req).await {
        Ok(chunks) => chunks,
        Err(err) => {
            eprintln!("error: sandbox exec: {err}");
            return 1;
        }
    };
    let mut code = 0i32;
    for chunk in chunks {
        match chunk {
            ExecChunk::Stdout { data } => print!("{data}"),
            ExecChunk::Stderr { data } => eprint!("{data}"),
            ExecChunk::Exit { code: c } => code = c,
        }
    }
    if !(0..=255).contains(&code) {
        eprintln!("error: sandbox command exited with code {code}");
        return 1;
    }
    code as u8
}

fn parse_envs(envs: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for entry in envs {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("--env expects KEY=VALUE, got `{entry}`"))?;
        if key.is_empty() {
            return Err(format!("--env key is empty in `{entry}`"));
        }
        out.insert(key.to_owned(), value.to_owned());
    }
    Ok(out)
}

/// Whether `path` exists; used by the tests to check `cp` output.
#[allow(dead_code)]
fn exists(path: &Path) -> bool {
    path.exists()
}
