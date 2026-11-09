//! `starforge ci run`: parse `.starforge/ci.toml` and run jobs in a local
//! sandbox, without a server or a CI job. A developer loop.

use std::collections::BTreeMap;
use std::process::Command;

use starforge_ci_spec::{CiJobSpec, CiSpec};
use starforge_runner::local::LocalSandboxClient;
use starforge_sandbox_protocol::{CreateSandboxRequest, ExecChunk, ExecRequest, NetworkPolicy};

use crate::cli::CiCmd;

/// Chunk size for copying the working tree into the sandbox (the daemon's
/// per-file cap is 8 MiB).
const COPY_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Run one `ci` subcommand; returns the process exit code.
pub async fn run(cmd: CiCmd, dry_run: bool) -> u8 {
    match cmd {
        CiCmd::Run {
            job,
            keep,
            socket,
            token_file,
            allow_host,
            spec,
        } => {
            let text = match std::fs::read_to_string(&spec) {
                Ok(text) => text,
                Err(err) => {
                    eprintln!("error: reading {}: {err}", spec.display());
                    return 1;
                }
            };
            let spec = match CiSpec::parse(&text) {
                Ok(spec) => spec,
                Err(err) => {
                    eprintln!("error: {}: {err}", spec.display());
                    return 1;
                }
            };
            let jobs = match select_jobs(&spec, job.as_deref()) {
                Ok(jobs) => jobs,
                Err(err) => {
                    eprintln!("error: {err}");
                    return 1;
                }
            };
            if dry_run {
                for job in &jobs {
                    println!(
                        "ci run: job {} image={}",
                        job.name,
                        job.image
                            .as_deref()
                            .or(job.template.as_deref())
                            .unwrap_or("<none>")
                    );
                }
                return 0;
            }
            let tree = match working_tree_tar() {
                Ok(tree) => tree,
                Err(err) => {
                    eprintln!("error: {err}");
                    return 1;
                }
            };
            let client = LocalSandboxClient::new(socket, token_file);
            let mut code = 0;
            for job in &jobs {
                println!("==> job {}", job.name);
                code = run_job(&client, job, &tree, &allow_host, keep).await;
                if code != 0 {
                    break;
                }
            }
            code
        }
    }
}

/// Selects the jobs to run: an exact expanded name first, then every
/// combination of a base name. No name runs every expanded job.
fn select_jobs(spec: &CiSpec, name: Option<&str>) -> Result<Vec<CiJobSpec>, String> {
    let expanded = spec.expanded_jobs();
    match name {
        None => Ok(expanded),
        Some(name) => {
            if let Some(job) = expanded.iter().find(|job| job.name == name) {
                return Ok(vec![job.clone()]);
            }
            let selected: Vec<CiJobSpec> = spec
                .jobs
                .iter()
                .filter(|job| job.name == name)
                .flat_map(CiJobSpec::expanded)
                .collect();
            if selected.is_empty() {
                return Err(format!("unknown CI job `{name}`"));
            }
            Ok(selected)
        }
    }
}

/// Runs one job in a fresh sandbox: copy the working tree, run the
/// commands, and return the last exit code.
async fn run_job(
    client: &LocalSandboxClient,
    job: &CiJobSpec,
    tree: &[u8],
    allow_host: &[String],
    keep: bool,
) -> u8 {
    if !job.secrets.is_empty() {
        eprintln!(
            "warning: job {} lists secrets; local runs do not resolve them",
            job.name
        );
    }
    let image = job
        .image
        .as_deref()
        .or(job.template.as_deref())
        .unwrap_or("starforge/rust");
    let timeout_s = job.timeout_duration().map(|d| d.as_secs()).unwrap_or(3600);
    let req = CreateSandboxRequest {
        template: image.to_owned(),
        timeout_s,
        envs: job.env.clone(),
        network: NetworkPolicy {
            allow_out: allow_host.to_vec(),
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
    let mut parts = Vec::new();
    for (index, chunk) in tree.chunks(COPY_CHUNK_BYTES).enumerate() {
        let path = format!(".starforge-ci/part-{index:03}");
        if let Err(err) = client.write_file(&info.id, &path, chunk).await {
            eprintln!("error: copying the working tree: {err}");
            let _ = client.kill(&info.id).await;
            return 1;
        }
        parts.push(path);
    }
    let extract = format!(
        "cat {} | tar xzf - -C /workspace && rm -rf .starforge-ci",
        parts.join(" ")
    );
    let mut code = exec(client, &info.id, &extract, timeout_s).await;
    if code != 0 {
        eprintln!("error: extracting the working tree failed ({code})");
    }
    if code == 0 {
        for command in &job.commands {
            code = exec(client, &info.id, command, timeout_s).await;
            if code != 0 {
                break;
            }
        }
    }
    if keep {
        println!(
            "sandbox {} kept; kill it with `starforge sandbox kill {}`",
            info.id, info.id
        );
    } else if let Err(err) = client.kill(&info.id).await {
        eprintln!("warning: killing sandbox {}: {err}", info.id);
    }
    if !(0..=255).contains(&code) {
        eprintln!("error: command exited with code {code}");
        return 1;
    }
    code as u8
}

/// Runs one shell command and streams its chunks; returns the exit code.
async fn exec(client: &LocalSandboxClient, id: &str, command: &str, timeout_s: u64) -> i64 {
    let req = ExecRequest {
        command: vec!["sh".to_owned(), "-c".to_owned(), command.to_owned()],
        cwd: None,
        envs: BTreeMap::new(),
        timeout_s,
    };
    match client.exec(id, &req).await {
        Ok(chunks) => {
            let mut code = 0;
            for chunk in chunks {
                match chunk {
                    ExecChunk::Stdout { data } => print!("{data}"),
                    ExecChunk::Stderr { data } => eprint!("{data}"),
                    ExecChunk::Exit { code: c } => code = i64::from(c),
                }
            }
            code
        }
        Err(err) => {
            eprintln!("error: exec: {err}");
            1
        }
    }
}

/// The working tree as a gzipped tar (members are `./...`, extracted at the
/// sandbox workspace root).
fn working_tree_tar() -> Result<Vec<u8>, String> {
    let out = Command::new("tar")
        .args([
            "czf",
            "-",
            "--exclude=.starforge-ci",
            "--exclude=target",
            "-C",
            ".",
            ".",
        ])
        .output()
        .map_err(|err| format!("running tar: {err}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}
