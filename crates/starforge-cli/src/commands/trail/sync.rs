//! `trail push` and `trail checkout` (J4).

use std::time::Duration;

use serde_json::{Value, json};

use super::{Format, TrailCtx, agent_unsupported, pretty, select_change};
use crate::api::ApiError;
use crate::git;
use crate::queue::{Sleeper, TokioSleeper};

/// Arguments for `trail push`.
#[derive(Debug, Clone)]
pub struct PushArgs {
    /// Trail number (`-o trail=N`); omit to create a trail.
    pub trail: Option<i64>,
    /// Trail title for a new trail (`-o title=T`).
    pub title: Option<String>,
    /// Base branch (default: the remote's HEAD branch).
    pub base: Option<String>,
    /// Topic (default: a slug of the current branch).
    pub topic: Option<String>,
    /// Git remote name (default: the discovered remote).
    pub remote: Option<String>,
}

/// Arguments for `trail checkout`.
#[derive(Debug, Clone)]
pub struct CheckoutArgs {
    /// Trail number.
    pub n: i64,
    /// Change number (default: the single open change).
    pub change: Option<i64>,
    /// Revision number (detached HEAD).
    pub rev: Option<i64>,
    /// Git remote name (default: the discovered remote).
    pub remote: Option<String>,
}

/// D7 topic slug: lowercase the branch, replace every char outside
/// `[a-z0-9-_.]` with `-`, and truncate to 63 chars. `None` when the result
/// would be empty.
pub fn topic_slug(branch: &str) -> Option<String> {
    let slug: String = branch
        .to_lowercase()
        .chars()
        .map(|c| {
            if matches!(c, 'a'..='z' | '0'..='9' | '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    (!slug.is_empty()).then_some(slug)
}

/// Server SHAs are lowercase 40/64-char hex; validate before handing one to
/// git (CLI git binding).
fn is_oid(sha: &str) -> bool {
    (sha.len() == 40 || sha.len() == 64)
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The server's title rule (mirrors `check_title` in `starforged-core`):
/// trimmed, 1-200 chars, a single line. Returns the trimmed title.
fn check_push_title(title: &str) -> Result<String, String> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err("title must not be empty".to_string());
    }
    if trimmed.chars().count() > 200 {
        return Err("title must be at most 200 chars".to_string());
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("title must be a single line".to_string());
    }
    Ok(trimmed.to_string())
}

/// `trail push`: push `HEAD` as a change revision with the production D8
/// poll (every 250 ms for up to 10 s).
pub async fn push(ctx: &TrailCtx, args: &PushArgs, format: Format) -> (String, u8) {
    push_with(
        ctx,
        args,
        format,
        &TokioSleeper,
        Duration::from_millis(250),
        Duration::from_secs(10),
    )
    .await
}

/// `trail push` with the D8 poll interval and deadline injected, so tests
/// never sleep 10 s. Follows the [`Sleeper`] pattern in [`crate::queue`].
pub async fn push_with<S: Sleeper>(
    ctx: &TrailCtx,
    args: &PushArgs,
    format: Format,
    sleeper: &S,
    poll_interval: Duration,
    poll_deadline: Duration,
) -> (String, u8) {
    // Client-side title validation first, before running git.
    let title = match args.title.as_deref() {
        Some(title) => match check_push_title(title) {
            Ok(title) => Some(title),
            Err(msg) => return (format!("error: {msg}"), 1),
        },
        None => None,
    };
    let Some(remote) = args.remote.as_deref().or(ctx.remote.as_deref()) else {
        return (
            "error: no usable remote; pass --remote <name>".to_string(),
            1,
        );
    };
    // D7 base: `--base`, else the remote's HEAD branch.
    let base = match args.base.as_deref() {
        Some(base) => base.to_string(),
        None => match git::remote_default_branch(&ctx.repo_dir, remote, &ctx.git_env) {
            Ok(Some(base)) => base,
            Ok(None) => {
                return (
                    format!(
                        "error: cannot determine the base branch of remote '{remote}'; pass --base <branch>"
                    ),
                    1,
                );
            }
            Err(err) => return (format!("error: {err}"), 1),
        },
    };
    // D7 topic: `--topic`, else a slug of the current branch (omitted on a
    // detached HEAD, so the server uses its handle default).
    let topic = match args.topic.as_deref() {
        Some(topic) => Some(topic.to_string()),
        None => match git::current_branch(&ctx.repo_dir, &ctx.git_env) {
            Ok(Some(branch)) => topic_slug(&branch),
            Ok(None) => None,
            Err(err) => return (format!("error: {err}"), 1),
        },
    };
    let sha = match git::head_sha(&ctx.repo_dir, &ctx.git_env) {
        Ok(sha) => sha,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let mut refspec = format!("HEAD:refs/for/{base}");
    if let Some(topic) = &topic {
        refspec.push('/');
        refspec.push_str(topic);
    }
    let mut options = Vec::new();
    if let Some(n) = args.trail {
        options.push(format!("trail={n}"));
    }
    if let Some(title) = &title {
        options.push(format!("title={title}"));
    }
    // A non-zero `git push` exits 1 here; git's own stderr has already
    // reached the user, so there is nothing to poll for.
    if git::push_refspec(&ctx.repo_dir, remote, &refspec, &options, &ctx.git_env).is_err() {
        return ("error: git push failed".to_string(), 1);
    }
    // D8: the change is recorded after receive-pack returns, so poll the
    // head-SHA lookup for the pushed base (and the pinned trail, if any).
    match poll_for_change(
        ctx,
        &sha,
        &base,
        args.trail,
        sleeper,
        poll_interval,
        poll_deadline,
    )
    .await
    {
        Ok(Some(change)) => {
            let n = change.get("trail").and_then(Value::as_i64).unwrap_or(0);
            let k = change.get("k").and_then(Value::as_i64).unwrap_or(0);
            let r = change
                .get("current_revision")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let url = ctx.api.web_url(&format!("trails/{n}"));
            match format {
                Format::Json => (
                    pretty(&json!({
                        "trail": n,
                        "change": k,
                        "revision": r,
                        "url": url,
                        "sha": sha,
                    })),
                    0,
                ),
                Format::Text => (format!("trail #{n} change {k} revision {r}: {url}"), 0),
                Format::Agent => agent_unsupported(),
            }
        }
        Ok(None) => match format {
            Format::Json => (
                pretty(&json!({
                    "trail": Value::Null,
                    "change": Value::Null,
                    "revision": Value::Null,
                    "url": Value::Null,
                    "sha": sha,
                })),
                0,
            ),
            Format::Text => (
                format!("pushed {sha}; the server has not recorded the change yet"),
                0,
            ),
            Format::Agent => agent_unsupported(),
        },
        // The git push already landed, so say so; the lookup itself failed.
        Err(err) => {
            let (msg, _) = ctx.api.render_error(err);
            (
                format!("pushed {sha}, but looking up the change failed: {msg}"),
                1,
            )
        }
    }
}

/// Poll `GET changes?head_sha=<sha>` for a change on `base` (pinned to
/// `trail` when given) until `deadline`. Only `Ok` with an empty or
/// non-matching `changes` array means "not yet recorded"; a read error fails
/// fast (the push already landed, but a persistent 401/404/transport failure
/// is not server lag and must not exit 0).
async fn poll_for_change<S: Sleeper>(
    ctx: &TrailCtx,
    sha: &str,
    base: &str,
    trail: Option<i64>,
    sleeper: &S,
    poll_interval: Duration,
    poll_deadline: Duration,
) -> Result<Option<Value>, ApiError> {
    let start = std::time::Instant::now();
    loop {
        let resp = match ctx
            .api
            .get("changes", &[("head_sha", sha.to_string())])
            .await
        {
            Ok(resp) => resp,
            Err(err) => return Err(err),
        };
        if let Some(changes) = resp.get("changes").and_then(Value::as_array)
            && let Some(hit) = changes
                .iter()
                .find(|change| {
                    change.get("base_branch").and_then(|v| v.as_str()) == Some(base)
                        && trail
                            .is_none_or(|n| change.get("trail").and_then(Value::as_i64) == Some(n))
                })
                .cloned()
        {
            return Ok(Some(hit));
        }
        if start.elapsed() >= poll_deadline {
            return Ok(None);
        }
        sleeper.sleep(poll_interval).await;
    }
}

/// `trail checkout`: fetch the change head and check it out per D6 (with the
/// D4 sole-closed allowance and the D1 hidden-ref fetch). The branch rule is
/// checked before any switch, so a refusal touches nothing.
pub async fn checkout(ctx: &TrailCtx, args: &CheckoutArgs, format: Format) -> (String, u8) {
    let Some(remote) = args.remote.as_deref().or(ctx.remote.as_deref()) else {
        return (
            "error: no usable remote; pass --remote <name>".to_string(),
            1,
        );
    };
    let changes_resp = match ctx
        .api
        .get(&format!("trails/{}/changes", args.n), &[])
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    let changes: Vec<Value> = changes_resp
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let k = match select_change(&changes, args.change, true) {
        Ok(k) => k,
        Err(msg) => return (format!("error: {msg}"), 1),
    };
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(rev) = args.rev {
        query.push(("rev", rev.to_string()));
    }
    let detail = match ctx
        .api
        .get(&format!("trails/{}/changes/{k}", args.n), &query)
        .await
    {
        Ok(detail) => detail,
        Err(err) => return ctx.api.render_error(err),
    };
    let Some(head_sha) = detail.pointer("/selected/head_sha").and_then(Value::as_str) else {
        return (format!("error: change {k} has no revisions yet"), 1);
    };
    if !is_oid(head_sha) {
        return (
            "error: server returned an invalid change head".to_string(),
            1,
        );
    }
    let revision = detail
        .pointer("/selected/r")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let branch = format!("trail/{}/{}", args.n, k);
    match git::valid_branch_name(&ctx.repo_dir, &branch, &ctx.git_env) {
        Ok(true) => {}
        Ok(false) => return (format!("error: invalid branch name '{branch}'"), 1),
        Err(err) => return (format!("error: {err}"), 1),
    }
    if let Err(err) = git::fetch_object(&ctx.repo_dir, remote, head_sha, &ctx.git_env) {
        return (format!("error: {err}"), 1);
    }
    let short = head_sha.get(..7).unwrap_or(head_sha);
    if args.rev.is_some() {
        // Revisions are immutable snapshots: check out a detached HEAD.
        if let Err(err) = git::switch_detach(&ctx.repo_dir, head_sha, &ctx.git_env) {
            return (format!("error: {err}"), 1);
        }
        return match format {
            Format::Json => (
                pretty(&json!({
                    "trail": args.n,
                    "change": k,
                    "revision": revision,
                    "sha": head_sha,
                    "branch": Value::Null,
                })),
                0,
            ),
            Format::Text => (
                format!(
                    "HEAD detached at {short} (trail #{} change {k} revision {revision})",
                    args.n
                ),
                0,
            ),
            Format::Agent => agent_unsupported(),
        };
    }
    match git::branch_tip(&ctx.repo_dir, &branch, &ctx.git_env) {
        Err(err) => return (format!("error: {err}"), 1),
        Ok(None) => {
            if let Err(err) = git::switch_create(&ctx.repo_dir, &branch, head_sha, &ctx.git_env) {
                return (format!("error: {err}"), 1);
            }
        }
        Ok(Some(tip)) if tip == head_sha => {
            if let Err(err) = git::switch_to(&ctx.repo_dir, &branch, &ctx.git_env) {
                return (format!("error: {err}"), 1);
            }
        }
        Ok(Some(tip)) => {
            match git::is_ancestor(&ctx.repo_dir, &tip, head_sha, &ctx.git_env) {
                Ok(true) => {}
                Ok(false) => {
                    return (
                        format!(
                            "error: refusing to update {branch}: the local branch has diverged"
                        ),
                        1,
                    );
                }
                Err(err) => return (format!("error: {err}"), 1),
            }
            if let Err(err) = git::switch_to(&ctx.repo_dir, &branch, &ctx.git_env) {
                return (format!("error: {err}"), 1);
            }
            if let Err(err) = git::merge_ff_only(&ctx.repo_dir, head_sha, &ctx.git_env) {
                return (format!("error: {err}"), 1);
            }
        }
    }
    match format {
        Format::Json => (
            pretty(&json!({
                "trail": args.n,
                "change": k,
                "revision": revision,
                "sha": head_sha,
                "branch": branch,
            })),
            0,
        ),
        Format::Text => (
            format!(
                "on {branch} at {short} (trail #{} change {k} revision {revision})",
                args.n
            ),
            0,
        ),
        Format::Agent => agent_unsupported(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiClient;

    #[test]
    fn slug_covers_shape_unicode_length_and_slashes() {
        assert_eq!(
            topic_slug("Feature/Foo_bar"),
            Some("feature-foo_bar".to_string())
        );
        assert_eq!(topic_slug("caf\u{e9}"), Some("caf-".to_string()));
        assert_eq!(topic_slug("///"), Some("---".to_string()));
        assert_eq!(topic_slug(""), None);
        let slug = topic_slug(&"a".repeat(100)).unwrap();
        assert_eq!(slug.len(), 63);
        assert!(slug.chars().all(|c| c == 'a'));
    }

    #[test]
    fn title_rule_mirrors_the_server() {
        assert_eq!(check_push_title("  My Title  "), Ok("My Title".to_string()));
        assert_eq!(
            check_push_title(""),
            Err("title must not be empty".to_string())
        );
        assert_eq!(
            check_push_title("   "),
            Err("title must not be empty".to_string())
        );
        assert_eq!(
            check_push_title(&"x".repeat(201)),
            Err("title must be at most 200 chars".to_string())
        );
        assert_eq!(
            check_push_title("one\ntwo"),
            Err("title must be a single line".to_string())
        );
        assert_eq!(
            check_push_title("one\rtwo"),
            Err("title must be a single line".to_string())
        );
    }

    #[test]
    fn oid_accepts_lowercase_hex_only() {
        assert!(is_oid(&"a".repeat(40)));
        assert!(is_oid(&"0123456789abcdef".repeat(4)));
        assert!(!is_oid(&"A".repeat(40)));
        assert!(!is_oid("abc"));
        assert!(!is_oid(&"g".repeat(40)));
    }

    fn dummy_ctx() -> TrailCtx {
        let api = ApiClient::new("http://127.0.0.1:9", "o/r", "token").unwrap();
        TrailCtx::new(
            api,
            std::path::Path::new("/nonexistent-starforge-repo"),
            None,
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn push_rejects_a_bad_title_before_any_io() {
        let ctx = dummy_ctx();
        let args = PushArgs {
            trail: None,
            title: Some("one\ntwo".to_string()),
            base: None,
            topic: None,
            remote: None,
        };
        let (out, code) = push_with(
            &ctx,
            &args,
            Format::Text,
            &TokioSleeper,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(out, "error: title must be a single line");
    }

    #[tokio::test]
    async fn push_without_a_remote_names_the_flag() {
        let ctx = dummy_ctx();
        let args = PushArgs {
            trail: None,
            title: None,
            base: Some("main".to_string()),
            topic: None,
            remote: None,
        };
        let (out, code) = push_with(
            &ctx,
            &args,
            Format::Text,
            &TokioSleeper,
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(code, 1);
        assert!(out.contains("--remote"), "names --remote: {out}");
    }
}
