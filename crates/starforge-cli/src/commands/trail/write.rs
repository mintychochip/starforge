//! `trail create` and `trail comment`.

use serde_json::{Value, json};

use super::{Format, TrailCtx, agent_unsupported, pretty};

/// `trail create`: posts `{title, intent}`, prints the new trail's URL.
pub async fn create(ctx: &TrailCtx, title: &str, intent: &str, format: Format) -> (String, u8) {
    let resp = match ctx
        .api
        .post("trails", &json!({"title": title, "intent": intent}))
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => {
            let n = resp.get("number").and_then(Value::as_i64).unwrap_or(0);
            (
                format!(
                    "created trail #{n}: {}",
                    ctx.api.web_url(&format!("trails/{n}"))
                ),
                0,
            )
        }
    }
}

/// `trail comment`: posts `{body}` on the trail, prints the trail's URL.
pub async fn comment(ctx: &TrailCtx, n: i64, body: &str, format: Format) -> (String, u8) {
    let resp = match ctx
        .api
        .post(&format!("trails/{n}/comments"), &json!({"body": body}))
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => (
            format!(
                "commented on trail #{n}: {}",
                ctx.api.web_url(&format!("trails/{n}"))
            ),
            0,
        ),
    }
}

/// Arguments for `trail change add`.
pub struct ChangeAddArgs<'a> {
    pub trail: i64,
    pub from: &'a str,
    pub branch: &'a str,
    pub base: &'a str,
}

/// `trail change add`: opens a cross-repository change from `from`'s branch.
pub async fn change_add(ctx: &TrailCtx, args: &ChangeAddArgs<'_>, format: Format) -> (String, u8) {
    let resp = match ctx
        .api
        .post(
            &format!("trails/{}/changes", args.trail),
            &json!({
                "kind": "cross_repo",
                "source_repo": args.from,
                "source_branch": args.branch,
                "base_branch": args.base,
            }),
        )
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => {
            let k = resp.get("k").and_then(Value::as_i64).unwrap_or(0);
            (
                format!(
                    "opened change #{k} on trail #{} from {}:{}: {}",
                    args.trail,
                    args.from,
                    args.branch,
                    ctx.api
                        .web_url(&format!("trails/{}/changes/{k}", args.trail))
                ),
                0,
            )
        }
    }
}

/// `trail change refresh`: re-fetches a cross-repository change's source.
pub async fn change_refresh(
    ctx: &TrailCtx,
    trail: i64,
    change: i64,
    format: Format,
) -> (String, u8) {
    let resp = match ctx
        .api
        .post(
            &format!("trails/{trail}/changes/{change}/refresh"),
            &json!({}),
        )
        .await
    {
        Ok(resp) => resp,
        Err(err) => return ctx.api.render_error(err),
    };
    match format {
        Format::Json => (pretty(&resp), 0),
        Format::Agent => agent_unsupported(),
        Format::Text => {
            let revision = resp
                .get("current_revision")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            (
                format!("refreshed trail #{trail} change #{change} (revision {revision})"),
                0,
            )
        }
    }
}
