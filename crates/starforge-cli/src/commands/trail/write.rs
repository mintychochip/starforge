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
