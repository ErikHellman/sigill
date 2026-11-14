//! One-click unsubscribe tokens: `<delivery id, 32 hex>.<mac>`, where the MAC is the first
//! 12 bytes of `HMAC-SHA256(unsubscribe_key, delivery id)` in base64url.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Html;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sigill_core::secrets::{ct_eq, hmac_sha256};
use sigill_core::telemetry;

use crate::AppState;

fn mac(key: &[u8], id: &uuid::Uuid) -> String {
    URL_SAFE_NO_PAD.encode(&hmac_sha256(key, id.as_bytes())[..12])
}

pub fn token(key: &[u8], delivery_id: &str) -> String {
    let id = uuid::Uuid::parse_str(delivery_id).expect("delivery ids are UUIDs");
    format!("{}.{}", id.simple(), mac(key, &id))
}

/// The delivery id in a valid token.
pub fn verify(key: &[u8], token: &str) -> Option<String> {
    let (id, given) = token.split_once('.')?;
    let id = uuid::Uuid::try_parse(id).ok()?;
    ct_eq(mac(key, &id).as_bytes(), given.as_bytes()).then(|| id.hyphenated().to_string())
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>{title}</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}\
         button{{font:inherit;padding:.5rem 1rem;cursor:pointer}}</style></head>\
         <body><h1>{title}</h1>{body}</body></html>"
    )
}

fn not_found() -> (StatusCode, Html<String>) {
    (StatusCode::NOT_FOUND, Html(page("Link not valid", "<p>This unsubscribe link is not valid.</p>")))
}

/// `GET /u/{token}`: a confirmation page. It does not unsubscribe by itself, because mail
/// scanners follow links.
pub async fn confirm_page(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> (StatusCode, Html<String>) {
    if verify(&state.inner.secrets.unsubscribe_key(), &token).is_none() {
        return not_found();
    }
    // The token is hex and base64url, so it is safe to put in the page as is.
    let body = format!(
        "<p>Stop receiving these emails?</p><form method=\"post\" action=\"/u/{token}\">\
         <button type=\"submit\">Unsubscribe</button></form>"
    );
    (StatusCode::OK, Html(page("Unsubscribe", &body)))
}

/// `POST /u/{token}`: RFC 8058 one-click unsubscribe (also used by the confirmation form).
pub async fn unsubscribe(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<(StatusCode, Html<String>), crate::error::ApiError> {
    let Some(delivery_id) = verify(&state.inner.secrets.unsubscribe_key(), &token) else {
        return Ok(not_found());
    };
    match state.store.record_unsubscribe(&delivery_id).await? {
        None => Ok(not_found()),
        Some(changed) => {
            if changed && let Some(d) = state.store.get_delivery(&delivery_id).await? {
                tracing::info!(delivery_id = %d.id, rcpt_domain = %d.rcpt_domain, "unsubscribed");
                telemetry::track(
                    "unsubscribed",
                    &[("stream", d.stream.as_str()), ("rcpt_domain", &d.rcpt_domain)],
                );
            }
            Ok((
                StatusCode::OK,
                Html(page("Unsubscribed", "<p>You will not receive these emails any more.</p>")),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = sigill_core::new_id();
        let t = token(&[1u8; 32], &id);
        assert_eq!(verify(&[1u8; 32], &t), Some(id));
        assert_eq!(verify(&[2u8; 32], &t), None);
        assert_eq!(verify(&[1u8; 32], "garbage"), None);
    }

    #[tokio::test]
    async fn one_click_flow() {
        use axum::http::Method;
        use serde_json::json;
        use sigill_core::Stream;

        let t = crate::testing::TestApp::new().await;
        t.template("news").await;
        let (s, v) = t
            .call(
                Method::POST,
                "/v1/messages",
                Some(json!({"template": "news", "to": ["Reader@x.test"], "stream": "broadcast",
                            "variables": {"name": "R"}})),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        let delivery = v["deliveries"][0]["id"].as_str().unwrap().to_string();
        let tok = token(&t.state.inner.secrets.unsubscribe_key(), &delivery);

        let (s, page) = t.call_with_key(Method::GET, &format!("/u/{tok}"), None, None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(page.as_str().unwrap().contains("method=\"post\""));
        assert!(
            !t.db.is_suppressed("reader@x.test", Stream::Broadcast).await.unwrap(),
            "GET changes nothing"
        );

        let (s, _) = t.call_with_key(Method::POST, &format!("/u/{tok}"), None, None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(t.db.is_suppressed("reader@x.test", Stream::Broadcast).await.unwrap());
        assert!(!t.db.is_suppressed("reader@x.test", Stream::Transactional).await.unwrap());
        let (s, _) = t.call_with_key(Method::POST, &format!("/u/{tok}"), None, None).await;
        assert_eq!(s, StatusCode::OK, "repeat is harmless");

        let bad = format!("{}x", &tok[..tok.len() - 1]);
        let (s, _) = t.call_with_key(Method::POST, &format!("/u/{bad}"), None, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}
