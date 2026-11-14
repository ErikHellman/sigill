//! `POST /v1/messages` and `GET /v1/messages/{id}`.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sigill_core::Stream;

use crate::AppState;
use crate::auth::AuthApp;
use crate::error::{ApiError, ApiResult};
use crate::send::{SendOutcome, SendRequest, send};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMessage {
    pub template: String,
    pub version: Option<i64>,
    pub to: Vec<String>,
    pub from: Option<String>,
    pub from_name: Option<String>,
    #[serde(default)]
    pub variables: Value,
    pub stream: Option<Stream>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub idempotency_key: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Json(req): Json<CreateMessage>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if let Some(k) = &req.idempotency_key
        && (k.is_empty() || k.len() > 255)
    {
        return Err(ApiError::invalid("idempotency_key must be 1 to 255 characters"));
    }
    let template = state
        .store
        .get_template(&app.id, &req.template, req.version)
        .await?
        .ok_or_else(|| ApiError::not_found("template"))?;
    let variables = if req.variables.is_null() { json!({}) } else { req.variables };
    let headers: Vec<(String, String)> = req.headers.into_iter().collect();
    let outcome = send(
        &state,
        SendRequest {
            app: &app,
            template: &template,
            to: &req.to,
            from: req.from.as_deref(),
            from_name: req.from_name.as_deref(),
            variables: &variables,
            stream: req.stream.unwrap_or(app.default_stream),
            headers: &headers,
            idempotency_key: req.idempotency_key.as_deref(),
            broadcast_id: None,
            not_before: None,
        },
    )
    .await?;
    match outcome {
        SendOutcome::Created { message_id, deliveries } => {
            Ok((StatusCode::ACCEPTED, Json(json!({"message_id": message_id, "deliveries": deliveries}))))
        }
        SendOutcome::Existing { message_id } => {
            let body = message_json(&state, &app.id, &message_id).await?;
            Ok((StatusCode::OK, Json(body)))
        }
    }
}

pub async fn get(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(message_json(&state, &app.id, &id).await?))
}

async fn message_json(state: &AppState, app_id: &str, id: &str) -> ApiResult<Value> {
    let msg = state.store.get_message(id).await?.filter(|m| m.app_id == app_id);
    let msg = msg.ok_or_else(|| ApiError::not_found("message"))?;
    let mut deliveries = Vec::new();
    for d in state.store.deliveries_for_message(id).await? {
        let events = state.store.events_for_delivery(&d.id).await?;
        deliveries.push(json!({
            "id": d.id,
            "to": d.rcpt,
            "status": d.status,
            "attempts": d.attempts,
            "next_attempt_at": (!d.status.is_final()).then_some(d.next_attempt_at),
            "last_smtp_code": d.last_smtp_code,
            "last_response": d.last_response,
            "updated_at": d.updated_at,
            "events": events.iter().map(|e| json!({"kind": e.kind, "detail": e.detail, "at": e.at})).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({
        "message_id": msg.id,
        "stream": msg.stream,
        "template": msg.template_key,
        "version": msg.template_version,
        "from": msg.from_addr,
        "subject": msg.subject,
        "idempotency_key": msg.idempotency_key,
        "broadcast_id": msg.broadcast_id,
        "created_at": msg.created_at,
        "deliveries": deliveries,
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use serde_json::json;
    use sigill_core::{Stream, SuppressionReason, SuppressionScope};

    use crate::testing::TestApp;

    #[tokio::test]
    async fn auth_is_required() {
        let t = TestApp::new().await;
        let (s, v) = t.call_with_key(Method::GET, "/v1/messages/x", None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(v["error"]["code"], "unauthorized");
        let bad = format!("{}x", t.key);
        let (s, _) = t.call_with_key(Method::GET, "/v1/messages/x", None, Some(&bad)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _) = t.call(Method::GET, "/v1/messages/x", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn send_validate_and_idempotency() {
        let t = TestApp::new().await;
        t.template("welcome").await;
        t.db.add_suppression("gone@x.com", SuppressionScope::All, SuppressionReason::HardBounce, None)
            .await
            .unwrap();
        let body = json!({
            "template": "welcome",
            "to": ["Ann@Example.com", "ann@example.com", "gone@x.com"],
            "variables": {"name": "Ann"},
            "headers": {"X-Order": "42"},
            "idempotency_key": "order-42",
        });
        let (s, v) = t.call(Method::POST, "/v1/messages", Some(body.clone())).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        let ds = v["deliveries"].as_array().unwrap();
        assert_eq!(ds.len(), 2, "duplicates collapse");
        let statuses: Vec<_> =
            ds.iter().map(|d| (d["to"].as_str().unwrap(), d["status"].as_str().unwrap())).collect();
        assert!(statuses.contains(&("Ann@example.com", "queued")));
        assert!(statuses.contains(&("gone@x.com", "suppressed")));
        let id = v["message_id"].as_str().unwrap().to_string();

        // Same idempotency key: the existing message, not a new one.
        let (s, v2) = t.call(Method::POST, "/v1/messages", Some(body)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v2["message_id"], id);

        let (s, m) = t.call(Method::GET, &format!("/v1/messages/{id}"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(m["subject"], "Hello Ann");
        assert_eq!(m["stream"], "transactional");
        assert_eq!(m["deliveries"].as_array().unwrap().len(), 2);

        // The stored body is signed MIME with our headers.
        let mime = String::from_utf8(t.db.message_mime(&id).await.unwrap().unwrap()).unwrap();
        assert!(mime.starts_with("DKIM-Signature:"));
        assert!(mime.contains(&format!("Message-ID: <{id}@mail.example.com>")));
        assert!(mime.contains("X-Order: 42"));
        assert!(!mime.contains("gone@x.com"), "suppressed recipients are not in To");
    }

    #[tokio::test]
    async fn rejects_bad_requests() {
        let t = TestApp::new().await;
        t.template("welcome").await;
        let cases = [
            (
                json!({"template": "welcome", "to": ["not-an-address"], "variables": {"name": "x"}}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({"template": "welcome", "to": [], "variables": {"name": "x"}}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (json!({"template": "nope", "to": ["a@x.com"]}), StatusCode::NOT_FOUND),
            (json!({"template": "welcome", "to": ["a@x.com"]}), StatusCode::UNPROCESSABLE_ENTITY),
            (
                json!({"template": "welcome", "to": ["a@x.com"], "variables": {"name": "x"}, "from": "a@other.org"}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({"template": "welcome", "to": ["a@x.com"], "variables": {"name": "x"}, "from": "a@news.example.com"}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({"template": "welcome", "to": ["a@x.com"], "variables": {"name": "x"}, "headers": {"Bcc": "x@y.com"}}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({"template": "welcome", "to": ["a@x.com", "b@x.com"], "variables": {"name": "x"}, "stream": "broadcast"}),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (json!({"template": "welcome", "to": ["a@x.com"], "bogus": 1}), StatusCode::UNPROCESSABLE_ENTITY),
        ];
        for (body, want) in cases {
            let (s, v) = t.call(Method::POST, "/v1/messages", Some(body.clone())).await;
            assert_eq!(s, want, "{body} -> {v}");
        }
        let (_, v) = t
            .call(
                Method::POST,
                "/v1/messages",
                Some(json!({"template": "welcome", "to": ["bad", "a@x.com"], "variables": {"name": "x"}})),
            )
            .await;
        assert_eq!(v["error"]["details"][0]["address"], "bad");
    }

    #[tokio::test]
    async fn broadcast_stream_gets_unsubscribe_headers() {
        let t = TestApp::new().await;
        t.template("news").await;
        let (s, v) = t
            .call(Method::POST, "/v1/messages", Some(json!({"template": "news", "to": ["a@x.com"], "variables": {"name": "x"}, "stream": "broadcast"})))
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        let id = v["message_id"].as_str().unwrap();
        let mime = String::from_utf8(t.db.message_mime(id).await.unwrap().unwrap()).unwrap();
        assert!(mime.contains("List-Unsubscribe: <https://sigill.test/u/"));
        assert!(mime.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
        assert!(
            mime.contains("From: <news@news.example.com>") || mime.contains("From: news@news.example.com")
        );
        let m = t.db.get_message(id).await.unwrap().unwrap();
        assert_eq!(m.stream, Stream::Broadcast);
    }
}
