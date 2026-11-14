//! Broadcast endpoints and the scheduler that turns a started broadcast into one message per
//! audience member, spread out by the hourly ramp-up limit.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sigill_core::address::Address;
use sigill_core::{HOUR_MS, Stream, now_ms, telemetry};
use sigill_store::broadcasts::{AudienceMember, Broadcast, NewBroadcast, segment_matches};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::AppState;
use crate::auth::AuthApp;
use crate::contacts::check_list;
use crate::error::{ApiError, ApiResult};
use crate::send::{SendRequest, send};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBroadcast {
    pub name: String,
    pub template: String,
    /// Template version; the latest at send time when left out.
    pub version: Option<i64>,
    pub list: String,
    pub from: Option<String>,
    #[serde(default)]
    pub variables: Value,
    /// Attribute filter: `{"plan": "pro", "country": ["SE", "NO"]}`.
    #[serde(default)]
    pub segment: Value,
}

async fn broadcast_json(state: &AppState, b: &Broadcast) -> ApiResult<Value> {
    let stats = state.store.broadcast_stats(&b.id).await?;
    let mut v = serde_json::to_value(b).map_err(ApiError::internal)?;
    v["stats"] = serde_json::to_value(stats).map_err(ApiError::internal)?;
    Ok(v)
}

pub async fn create(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Json(req): Json<CreateBroadcast>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if req.name.trim().is_empty() || req.name.len() > 200 {
        return Err(ApiError::invalid("`name` must be 1 to 200 characters"));
    }
    check_list(&req.list)?;
    state
        .store
        .get_template(&app.id, &req.template, req.version)
        .await?
        .ok_or_else(|| ApiError::not_found("template"))?;
    let from = req.from.as_deref().or(state.config.streams.broadcast.default_from.as_deref());
    let from = from.ok_or_else(|| ApiError::invalid("`from` is required (no default broadcast sender)"))?;
    let addr = Address::parse(from).map_err(|e| ApiError::invalid(format!("invalid `from`: {e}")))?;
    match state.config.domain(addr.domain()) {
        Some(d) if d.stream == Stream::Broadcast => {}
        Some(_) => return Err(ApiError::invalid("`from` domain is not configured for the broadcast stream")),
        None => return Err(ApiError::invalid("`from` domain is not a sending domain")),
    }
    let variables = match req.variables {
        Value::Null => json!({}),
        v @ Value::Object(_) => v,
        _ => return Err(ApiError::invalid("`variables` must be an object")),
    };
    let segment = match req.segment {
        Value::Null => json!({}),
        v @ Value::Object(_) => v,
        _ => return Err(ApiError::invalid("`segment` must be an object")),
    };
    let from = addr.to_string();
    let b = state
        .store
        .create_broadcast(&NewBroadcast {
            app_id: &app.id,
            name: req.name.trim(),
            template_key: &req.template,
            template_version: req.version,
            list: &req.list,
            from_addr: Some(&from),
            variables: &variables,
            segment_query: &segment,
            scheduled_at: None,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(broadcast_json(&state, &b).await?)))
}

pub async fn get(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let b = state.store.get_broadcast(&app.id, &id).await?.ok_or_else(|| ApiError::not_found("broadcast"))?;
    Ok(Json(broadcast_json(&state, &b).await?))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendBroadcast {
    /// Start time (unix ms); now when left out.
    pub at: Option<i64>,
}

pub async fn send_broadcast(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
    body: Option<Json<SendBroadcast>>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let at = body.and_then(|Json(b)| b.at).unwrap_or_else(now_ms);
    let b = state.store.schedule_broadcast(&app.id, &id, at).await?;
    info!(broadcast_id = %b.id, at, "broadcast scheduled");
    Ok((StatusCode::ACCEPTED, Json(broadcast_json(&state, &b).await?)))
}

pub async fn cancel(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let b = state.store.cancel_broadcast(&app.id, &id).await?;
    Ok(Json(broadcast_json(&state, &b).await?))
}

/// Starts due broadcasts and marks finished ones.
pub struct Scheduler {
    state: AppState,
    interval: Duration,
}

impl Scheduler {
    pub fn new(state: AppState) -> Self {
        Self { state, interval: Duration::from_secs(5) }
    }

    pub async fn run(self, token: CancellationToken) {
        // Finish materialising broadcasts interrupted by a restart; idempotency keys make
        // this safe to repeat.
        match self.state.store.sending_broadcasts().await {
            Ok(list) => {
                for b in list {
                    if let Err(e) = self.materialise(&b).await {
                        error!(broadcast_id = %b.id, error = %e.message, "resuming broadcast failed");
                    }
                }
            }
            Err(e) => error!(error = %e, "listing sending broadcasts failed"),
        }
        loop {
            if let Err(e) = self.tick(now_ms()).await {
                error!(error = %e.message, "broadcast scheduler tick failed");
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(self.interval) => {}
            }
        }
    }

    /// Start every due broadcast, then mark drained ones finished.
    pub async fn tick(&self, now: i64) -> ApiResult<()> {
        for b in self.state.store.due_broadcasts(now).await? {
            let audience = self.audience(&b).await?;
            self.state.store.mark_broadcast_sending(&b.id, audience.len() as i64).await?;
            info!(broadcast_id = %b.id, audience = audience.len(), "broadcast started");
            telemetry::track("broadcast_started", &[("audience", &audience.len().to_string())]);
            let Some(b) = self.state.store.get_broadcast(&b.app_id, &b.id).await? else { continue };
            self.queue(&b, &audience).await?;
        }
        for b in self.state.store.finish_broadcasts().await? {
            info!(broadcast_id = %b.id, sent = b.sent_count, "broadcast finished");
            telemetry::track(
                "broadcast_finished",
                &[("audience", &b.audience_count.to_string()), ("sent", &b.sent_count.to_string())],
            );
        }
        Ok(())
    }

    async fn audience(&self, b: &Broadcast) -> ApiResult<Vec<AudienceMember>> {
        let all = self.state.store.broadcast_audience(&b.app_id, &b.list).await?;
        Ok(all.into_iter().filter(|m| segment_matches(&b.segment_query, &m.attributes)).collect())
    }

    async fn materialise(&self, b: &Broadcast) -> ApiResult<()> {
        let audience = self.audience(b).await?;
        self.queue(b, &audience).await
    }

    /// Queue one message per member. Member `i` may go out at
    /// `started_at + i * (1 hour / max_per_hour)`.
    async fn queue(&self, b: &Broadcast, audience: &[AudienceMember]) -> ApiResult<()> {
        let state = &self.state;
        let app = state.store.get_app(&b.app_id).await?.ok_or_else(|| ApiError::not_found("app"))?;
        let Some(template) = state.store.get_template(&b.app_id, &b.template_key, b.template_version).await?
        else {
            warn!(broadcast_id = %b.id, "broadcast template is gone; nothing queued");
            return Ok(());
        };
        let start = b.started_at.unwrap_or_else(now_ms);
        let spacing = HOUR_MS as f64 / state.config.broadcast.max_per_hour.max(1) as f64;
        let mut failed = 0usize;
        for (i, m) in audience.iter().enumerate() {
            let mut vars = b.variables.clone();
            if !vars.is_object() {
                vars = json!({});
            }
            vars["contact"] = json!({"email": m.email, "name": m.name, "attributes": m.attributes});
            let key = format!("broadcast:{}:{}", b.id, m.contact_id);
            let not_before = start + (i as f64 * spacing) as i64;
            let to = [m.email.clone()];
            let r = send(
                state,
                SendRequest {
                    app: &app,
                    template: &template,
                    to: &to,
                    from: b.from_addr.as_deref(),
                    from_name: None,
                    variables: &vars,
                    stream: Stream::Broadcast,
                    headers: &[],
                    idempotency_key: Some(&key),
                    broadcast_id: Some(&b.id),
                    not_before: Some(not_before),
                },
            )
            .await;
            if let Err(e) = r {
                failed += 1;
                warn!(broadcast_id = %b.id, contact_id = %m.contact_id, error = %e.message, "broadcast message not queued");
            }
        }
        if failed > 0 {
            warn!(broadcast_id = %b.id, failed, "some broadcast messages could not be queued");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use serde_json::json;
    use sigill_core::{DeliveryStatus, Stream, now_ms};

    use super::Scheduler;
    use crate::testing::TestApp;

    async fn contact(t: &TestApp, email: &str, plan: &str, lists: &[&str]) -> String {
        let (s, v) = t
            .call(
                Method::POST,
                "/v1/contacts",
                Some(json!({"email": email, "name": "N", "attributes": {"plan": plan}, "lists": lists})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn broadcast_end_to_end() {
        let mut cfg = sigill_testkit::config();
        cfg.broadcast.max_per_hour = 3600; // one per second
        let t = TestApp::with_config(cfg).await;
        let (s, _) = t
            .call(
                Method::PUT,
                "/v1/templates/news",
                Some(json!({
                    "subject": "{{ title }}",
                    "html": "<p>Hi {{ contact.name }}</p><a href=\"{{ unsubscribe_url }}\">unsubscribe</a>",
                    "text": "Hi {{ contact.name }} {{ unsubscribe_url }}",
                })),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED);
        contact(&t, "a@x.test", "pro", &["news"]).await;
        contact(&t, "b@x.test", "free", &["news"]).await;
        contact(&t, "c@x.test", "pro", &["news"]).await;
        contact(&t, "d@x.test", "pro", &["other"]).await;
        t.call(Method::POST, "/v1/suppressions", Some(json!({"address": "c@x.test", "scope": "broadcast"})))
            .await;

        // The from domain must be the broadcast one.
        let (s, _) = t
            .call(
                Method::POST,
                "/v1/broadcasts",
                Some(json!({"name": "N", "template": "news", "list": "news", "from": "x@mail.example.com"})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        let (s, b) = t
            .call(
                Method::POST,
                "/v1/broadcasts",
                Some(json!({"name": "November", "template": "news", "list": "news",
                            "variables": {"title": "News"}, "segment": {"plan": ["pro"]}})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["status"], "draft");
        let id = b["id"].as_str().unwrap().to_string();

        let (s, b) = t.call(Method::POST, &format!("/v1/broadcasts/{id}/send"), None).await;
        assert_eq!((s, &b["status"]), (StatusCode::ACCEPTED, &json!("scheduled")));
        let (s, _) = t.call(Method::POST, &format!("/v1/broadcasts/{id}/send"), None).await;
        assert_eq!(s, StatusCode::CONFLICT);

        let scheduler = Scheduler::new(t.state.clone());
        scheduler.tick(now_ms() + 10).await.unwrap();
        let (_, b) = t.call(Method::GET, &format!("/v1/broadcasts/{id}"), None).await;
        assert_eq!(b["status"], "sending");
        // Only a@ matches: b@ is on the free plan, c@ is suppressed, d@ has no consent.
        assert_eq!(b["audience_count"], 1);
        assert_eq!(b["stats"]["pending"], 1);

        let claimed = t.db.claim_due(Stream::Broadcast, now_ms() + 10, 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].rcpt, "a@x.test");
        let mime =
            String::from_utf8(t.db.message_mime(&claimed[0].message_id).await.unwrap().unwrap()).unwrap();
        assert!(mime.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
        assert!(mime.contains("List-Unsubscribe: <https://sigill.test/u/"));

        // Re-running materialisation (as after a restart) queues nothing new.
        for b in t.db.sending_broadcasts().await.unwrap() {
            scheduler.materialise(&b).await.unwrap();
        }
        assert_eq!(t.db.queue_depth(Stream::Broadcast).await.unwrap(), 1);

        t.db.complete(&[(
            claimed[0].id.clone(),
            sigill_store::queue::Outcome::Sent { code: 250, response: "OK".into() },
        )])
        .await
        .unwrap();
        scheduler.tick(now_ms()).await.unwrap();
        let (_, b) = t.call(Method::GET, &format!("/v1/broadcasts/{id}"), None).await;
        assert_eq!((b["status"].as_str(), b["sent_count"].as_i64()), (Some("finished"), Some(1)));
        assert_eq!(b["stats"]["sent"], 1);
        let d = t.db.get_delivery(&claimed[0].id).await.unwrap().unwrap();
        assert_eq!(d.status, DeliveryStatus::Sent);
    }

    #[tokio::test]
    async fn ramp_up_spreads_messages() {
        let mut cfg = sigill_testkit::config();
        cfg.broadcast.max_per_hour = 2; // 30 minutes apart
        let t = TestApp::with_config(cfg).await;
        t.template("news").await;
        for i in 0..3 {
            contact(&t, &format!("u{i}@x.test"), "pro", &["news"]).await;
        }
        let (_, b) = t
            .call(
                Method::POST,
                "/v1/broadcasts",
                Some(json!({"name": "R", "template": "news", "list": "news", "variables": {"name": "x"}})),
            )
            .await;
        let id = b["id"].as_str().unwrap();
        t.call(Method::POST, &format!("/v1/broadcasts/{id}/send"), Some(json!({"at": 0}))).await;
        Scheduler::new(t.state.clone()).tick(now_ms()).await.unwrap();
        // Only the first is due now; the others 30 and 60 minutes later.
        assert_eq!(t.db.claim_due(Stream::Broadcast, now_ms() + 1000, 10).await.unwrap().len(), 1);
        let later = now_ms() + 31 * 60_000;
        assert_eq!(t.db.claim_due(Stream::Broadcast, later, 10).await.unwrap().len(), 1);

        let (s, _) = t.call(Method::POST, &format!("/v1/broadcasts/{id}/cancel"), None).await;
        assert_eq!(s, StatusCode::CONFLICT, "a sending broadcast cannot be cancelled");
    }
}
