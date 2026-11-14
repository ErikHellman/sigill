//! Turning a send request into a stored, rendered and signed message with one delivery per
//! recipient. Used by `POST /v1/messages` and by broadcasts.

use std::collections::BTreeMap;

use sigill_core::address::Address;
use sigill_core::{DeliveryStatus, Stream, new_id, now_ms, telemetry};
use sigill_render::{MimeParts, TemplateSource, build_mime};
use sigill_store::apps::App;
use sigill_store::messages::{Inserted, NewDelivery, NewMessage};
use sigill_store::templates::Template;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

pub const MAX_RECIPIENTS: usize = 50;

pub struct SendRequest<'a> {
    pub app: &'a App,
    pub template: &'a Template,
    pub to: &'a [String],
    pub from: Option<&'a str>,
    pub from_name: Option<&'a str>,
    pub variables: &'a serde_json::Value,
    pub stream: Stream,
    pub headers: &'a [(String, String)],
    pub idempotency_key: Option<&'a str>,
    pub broadcast_id: Option<&'a str>,
    pub not_before: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueuedDelivery {
    pub id: String,
    pub to: String,
    pub status: DeliveryStatus,
}

#[derive(Debug)]
pub enum SendOutcome {
    Created { message_id: String, deliveries: Vec<QueuedDelivery> },
    Existing { message_id: String },
}

/// Validate and dedupe recipients. Errors list every invalid address.
pub fn parse_recipients(to: &[String]) -> ApiResult<Vec<Address>> {
    if to.is_empty() {
        return Err(ApiError::invalid("`to` needs at least one address"));
    }
    if to.len() > MAX_RECIPIENTS {
        return Err(ApiError::invalid(format!("at most {MAX_RECIPIENTS} recipients per message")));
    }
    let mut seen = BTreeMap::new();
    let mut invalid = Vec::new();
    for raw in to {
        match Address::parse(raw) {
            Ok(a) => {
                seen.entry(a.normalized()).or_insert(a);
            }
            Err(e) => invalid.push(serde_json::json!({"address": raw, "reason": e.to_string()})),
        }
    }
    if !invalid.is_empty() {
        return Err(ApiError::invalid("invalid recipient address").with_details(serde_json::json!(invalid)));
    }
    Ok(seen.into_values().collect())
}

pub async fn send(state: &AppState, req: SendRequest<'_>) -> ApiResult<SendOutcome> {
    if let Some(key) = req.idempotency_key
        && let Some(message_id) = state.store.message_by_idempotency(&req.app.id, key).await?
    {
        return Ok(SendOutcome::Existing { message_id });
    }
    let recipients = parse_recipients(req.to)?;
    if req.stream == Stream::Broadcast && recipients.len() > 1 {
        return Err(ApiError::invalid(
            "broadcast-stream messages take one recipient each (each gets its own unsubscribe link)",
        ));
    }

    let stream_cfg = state.config.streams.get(req.stream);
    let from = req
        .from
        .or(stream_cfg.default_from.as_deref())
        .ok_or_else(|| ApiError::invalid("`from` is required (no default sender for this stream)"))?;
    let from_addr = Address::parse(from).map_err(|e| ApiError::invalid(format!("invalid `from`: {e}")))?;
    let domain = state.config.domain(from_addr.domain()).ok_or_else(|| {
        ApiError::invalid(format!("`from` domain {} is not a sending domain", from_addr.domain()))
    })?;
    if domain.stream != req.stream {
        return Err(ApiError::invalid(format!(
            "`from` domain {} is configured for the {} stream",
            domain.name, domain.stream
        )));
    }

    // Suppressed recipients are recorded but never sent.
    let mut deliveries = Vec::with_capacity(recipients.len());
    for a in &recipients {
        let suppressed = state.store.is_suppressed(&a.normalized(), req.stream).await?;
        deliveries.push(NewDelivery {
            id: new_id(),
            rcpt: a.to_string(),
            rcpt_domain: a.domain().to_string(),
            suppressed,
        });
    }

    let source = TemplateSource {
        subject: &req.template.subject_tpl,
        html: &req.template.html_tpl,
        text: &req.template.text_tpl,
    };
    let unsubscribe_url = (req.stream == Stream::Broadcast).then(|| {
        format!(
            "{}/u/{}",
            state.config.server.public_url.trim_end_matches('/'),
            crate::unsubscribe::token(&state.inner.secrets.unsubscribe_key(), &deliveries[0].id)
        )
    });
    // Broadcast templates can show the unsubscribe link as `{{ unsubscribe_url }}`.
    let rendered = match (&unsubscribe_url, req.variables) {
        (Some(url), serde_json::Value::Object(vars)) if !vars.contains_key("unsubscribe_url") => {
            let mut vars = vars.clone();
            vars.insert("unsubscribe_url".into(), url.clone().into());
            sigill_render::render(&source, &serde_json::Value::Object(vars))?
        }
        _ => sigill_render::render(&source, req.variables)?,
    };
    let message_id = new_id();
    let to: Vec<String> = deliveries.iter().filter(|d| !d.suppressed).map(|d| d.rcpt.clone()).collect();
    let to_header = if to.is_empty() { vec![deliveries[0].rcpt.clone()] } else { to };
    let mime = build_mime(&MimeParts {
        message_id: &message_id,
        from_name: req.from_name,
        from: &from_addr.to_string(),
        to: &to_header,
        subject: &rendered.subject,
        html: &rendered.html,
        text: &rendered.text,
        headers: req.headers,
        list_unsubscribe: unsubscribe_url.as_deref(),
        date: now_ms() / 1000,
    })?;
    let signed = state.inner.signers.sign(&domain.name, &mime).map_err(ApiError::internal)?;

    let inserted = state
        .store
        .insert_message(
            &NewMessage {
                id: &message_id,
                app_id: &req.app.id,
                idempotency_key: req.idempotency_key,
                stream: req.stream,
                template_key: &req.template.key,
                template_version: req.template.version,
                from_addr: &from_addr.to_string(),
                subject: &rendered.subject,
                rendered_mime: &signed,
                broadcast_id: req.broadcast_id,
                priority: stream_cfg.priority,
                not_before: req.not_before,
            },
            &deliveries,
        )
        .await?;
    if let Inserted::Existing(message_id) = inserted {
        return Ok(SendOutcome::Existing { message_id });
    }
    state.inner.wake.notify_one();
    for d in &deliveries {
        tracing::info!(message_id = %message_id, delivery_id = %d.id, rcpt_domain = %d.rcpt_domain,
            suppressed = d.suppressed, "delivery queued");
        let kind = if d.suppressed { "delivery_suppressed" } else { "message_queued" };
        telemetry::track(kind, &[("stream", req.stream.as_str()), ("rcpt_domain", &d.rcpt_domain)]);
    }
    Ok(SendOutcome::Created {
        message_id,
        deliveries: deliveries
            .into_iter()
            .map(|d| QueuedDelivery {
                status: if d.suppressed { DeliveryStatus::Suppressed } else { DeliveryStatus::Queued },
                id: d.id,
                to: d.rcpt,
            })
            .collect(),
    })
}
