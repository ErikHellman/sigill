//! The admin UI: server-rendered pages behind HTTP basic auth with `SIGILL_ADMIN_PASSWORD`.
//! Without a password the admin routes answer 404. Wrong passwords are counted per client
//! (and overall) and answered with 429 once a limit is reached, so the password cannot be
//! guessed at speed; see [`LoginThrottle`].

use askama::Template;
use axum::Form;
use axum::Router;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use serde::Deserialize;
use sigill_core::address::normalize;
use sigill_core::secrets::ct_eq;
use sigill_core::{Stream, SuppressionReason, SuppressionScope};

use crate::AppState;

pub(crate) mod throttle;
mod time;
pub use throttle::LoginThrottle;
pub use time::format_ms;

/// Passwords shorter than this are refused at startup.
pub const MIN_ADMIN_PASSWORD_LEN: usize = 16;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(|| async { Redirect::to("/admin/messages") }))
        .route("/admin/messages", get(messages))
        .route("/admin/messages/{id}", get(message))
        .route("/admin/suppressions", get(suppressions).post(add_suppression))
        .route("/admin/suppressions/delete", post(remove_suppression))
        .route("/admin/queue", get(queue))
        .route("/admin/dns", get(dns))
        .route("/admin/dmarc", get(dmarc))
}

/// Proof that the request carried the admin password. Also refuses cross-site form posts,
/// since browsers resend basic-auth credentials on their own.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let Some(password) = state.inner.admin_password.as_deref() else {
            return Err(StatusCode::NOT_FOUND.into_response());
        };
        let given = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b.trim()).ok())
            .and_then(|raw| String::from_utf8(raw).ok())
            .and_then(|s| s.split_once(':').map(|(_, p)| p.to_string()));
        let throttle = &state.inner.admin_logins;
        let client = throttle::client_key(parts);
        if throttle.blocked(&client) {
            return Err(
                (StatusCode::TOO_MANY_REQUESTS, "too many failed logins; try again later").into_response()
            );
        }
        if !given.as_ref().is_some_and(|g| ct_eq(g.as_bytes(), password.as_bytes())) {
            // A request without credentials is the browser asking for the prompt, not a guess.
            if given.is_some() {
                throttle.record_failure(&client);
                tracing::warn!("admin login failed");
            }
            let mut res = (StatusCode::UNAUTHORIZED, "authentication required").into_response();
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"sigill admin\""));
            return Err(res);
        }
        if parts.method != Method::GET && parts.method != Method::HEAD && !same_origin(parts) {
            return Err((StatusCode::FORBIDDEN, "cross-site request refused").into_response());
        }
        Ok(Admin)
    }
}

fn same_origin(parts: &Parts) -> bool {
    let h = |n: header::HeaderName| parts.headers.get(n).and_then(|v| v.to_str().ok());
    if let Some(site) = parts.headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site == "same-origin" || site == "none";
    }
    match (h(header::ORIGIN), h(header::HOST)) {
        (Some(origin), Some(host)) => origin.split_once("://").is_some_and(|(_, rest)| rest == host),
        // Non-browser clients send neither header.
        (None, _) => true,
        _ => false,
    }
}

fn render(t: impl Template) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "admin template failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn internal(e: sigill_store::Error) -> Response {
    tracing::error!(error = %e, "admin query failed");
    sigill_core::telemetry::capture_error(&e);
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

#[derive(Deserialize, Default)]
pub struct Search {
    #[serde(default)]
    q: String,
    notice: Option<String>,
}

struct MessageRow {
    id: String,
    created: String,
    app: String,
    stream: String,
    template: String,
    subject: String,
    recipients: i64,
    sent: i64,
    pending: i64,
    failed: i64,
}

#[derive(Template)]
#[template(path = "admin/messages.html")]
struct MessagesPage {
    nav: &'static str,
    q: String,
    rows: Vec<MessageRow>,
}

async fn messages(_: Admin, State(state): State<AppState>, Query(s): Query<Search>) -> Response {
    let rows = match state.store.search_messages(&s.q, 100).await {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    render(MessagesPage {
        nav: "messages",
        q: s.q,
        rows: rows
            .into_iter()
            .map(|m| MessageRow {
                created: format_ms(m.created_at),
                id: m.id,
                app: m.app_name,
                stream: m.stream,
                template: m.template_key,
                subject: m.subject,
                recipients: m.recipients,
                sent: m.sent,
                pending: m.pending,
                failed: m.failed,
            })
            .collect(),
    })
}

struct EventRow {
    at: String,
    kind: String,
    detail: String,
}

struct DeliveryRow {
    id: String,
    rcpt: String,
    status: String,
    attempts: i64,
    last_code: String,
    last_response: String,
    events: Vec<EventRow>,
}

#[derive(Template)]
#[template(path = "admin/message.html")]
struct MessagePage {
    nav: &'static str,
    id: String,
    subject: String,
    created: String,
    stream: String,
    from: String,
    template: String,
    idempotency_key: String,
    broadcast_id: String,
    has_body: bool,
    deliveries: Vec<DeliveryRow>,
}

async fn message(_: Admin, State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let load = async {
        let Some(m) = state.store.get_message(&id).await? else { return Ok(None) };
        let mut deliveries = Vec::new();
        for d in state.store.deliveries_for_message(&id).await? {
            let events = state.store.events_for_delivery(&d.id).await?;
            deliveries.push(DeliveryRow {
                id: d.id,
                rcpt: d.rcpt,
                status: d.status.to_string(),
                attempts: d.attempts,
                last_code: d.last_smtp_code.map(|c| c.to_string()).unwrap_or_default(),
                last_response: d.last_response.unwrap_or_default(),
                events: events
                    .into_iter()
                    .map(|e| EventRow {
                        at: format_ms(e.at),
                        kind: e.kind.to_string(),
                        detail: e.detail.unwrap_or_default(),
                    })
                    .collect(),
            });
        }
        Ok::<_, sigill_store::Error>(Some(MessagePage {
            nav: "messages",
            id: m.id,
            subject: m.subject,
            created: format_ms(m.created_at),
            stream: m.stream.to_string(),
            from: m.from_addr,
            template: format!("{} v{}", m.template_key, m.template_version),
            idempotency_key: m.idempotency_key.unwrap_or_default(),
            broadcast_id: m.broadcast_id.unwrap_or_default(),
            has_body: m.has_body,
            deliveries,
        }))
    };
    match load.await {
        Ok(Some(page)) => render(page),
        Ok(None) => (StatusCode::NOT_FOUND, "message not found").into_response(),
        Err(e) => internal(e),
    }
}

struct SuppressionRow {
    address: String,
    scope: String,
    reason: String,
    created: String,
    source: String,
}

#[derive(Template)]
#[template(path = "admin/suppressions.html")]
struct SuppressionsPage {
    nav: &'static str,
    q: String,
    notice: Option<String>,
    rows: Vec<SuppressionRow>,
}

async fn suppressions(_: Admin, State(state): State<AppState>, Query(s): Query<Search>) -> Response {
    let search = s.q.trim().to_ascii_lowercase();
    let rows = match state.store.list_suppressions(Some(&search), 200, 0).await {
        Ok(r) => r,
        Err(e) => return internal(e),
    };
    render(SuppressionsPage {
        nav: "suppressions",
        q: s.q,
        notice: s.notice.as_deref().and_then(notice_text),
        rows: rows
            .into_iter()
            .map(|r| SuppressionRow {
                address: r.address,
                scope: r.scope.to_string(),
                reason: r.reason.to_string(),
                created: format_ms(r.created_at),
                source: r.source_delivery_id.unwrap_or_default(),
            })
            .collect(),
    })
}

#[derive(Deserialize)]
struct SuppressionForm {
    address: String,
    scope: Option<SuppressionScope>,
}

/// Redirect back to the list with a notice code (codes, not text, so links cannot inject
/// arbitrary messages).
fn back(code: &str) -> Response {
    Redirect::to(&format!("/admin/suppressions?notice={code}")).into_response()
}

fn notice_text(code: &str) -> Option<String> {
    Some(
        match code {
            "added" => "Suppression added.",
            "removed" => "Suppression removed.",
            "invalid" => "Not a valid address.",
            "missing" => "No such suppression.",
            _ => return None,
        }
        .to_string(),
    )
}

async fn add_suppression(
    _: Admin,
    State(state): State<AppState>,
    Form(f): Form<SuppressionForm>,
) -> Response {
    let Some(address) = normalize(&f.address) else { return back("invalid") };
    let scope = f.scope.unwrap_or(SuppressionScope::All);
    match state.store.add_suppression(&address, scope, SuppressionReason::Manual, None).await {
        Ok(()) => {
            tracing::info!("suppression added in admin UI");
            back("added")
        }
        Err(e) => internal(e),
    }
}

async fn remove_suppression(
    _: Admin,
    State(state): State<AppState>,
    Form(f): Form<SuppressionForm>,
) -> Response {
    let Some(address) = normalize(&f.address) else { return back("invalid") };
    match state.store.remove_suppression(&address).await {
        Ok(0) => back("missing"),
        Ok(_) => {
            tracing::info!("suppression removed in admin UI");
            back("removed")
        }
        Err(e) => internal(e),
    }
}

#[derive(Template)]
#[template(path = "admin/queue.html")]
struct QueuePage {
    nav: &'static str,
    counts: Vec<(String, String, i64)>,
    next_due: String,
    webhook_backlog: i64,
    broadcasts: Vec<(String, String, String, i64)>,
    throttles: Vec<(String, i64, i64, String)>,
}

async fn queue(_: Admin, State(state): State<AppState>) -> Response {
    let load = async {
        let now = sigill_core::now_ms();
        let counts = state.store.queue_counts().await?;
        let next = state.store.next_due_at().await?;
        Ok::<_, sigill_store::Error>(QueuePage {
            nav: "queue",
            counts: counts.into_iter().map(|(s, st, n)| (s.to_string(), st.to_string(), n)).collect(),
            next_due: match next {
                Some(t) if t <= now => "now".into(),
                Some(t) => format_ms(t),
                None => "-".into(),
            },
            webhook_backlog: state.store.webhook_backlog().await?,
            broadcasts: state
                .store
                .sending_broadcasts()
                .await?
                .into_iter()
                .map(|b| (b.name, b.list, b.started_at.map(format_ms).unwrap_or_default(), b.audience_count))
                .collect(),
            throttles: state
                .store
                .throttles()
                .await?
                .into_iter()
                .map(|t| {
                    let backoff = t.backoff_until.filter(|u| *u > now).map(format_ms).unwrap_or_default();
                    (t.rcpt_domain, t.max_conns, t.max_per_minute, backoff)
                })
                .collect(),
        })
    };
    match load.await {
        Ok(p) => render(p),
        Err(e) => internal(e),
    }
}

struct DnsDomain {
    domain: String,
    stream: String,
    return_path: String,
    verified: String,
    records: Vec<(String, &'static str, String)>,
}

#[derive(Template)]
#[template(path = "admin/dns.html")]
struct DnsPage {
    nav: &'static str,
    domains: Vec<DnsDomain>,
    ips: Vec<(String, String, String)>,
}

async fn dns(_: Admin, State(state): State<AppState>) -> Response {
    let stored = match state.store.sending_domains().await {
        Ok(d) => d,
        Err(e) => return internal(e),
    };
    let cfg = &state.config;
    let mut domains = Vec::new();
    for d in &cfg.domains {
        let name = d.name.to_ascii_lowercase();
        let rp = d.return_path_domain.to_ascii_lowercase();
        let mut records: Vec<(String, &'static str, String)> = Vec::new();
        if let Some(keys) = state.inner.signers.get(&d.name) {
            for (selector, txt) in &keys.dns_records {
                records.push((format!("{selector}._domainkey.{name}"), "TXT", txt.clone()));
            }
        }
        let ips: Vec<String> = cfg.streams.get(d.stream).ips.iter().map(|ip| format!("ip4:{ip}")).collect();
        let spf = if ips.is_empty() {
            "v=spf1 ip4:<sending IP> -all".to_string()
        } else {
            format!("v=spf1 {} -all", ips.join(" "))
        };
        records.push((rp.clone(), "TXT", spf));
        records.push((rp.clone(), "MX", format!("10 {}.", cfg.bounce.hostname)));
        records.push((
            format!("_dmarc.{name}"),
            "TXT",
            format!("v=DMARC1; p=none; rua=mailto:{}@{rp}; adkim=r; aspf=r", cfg.bounce.dmarc_local_part),
        ));
        let verified = stored.iter().find(|s| s.domain == name).and_then(|s| s.verified_at);
        domains.push(DnsDomain {
            verified: verified.map(format_ms).unwrap_or_default(),
            domain: name,
            stream: d.stream.to_string(),
            return_path: rp,
            records,
        });
    }
    let ips = Stream::ALL
        .iter()
        .flat_map(|s| {
            let c = cfg.streams.get(*s);
            c.ips.iter().map(move |ip| (s.to_string(), ip.to_string(), c.helo_hostname.clone()))
        })
        .collect();
    render(DnsPage { nav: "dns", domains, ips })
}

struct ReportRow {
    org: String,
    domain: String,
    period: String,
    policy: String,
    total: i64,
    fail: i64,
}

struct FailureRow {
    org: String,
    header_from: String,
    ip: String,
    count: i64,
    disposition: String,
    dkim: String,
    spf: String,
}

#[derive(Template)]
#[template(path = "admin/dmarc.html")]
struct DmarcPage {
    nav: &'static str,
    reports: Vec<ReportRow>,
    failures: Vec<FailureRow>,
}

async fn dmarc(_: Admin, State(state): State<AppState>) -> Response {
    let load = async {
        let reports = state.store.recent_dmarc_reports(50).await?;
        let failures = state.store.dmarc_failures(100).await?;
        Ok::<_, sigill_store::Error>(DmarcPage {
            nav: "dmarc",
            reports: reports
                .into_iter()
                .map(|r| ReportRow {
                    period: format!("{} – {}", format_ms(r.date_begin), format_ms(r.date_end)),
                    org: r.org_name,
                    domain: r.domain,
                    policy: r.policy,
                    total: r.total_count,
                    fail: r.fail_count,
                })
                .collect(),
            failures: failures
                .into_iter()
                .map(|(r, x)| FailureRow {
                    org: r.org_name,
                    header_from: x.header_from,
                    ip: x.source_ip,
                    count: x.count,
                    disposition: x.disposition,
                    dkim: x.dkim_result,
                    spf: x.spf_result,
                })
                .collect(),
        })
    };
    match load.await {
        Ok(p) => render(p),
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests;
