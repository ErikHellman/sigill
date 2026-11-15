//! The webhook worker: POSTs queued events from `webhook_outbox` to each app's URL, signed
//! with the app's secret, and retries failures with exponential backoff.
//!
//! Each request carries `Sigill-Signature: t=<unix seconds>,v1=<hex>`, where the hex is
//! `HMAC-SHA256(secret, "<t>.<body>")` and the secret is the one `sigill app set-webhook`
//! prints. Receivers should check the signature and reject old timestamps.

use std::sync::Arc;
use std::time::Duration;

use sigill_core::config::WebhookConfig;
use sigill_core::secrets::{Secrets, hmac_sha256};
use sigill_core::{now_ms, telemetry};
use sigill_store::Store;
use sigill_store::webhooks::OutboxItem;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// First retry delay; doubles per attempt up to [`MAX_DELAY_MS`].
pub const BASE_DELAY_MS: i64 = 30_000;
pub const MAX_DELAY_MS: i64 = 6 * sigill_core::HOUR_MS;
const BATCH: i64 = 50;
const IDLE_POLL: Duration = Duration::from_secs(1);

/// `t=<timestamp>,v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`.
pub fn signature(secret: &str, timestamp: i64, body: &str) -> String {
    let mac = hmac_sha256(secret.as_bytes(), format!("{timestamp}.{body}").as_bytes());
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    format!("t={timestamp},v1={hex}")
}

/// Delay before the next attempt after `attempts` failed ones (1-based).
pub fn retry_delay(attempts: i64) -> i64 {
    let exp = (attempts - 1).clamp(0, 20) as u32;
    BASE_DELAY_MS.saturating_mul(1 << exp).min(MAX_DELAY_MS)
}

#[derive(Clone)]
pub struct WebhookWorker {
    store: Store,
    secrets: Arc<Secrets>,
    client: reqwest::Client,
    max_attempts: i64,
}

impl WebhookWorker {
    pub fn new(store: Store, secrets: Secrets, cfg: &WebhookConfig) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sigill-webhook/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { store, secrets: Arc::new(secrets), client, max_attempts: cfg.max_attempts.max(1) })
    }

    /// Deliver webhooks until `token` is cancelled.
    pub async fn run(self, token: CancellationToken) {
        info!("webhook worker started");
        loop {
            let sent = match self.tick().await {
                Ok(n) => n,
                Err(e) => {
                    error!(error = %e, "webhook batch failed");
                    telemetry::capture_error(&e);
                    0
                }
            };
            if sent > 0 {
                continue;
            }
            let wait = match self.store.next_webhook_at().await {
                Ok(Some(t)) => Duration::from_millis((t - now_ms()).clamp(0, 1_000) as u64),
                _ => IDLE_POLL,
            };
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(wait.max(Duration::from_millis(50))) => {}
            }
        }
        info!("webhook worker stopped");
    }

    /// Send one batch of due webhooks concurrently. Returns how many were attempted.
    pub async fn tick(&self) -> sigill_store::Result<usize> {
        self.tick_at(now_ms()).await
    }

    /// [`Self::tick`] with an explicit clock, for tests.
    pub async fn tick_at(&self, now: i64) -> sigill_store::Result<usize> {
        let due = self.store.due_webhooks(now, BATCH).await?;
        let n = due.len();
        let mut set = JoinSet::new();
        for item in due {
            let this = self.clone();
            set.spawn(async move { this.deliver(item).await });
        }
        while let Some(r) = set.join_next().await {
            match r {
                Ok(Err(e)) => return Err(e),
                Err(e) => error!(error = %e, "webhook task panicked"),
                Ok(Ok(())) => {}
            }
        }
        Ok(n)
    }

    async fn deliver(&self, item: OutboxItem) -> sigill_store::Result<()> {
        let Some(url) = item.webhook_url.as_deref() else {
            // The app removed its webhook URL; nothing to deliver to.
            return self.store.webhook_done(item.id).await;
        };
        // Payloads carry recipient addresses: never send them over plain HTTP to another host.
        if !webhook_url_allowed(url) {
            warn!(outbox_id = item.id, app_id = %item.app_id, "webhook URL is not https; event dropped");
            return self.store.webhook_done(item.id).await;
        }
        let secret = self.secrets.webhook_secret(&item.app_id, item.webhook_secret_version);
        let ts = now_ms() / 1000;
        let result = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("sigill-signature", signature(&secret, ts, &item.payload))
            .body(item.payload.clone())
            .send()
            .await;
        let error = match result {
            Ok(res) if res.status().is_success() => {
                debug!(outbox_id = item.id, app_id = %item.app_id, "webhook delivered");
                return self.store.webhook_done(item.id).await;
            }
            Ok(res) => format!("HTTP {}", res.status().as_u16()),
            Err(e) => without_url(e).to_string(),
        };
        let attempts = item.attempts + 1;
        if attempts >= self.max_attempts {
            warn!(outbox_id = item.id, app_id = %item.app_id, attempts, error = %error, "webhook dropped");
            telemetry::track("webhook_dropped", &[("app_id", &item.app_id)]);
            return self.store.webhook_done(item.id).await;
        }
        debug!(outbox_id = item.id, app_id = %item.app_id, attempts, error = %error, "webhook failed, will retry");
        self.store.webhook_retry(item.id, now_ms() + retry_delay(attempts), &error).await
    }
}

/// Webhook URLs must be `https`. Plain `http` is allowed only to this machine (local
/// development and tests).
pub fn webhook_url_allowed(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else { return false };
    match u.scheme() {
        "https" => u.host_str().is_some(),
        "http" => matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

/// reqwest errors include the URL, which may carry an app's credentials.
fn without_url(e: reqwest::Error) -> reqwest::Error {
    e.without_url()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_format() {
        let s = signature("secret", 1_700_000_000, "{}");
        let (t, v1) = s.split_once(',').unwrap();
        assert_eq!(t, "t=1700000000");
        assert_eq!(v1.len(), 3 + 64);
        assert_ne!(s, signature("other", 1_700_000_000, "{}"));
    }

    #[test]
    fn only_https_or_local_urls() {
        assert!(webhook_url_allowed("https://app.example.com/hooks/sigill"));
        assert!(webhook_url_allowed("http://127.0.0.1:9000/hook"));
        assert!(webhook_url_allowed("http://localhost/hook"));
        assert!(!webhook_url_allowed("http://app.example.com/hook"));
        assert!(!webhook_url_allowed("ftp://app.example.com/hook"));
        assert!(!webhook_url_allowed("not a url"));
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(retry_delay(1), 30_000);
        assert_eq!(retry_delay(2), 60_000);
        assert_eq!(retry_delay(30), MAX_DELAY_MS);
    }
}
