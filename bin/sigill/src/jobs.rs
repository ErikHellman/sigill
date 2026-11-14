//! Periodic maintenance: retention with incremental vacuum, backlog telemetry and health
//! checks. A failed health check logs an error, which the Vaka layer turns into an issue.

use std::sync::Arc;
use std::time::Duration;

use sigill_core::config::AlertConfig;
use sigill_core::{Config, telemetry};
use sigill_store::Store;
use tokio_util::sync::CancellationToken;

const TICK: Duration = Duration::from_secs(60);
/// Retention runs once an hour (and once shortly after start).
const RETENTION_EVERY: u32 = 60;
/// Health checks run every 15 minutes.
const HEALTH_EVERY: u32 = 15;

#[derive(Debug, PartialEq)]
pub enum Problem {
    Backlog(i64),
    BounceRate(f64),
    DeferSpike(String, i64),
}

/// Compare the last hour (and the current queue) with the alert thresholds.
pub async fn health(store: &Store, alerts: &AlertConfig) -> Vec<Problem> {
    let mut out = Vec::new();
    let backlog: i64 = match store.queue_counts().await {
        Ok(c) => c.iter().map(|(_, _, n)| n).sum(),
        Err(_) => 0,
    };
    if backlog > alerts.queue_backlog {
        out.push(Problem::Backlog(backlog));
    }
    if let Ok(stats) = store.recent_stats(sigill_core::now_ms() - sigill_core::HOUR_MS).await {
        let rate = stats.bounce_rate_percent();
        if stats.sent + stats.bounced >= alerts.bounce_rate_min_sample && rate > alerts.bounce_rate_percent {
            out.push(Problem::BounceRate(rate));
        }
        for (domain, n) in stats.deferred_by_domain {
            if n > alerts.defer_spike_per_domain {
                out.push(Problem::DeferSpike(domain, n));
            }
        }
    }
    out
}

pub async fn maintenance(store: Store, config: Arc<Config>, token: CancellationToken) {
    let mut ticks: u32 = RETENTION_EVERY - 1;
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(TICK) => {}
        }
        ticks += 1;
        if let Ok(n) = store.webhook_backlog().await {
            telemetry::track("webhook_backlog", &[("depth", &n.to_string())]);
        }
        if ticks.is_multiple_of(HEALTH_EVERY) {
            for problem in health(&store, &config.alerts).await {
                // Stable messages so each kind groups into one Vaka issue.
                match problem {
                    Problem::Backlog(n) => tracing::error!(waiting = n, "queue backlog above threshold"),
                    Problem::BounceRate(pct) => {
                        tracing::error!(percent = format!("{pct:.1}"), "bounce rate above threshold")
                    }
                    Problem::DeferSpike(domain, n) => {
                        tracing::error!(rcpt_domain = %domain, deferrals = n, "defer spike for a recipient domain")
                    }
                }
            }
        }
        if ticks >= RETENTION_EVERY {
            ticks = 0;
            let r = &config.retention;
            match store.run_retention(r.message_body_days, r.event_days).await {
                Ok(rep) => tracing::info!(
                    bodies_cleared = rep.bodies_cleared,
                    events_deleted = rep.events_deleted,
                    "retention run"
                ),
                Err(e) => {
                    tracing::error!(error = %e, "retention run failed");
                    telemetry::capture_error(&e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sigill_core::Stream;
    use sigill_core::config::AlertConfig;
    use sigill_store::messages::{NewDelivery, NewMessage};
    use sigill_store::queue::Outcome;

    use super::{Problem, health};

    #[tokio::test]
    async fn flags_bounce_rate_and_defer_spikes() {
        let db = sigill_store::testing::test_db().await;
        db.create_app("a", "a", "h", None, Stream::Transactional).await.unwrap();
        let deliveries: Vec<NewDelivery> = (0..4)
            .map(|i| NewDelivery {
                id: format!("d{i}"),
                rcpt: format!("u{i}@x.test"),
                rcpt_domain: "x.test".into(),
                suppressed: false,
            })
            .collect();
        let msg = NewMessage {
            id: "m",
            app_id: "a",
            idempotency_key: None,
            stream: Stream::Transactional,
            template_key: "t",
            template_version: 1,
            from_addr: "f@mail.example.com",
            subject: "s",
            rendered_mime: b"x",
            broadcast_id: None,
            priority: 0,
            not_before: None,
        };
        db.insert_message(&msg, &deliveries).await.unwrap();
        db.complete(&[
            ("d0".into(), Outcome::Sent { code: 250, response: "OK".into() }),
            ("d1".into(), Outcome::Bounced { code: Some(550), response: "5.1.1".into(), suppress: None }),
            ("d2".into(), Outcome::Deferred { code: Some(451), response: "x".into(), next_attempt_at: 0 }),
            ("d3".into(), Outcome::Deferred { code: Some(451), response: "x".into(), next_attempt_at: 0 }),
        ])
        .await
        .unwrap();
        let strict = AlertConfig {
            queue_backlog: 1,
            bounce_rate_percent: 10.0,
            bounce_rate_min_sample: 2,
            defer_spike_per_domain: 1,
        };
        assert_eq!(
            health(&db, &strict).await,
            vec![Problem::Backlog(2), Problem::BounceRate(50.0), Problem::DeferSpike("x.test".into(), 2)]
        );
        assert!(health(&db, &AlertConfig::default()).await.is_empty());
    }
}
