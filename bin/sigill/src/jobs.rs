//! Periodic maintenance: retention with incremental vacuum, and backlog telemetry.

use std::sync::Arc;
use std::time::Duration;

use sigill_core::{Config, telemetry};
use sigill_store::Store;
use tokio_util::sync::CancellationToken;

const TICK: Duration = Duration::from_secs(60);
/// Retention runs once an hour (and once shortly after start).
const RETENTION_EVERY: u32 = 60;

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
