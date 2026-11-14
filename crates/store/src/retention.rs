//! Retention: drop old message bodies and events, then reclaim space.

use sigill_core::{DAY_MS, now_ms};

use crate::{Result, Store};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub bodies_cleared: u64,
    pub events_deleted: u64,
}

impl Store {
    /// Clear bodies of messages older than `body_days` whose deliveries are all final, and
    /// delete events older than `event_days`. Runs an incremental vacuum afterwards.
    pub async fn run_retention(&self, body_days: i64, event_days: i64) -> Result<RetentionReport> {
        let now = now_ms();
        let body_cutoff = now - body_days * DAY_MS;
        let event_cutoff = now - event_days * DAY_MS;
        let bodies = sqlx::query!(
            "UPDATE messages SET rendered_mime = NULL
             WHERE rendered_mime IS NOT NULL AND created_at < ?
               AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = messages.id
                               AND d.status IN ('queued', 'sending', 'deferred'))",
            body_cutoff
        )
        .execute(&self.write)
        .await?
        .rows_affected();
        let events = sqlx::query!("DELETE FROM delivery_events WHERE at < ?", event_cutoff)
            .execute(&self.write)
            .await?
            .rows_affected();
        sqlx::query("PRAGMA incremental_vacuum").execute(&self.write).await?;
        Ok(RetentionReport { bodies_cleared: bodies, events_deleted: events })
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::tests::{dl, msg, seed_app};
    use crate::queue::Outcome;
    use crate::testing::test_db;

    #[tokio::test]
    async fn clears_only_finished_old_bodies() {
        let db = test_db().await;
        seed_app(&db, None).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@x.com", false)]).await.unwrap();
        db.insert_message(&msg("m2", None), &[dl("d2", "b@x.com", false)]).await.unwrap();
        db.complete(&[("d1".into(), Outcome::Sent { code: 250, response: "ok".into() })]).await.unwrap();
        // Negative day counts move the cut-off into the future, so everything counts as old.
        let r = db.run_retention(-1, 1000).await.unwrap();
        assert_eq!(r.bodies_cleared, 1);
        assert!(db.message_mime("m1").await.unwrap().is_none());
        assert!(db.message_mime("m2").await.unwrap().is_some());
        let r = db.run_retention(-1, -1).await.unwrap();
        assert!(r.events_deleted >= 3);
    }
}
