//! Retention: drop old message bodies, events, message records and DMARC reports, then
//! reclaim space.

use sigill_core::{DAY_MS, now_ms};

use crate::{Result, Store};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub bodies_cleared: u64,
    pub events_deleted: u64,
    pub messages_deleted: u64,
    pub dmarc_reports_deleted: u64,
}

impl Store {
    /// Clear bodies of messages older than `body_days` whose deliveries are all final,
    /// delete events and DMARC reports older than `event_days`, and delete messages older
    /// than `message_days` (with their deliveries, so recipient addresses and subjects do
    /// not stay forever) once all their deliveries are final. Runs an incremental vacuum
    /// afterwards.
    pub async fn run_retention(
        &self,
        body_days: i64,
        event_days: i64,
        message_days: i64,
    ) -> Result<RetentionReport> {
        let now = now_ms();
        let message_cutoff = now - message_days * DAY_MS;
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
        let messages = sqlx::query!(
            "DELETE FROM messages
             WHERE created_at < ?
               AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = messages.id
                               AND d.status IN ('queued', 'sending', 'deferred'))",
            message_cutoff
        )
        .execute(&self.write)
        .await?
        .rows_affected();
        let dmarc = sqlx::query!("DELETE FROM dmarc_reports WHERE received_at < ?", event_cutoff)
            .execute(&self.write)
            .await?
            .rows_affected();
        sqlx::query("PRAGMA incremental_vacuum").execute(&self.write).await?;
        Ok(RetentionReport {
            bodies_cleared: bodies,
            events_deleted: events,
            messages_deleted: messages,
            dmarc_reports_deleted: dmarc,
        })
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
        let r = db.run_retention(-1, 1000, 1000).await.unwrap();
        assert_eq!(r.bodies_cleared, 1);
        assert_eq!(r.messages_deleted, 0);
        assert!(db.message_mime("m1").await.unwrap().is_none());
        assert!(db.message_mime("m2").await.unwrap().is_some());
        let r = db.run_retention(-1, -1, 1000).await.unwrap();
        assert!(r.events_deleted >= 3);
        // Old messages go with their deliveries, but never while a delivery is still open.
        let r = db.run_retention(-1, -1, -1).await.unwrap();
        assert_eq!(r.messages_deleted, 1);
        assert!(db.get_message("m1").await.unwrap().is_none());
        assert!(db.get_delivery("d1").await.unwrap().is_none());
        assert!(db.get_message("m2").await.unwrap().is_some(), "m2 is still queued");
    }

    #[tokio::test]
    async fn deletes_old_dmarc_reports() {
        let db = test_db().await;
        let rec = crate::dmarc::DmarcRecord {
            source_ip: "192.0.2.1".into(),
            count: 1,
            disposition: "none".into(),
            dkim_result: "pass".into(),
            spf_result: "pass".into(),
            header_from: "example.com".into(),
        };
        let report = crate::dmarc::NewDmarcReport {
            org_name: "o",
            report_id: "1",
            domain: "example.com",
            date_begin: 0,
            date_end: 1,
            policy: "none",
            records: &[rec],
        };
        assert!(db.insert_dmarc_report(&report).await.unwrap());
        assert_eq!(db.run_retention(1000, 1000, 1000).await.unwrap().dmarc_reports_deleted, 0);
        assert_eq!(db.run_retention(1000, -1, 1000).await.unwrap().dmarc_reports_deleted, 1);
        assert!(db.recent_dmarc_reports(10).await.unwrap().is_empty());
    }
}
