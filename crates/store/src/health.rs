//! Recent delivery statistics for health alerts.

use crate::{Result, Store};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecentStats {
    pub sent: i64,
    pub bounced: i64,
    /// Deferral events per recipient domain, most first.
    pub deferred_by_domain: Vec<(String, i64)>,
}

impl RecentStats {
    /// Bounced share of sent + bounced, in percent.
    pub fn bounce_rate_percent(&self) -> f64 {
        let n = self.sent + self.bounced;
        if n == 0 { 0.0 } else { self.bounced as f64 * 100.0 / n as f64 }
    }
}

impl Store {
    /// Event counts since `since` (unix ms).
    pub async fn recent_stats(&self, since: i64) -> Result<RecentStats> {
        let counts = sqlx::query!(
            r#"SELECT kind, COUNT(*) AS "n!: i64" FROM delivery_events
               WHERE at >= ? AND kind IN ('sent', 'bounced') GROUP BY kind"#,
            since
        )
        .fetch_all(&self.read)
        .await?;
        let mut stats = RecentStats::default();
        for c in counts {
            match c.kind.as_str() {
                "sent" => stats.sent = c.n,
                _ => stats.bounced = c.n,
            }
        }
        stats.deferred_by_domain = sqlx::query!(
            r#"SELECT d.rcpt_domain, COUNT(*) AS "n!: i64" FROM delivery_events e
               JOIN deliveries d ON d.id = e.delivery_id
               WHERE e.at >= ? AND e.kind = 'deferred'
               GROUP BY d.rcpt_domain ORDER BY 2 DESC LIMIT 20"#,
            since
        )
        .fetch_all(&self.read)
        .await?
        .into_iter()
        .map(|r| (r.rcpt_domain, r.n))
        .collect();
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::tests::{dl, msg, seed_app};
    use crate::queue::Outcome;
    use crate::testing::test_db;

    #[tokio::test]
    async fn counts_recent_events() {
        let db = test_db().await;
        seed_app(&db, None).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@x.com", false), dl("d2", "b@y.com", false)])
            .await
            .unwrap();
        db.complete(&[
            ("d1".into(), Outcome::Sent { code: 250, response: "OK".into() }),
            (
                "d2".into(),
                Outcome::Deferred { code: Some(451), response: "later".into(), next_attempt_at: 0 },
            ),
        ])
        .await
        .unwrap();
        let s = db.recent_stats(0).await.unwrap();
        assert_eq!((s.sent, s.bounced), (1, 0));
        assert_eq!(s.deferred_by_domain, vec![("y.com".to_string(), 1)]);
        assert_eq!(s.bounce_rate_percent(), 0.0);
        assert!(db.recent_stats(sigill_core::now_ms() + 1000).await.unwrap().deferred_by_domain.is_empty());
    }
}
