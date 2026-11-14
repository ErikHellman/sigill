//! The delivery queue: claiming due rows and recording what happened to them.

use sigill_core::{DeliveryStatus, EventKind, Stream, SuppressionReason, SuppressionScope, now_ms};

use crate::{Result, Store, events, parse};

/// A delivery handed to a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub id: String,
    pub message_id: String,
    pub stream: Stream,
    pub rcpt: String,
    pub rcpt_domain: String,
    pub attempts: i64,
    pub created_at: i64,
}

/// What happened to one claimed delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent {
        code: u16,
        response: String,
    },
    Deferred {
        code: Option<u16>,
        response: String,
        next_attempt_at: i64,
    },
    /// Permanent failure reported by the receiver. `suppress` adds the (normalised)
    /// address to the suppression list in the same transaction.
    Bounced {
        code: Option<u16>,
        response: String,
        suppress: Option<String>,
    },
    /// The retry window ran out.
    Failed {
        code: Option<u16>,
        response: String,
    },
    /// Put back without counting an attempt (throttling, shutdown).
    Released {
        next_attempt_at: i64,
    },
    /// Found on the suppression list just before sending.
    Suppressed,
}

/// Column values written for one outcome: status, next attempt, SMTP code, response text,
/// attempts increment and the event to record.
type Update<'a> = (DeliveryStatus, Option<i64>, Option<i64>, Option<&'a str>, i64, Option<EventKind>);

impl Store {
    /// Crash recovery: rows left in `sending` by a previous run go back to `queued`.
    pub async fn reset_sending(&self) -> Result<u64> {
        let now = now_ms();
        let r = sqlx::query!(
            "UPDATE deliveries SET status = 'queued', updated_at = ? WHERE status = 'sending'",
            now
        )
        .execute(&self.write)
        .await?;
        Ok(r.rows_affected())
    }

    /// Claim up to `limit` due deliveries of one stream, marking them `sending` in the same
    /// statement. Domains in backoff are skipped. Ordered by priority, then due time.
    pub async fn claim_due(&self, stream: Stream, now: i64, limit: i64) -> Result<Vec<Claimed>> {
        let stream_s = stream.as_str();
        let rows = sqlx::query!(
            r#"UPDATE deliveries SET status = 'sending', updated_at = ?1
               WHERE id IN (
                   SELECT id FROM deliveries
                   WHERE status IN ('queued', 'deferred') AND next_attempt_at <= ?1 AND stream = ?2
                     AND rcpt_domain NOT IN (
                         SELECT rcpt_domain FROM domain_throttle WHERE backoff_until > ?1)
                   ORDER BY priority, next_attempt_at
                   LIMIT ?3)
               RETURNING id AS "id!", message_id AS "message_id!", stream AS "stream!", rcpt AS "rcpt!",
                         rcpt_domain AS "rcpt_domain!", attempts AS "attempts!", created_at AS "created_at!""#,
            now,
            stream_s,
            limit
        )
        .fetch_all(&self.write)
        .await?;
        let mut out: Vec<Claimed> = rows
            .into_iter()
            .map(|r| {
                Ok(Claimed {
                    id: r.id,
                    message_id: r.message_id,
                    stream: parse(&r.stream)?,
                    rcpt: r.rcpt,
                    rcpt_domain: r.rcpt_domain,
                    attempts: r.attempts,
                    created_at: r.created_at,
                })
            })
            .collect::<Result<_>>()?;
        // RETURNING order is unspecified; keep a stable order for grouping.
        out.sort_by(|a, b| {
            (&a.message_id, &a.rcpt_domain, &a.rcpt).cmp(&(&b.message_id, &b.rcpt_domain, &b.rcpt))
        });
        Ok(out)
    }

    /// Record outcomes for claimed deliveries in one transaction (events and webhooks too).
    pub async fn complete(&self, results: &[(String, Outcome)]) -> Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        let now = now_ms();
        let mut tx = self.write.begin().await?;
        for (id, outcome) in results {
            let (status, next_at, code, response, attempt, event): Update<'_> = match outcome {
                Outcome::Sent { code, response } => {
                    (DeliveryStatus::Sent, None, Some(*code as i64), Some(response), 1, Some(EventKind::Sent))
                }
                Outcome::Deferred { code, response, next_attempt_at } => (
                    DeliveryStatus::Deferred,
                    Some(*next_attempt_at),
                    code.map(i64::from),
                    Some(response),
                    1,
                    Some(EventKind::Deferred),
                ),
                Outcome::Bounced { code, response, .. } => (
                    DeliveryStatus::Bounced,
                    None,
                    code.map(i64::from),
                    Some(response),
                    1,
                    Some(EventKind::Bounced),
                ),
                Outcome::Failed { code, response } => (
                    DeliveryStatus::Failed,
                    None,
                    code.map(i64::from),
                    Some(response),
                    1,
                    Some(EventKind::Failed),
                ),
                Outcome::Released { next_attempt_at } => {
                    (DeliveryStatus::Queued, Some(*next_attempt_at), None, None, 0, None)
                }
                Outcome::Suppressed => {
                    (DeliveryStatus::Suppressed, None, None, None, 0, Some(EventKind::Suppressed))
                }
            };
            let status_s = status.as_str();
            sqlx::query!(
                "UPDATE deliveries SET status = ?, attempts = attempts + ?,
                        next_attempt_at = COALESCE(?, next_attempt_at),
                        last_smtp_code = COALESCE(?, last_smtp_code),
                        last_response = COALESCE(?, last_response), updated_at = ?
                 WHERE id = ?",
                status_s,
                attempt,
                next_at,
                code,
                response,
                now,
                id
            )
            .execute(&mut *tx)
            .await?;
            if let Some(kind) = event {
                let detail = match (code, response) {
                    (Some(c), Some(r)) => Some(format!("{c} {r}")),
                    (None, Some(r)) => Some(r.to_string()),
                    _ => None,
                };
                events::record(&mut tx, id, kind, detail.as_deref()).await?;
            }
            if let Outcome::Bounced { suppress: Some(address), .. } = outcome {
                crate::suppressions::insert(
                    &mut tx,
                    address,
                    SuppressionScope::All,
                    SuppressionReason::HardBounce,
                    Some(id),
                )
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Number of deliveries per stream and status.
    pub async fn queue_counts(&self) -> Result<Vec<(Stream, DeliveryStatus, i64)>> {
        let rows = sqlx::query!(
            r#"SELECT stream, status, COUNT(*) AS "n!: i64" FROM deliveries
               WHERE status IN ('queued', 'sending', 'deferred') GROUP BY stream, status"#
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(|r| Ok((parse(&r.stream)?, parse(&r.status)?, r.n))).collect()
    }

    /// Deliveries waiting (queued, deferred or sending) for one stream.
    pub async fn queue_depth(&self, stream: Stream) -> Result<i64> {
        let s = stream.as_str();
        Ok(sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM deliveries
               WHERE stream = ? AND status IN ('queued', 'sending', 'deferred')"#,
            s
        )
        .fetch_one(&self.read)
        .await?)
    }

    /// Earliest `next_attempt_at` among waiting deliveries, for dispatcher sleeps.
    pub async fn next_due_at(&self) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar!(
            r#"SELECT MIN(next_attempt_at) AS "t: i64" FROM deliveries WHERE status IN ('queued', 'deferred')"#
        )
        .fetch_one(&self.read)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::tests::{dl, msg, seed_app};
    use crate::testing::test_db;

    #[tokio::test]
    async fn claim_complete_and_recover() {
        let db = test_db().await;
        seed_app(&db, Some("https://hook.test")).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@x.com", false), dl("d2", "b@gmail.com", false)])
            .await
            .unwrap();
        let now = now_ms() + 1;
        let claimed = db.claim_due(Stream::Transactional, now, 10).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert!(db.claim_due(Stream::Transactional, now, 10).await.unwrap().is_empty());
        assert!(db.claim_due(Stream::Broadcast, now, 10).await.unwrap().is_empty());

        // Crash recovery puts them back.
        assert_eq!(db.reset_sending().await.unwrap(), 2);
        let claimed = db.claim_due(Stream::Transactional, now, 1).await.unwrap();
        assert_eq!(claimed.len(), 1);

        db.complete(&[(claimed[0].id.clone(), Outcome::Sent { code: 250, response: "2.0.0 OK".into() })])
            .await
            .unwrap();
        let d = db.get_delivery(&claimed[0].id).await.unwrap().unwrap();
        assert_eq!(d.status, DeliveryStatus::Sent);
        assert_eq!(d.attempts, 1);
        assert_eq!(d.last_smtp_code, Some(250));
        let kinds: Vec<_> =
            db.events_for_delivery(&d.id).await.unwrap().into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec![EventKind::Queued, EventKind::Sent]);
        // A webhook was queued for the delivered event (queued events are not reported).
        let hooks = db.due_webhooks(now_ms() + 1, 10).await.unwrap();
        assert_eq!(hooks.len(), 1);
        let payload: serde_json::Value = serde_json::from_str(&hooks[0].payload).unwrap();
        assert_eq!(payload["event"], "delivered");
        assert_eq!(payload["message_id"], "m1");
    }

    #[tokio::test]
    async fn backoff_and_bounce_suppression() {
        let db = test_db().await;
        seed_app(&db, None).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@gmail.com", false), dl("d2", "b@x.com", false)])
            .await
            .unwrap();
        let now = now_ms() + 1;
        db.set_backoff("gmail.com", now + 60_000).await.unwrap();
        let claimed = db.claim_due(Stream::Transactional, now, 10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].rcpt_domain, "x.com");
        db.complete(&[(
            "d2".into(),
            Outcome::Bounced {
                code: Some(550),
                response: "5.1.1 no such user".into(),
                suppress: Some("b@x.com".into()),
            },
        )])
        .await
        .unwrap();
        assert!(db.is_suppressed("b@x.com", Stream::Transactional).await.unwrap());
        assert_eq!(db.get_delivery("d2").await.unwrap().unwrap().status, DeliveryStatus::Bounced);
        // No webhook URL, so nothing queued.
        assert!(db.due_webhooks(now_ms() + 1, 10).await.unwrap().is_empty());

        db.complete(&[("d1".into(), Outcome::Released { next_attempt_at: now + 5 })]).await.unwrap();
        let d = db.get_delivery("d1").await.unwrap().unwrap();
        assert_eq!((d.status, d.attempts), (DeliveryStatus::Queued, 0));
        assert_eq!(db.queue_depth(Stream::Transactional).await.unwrap(), 1);
    }
}
