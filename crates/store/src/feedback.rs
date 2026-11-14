//! Asynchronous feedback about deliveries that were already handed over: bounce messages
//! (DSNs) and complaints (ARF reports).

use sigill_core::{EventKind, SuppressionReason, SuppressionScope, now_ms};

use crate::{Result, Store, events, suppressions};

impl Store {
    /// A bounce message arrived for a delivery we had sent. Marks it `bounced` (only if it
    /// is still `sent`, so repeated bounces count once), records the event and, for a hard
    /// bounce, suppresses `suppress`. Returns whether the delivery changed.
    pub async fn record_async_bounce(
        &self,
        delivery_id: &str,
        code: Option<u16>,
        detail: &str,
        suppress: Option<&str>,
    ) -> Result<bool> {
        let now = now_ms();
        let code = code.map(i64::from);
        let mut tx = self.write.begin().await?;
        let r = sqlx::query!(
            "UPDATE deliveries SET status = 'bounced', last_smtp_code = COALESCE(?, last_smtp_code),
                    last_response = ?, updated_at = ?
             WHERE id = ? AND status = 'sent'",
            code,
            detail,
            now,
            delivery_id
        )
        .execute(&mut *tx)
        .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        events::record(&mut tx, delivery_id, EventKind::Bounced, Some(detail)).await?;
        if let Some(address) = suppress {
            suppressions::insert(
                &mut tx,
                address,
                SuppressionScope::All,
                SuppressionReason::HardBounce,
                Some(delivery_id),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// A recipient reported a delivery as spam. Records a `complained` event (once per
    /// delivery), suppresses the address on every stream and revokes the recipient's
    /// consents in the sending app. Returns false when the complaint was already recorded.
    pub async fn record_complaint(&self, delivery_id: &str, address: &str) -> Result<bool> {
        let now = now_ms();
        let mut tx = self.write.begin().await?;
        let seen = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM delivery_events WHERE delivery_id = ? AND kind = 'complained'"#,
            delivery_id
        )
        .fetch_one(&mut *tx)
        .await?;
        if seen > 0 {
            return Ok(false);
        }
        events::record(&mut tx, delivery_id, EventKind::Complained, None).await?;
        suppressions::insert(
            &mut tx,
            address,
            SuppressionScope::All,
            SuppressionReason::Complaint,
            Some(delivery_id),
        )
        .await?;
        sqlx::query!(
            "UPDATE consents SET revoked_at = ?
             WHERE revoked_at IS NULL AND contact_id IN (
                 SELECT c.id FROM contacts c
                 JOIN messages m ON m.app_id = c.app_id
                 JOIN deliveries d ON d.message_id = m.id
                 WHERE d.id = ? AND lower(c.email) = ?)",
            now,
            delivery_id,
            address
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// One-click unsubscribe from a broadcast delivery: suppress the address for broadcast
    /// mail, revoke its consents in the sending app and record an `unsubscribed` event (once).
    /// Returns `None` when the delivery does not exist, else whether anything changed.
    pub async fn record_unsubscribe(&self, delivery_id: &str) -> Result<Option<bool>> {
        let now = now_ms();
        let mut tx = self.write.begin().await?;
        let Some(row) = sqlx::query!(
            "SELECT d.rcpt, m.app_id FROM deliveries d JOIN messages m ON m.id = d.message_id WHERE d.id = ?",
            delivery_id
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let seen = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM delivery_events WHERE delivery_id = ? AND kind = 'unsubscribed'"#,
            delivery_id
        )
        .fetch_one(&mut *tx)
        .await?;
        if seen > 0 {
            return Ok(Some(false));
        }
        let address = sigill_core::address::normalize(&row.rcpt).unwrap_or(row.rcpt);
        suppressions::insert(
            &mut tx,
            &address,
            SuppressionScope::Broadcast,
            SuppressionReason::Unsubscribe,
            Some(delivery_id),
        )
        .await?;
        sqlx::query!(
            "UPDATE consents SET revoked_at = ?
             WHERE revoked_at IS NULL AND contact_id IN (
                 SELECT id FROM contacts WHERE app_id = ? AND lower(email) = ?)",
            now,
            row.app_id,
            address
        )
        .execute(&mut *tx)
        .await?;
        events::record(&mut tx, delivery_id, EventKind::Unsubscribed, None).await?;
        tx.commit().await?;
        Ok(Some(true))
    }
}

#[cfg(test)]
mod tests {
    use sigill_core::{DeliveryStatus, Stream};

    use crate::messages::tests::{dl, msg, seed_app};
    use crate::queue::Outcome;
    use crate::testing::test_db;

    #[tokio::test]
    async fn async_bounce_only_after_sent() {
        let db = test_db().await;
        seed_app(&db, Some("https://hook.test")).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@x.com", false)]).await.unwrap();
        // Still queued: nothing happens.
        assert!(!db.record_async_bounce("d1", Some(550), "5.1.1 gone", Some("a@x.com")).await.unwrap());

        db.complete(&[("d1".into(), Outcome::Sent { code: 250, response: "OK".into() })]).await.unwrap();
        assert!(db.record_async_bounce("d1", Some(550), "5.1.1 gone", Some("a@x.com")).await.unwrap());
        assert!(!db.record_async_bounce("d1", Some(550), "5.1.1 gone", Some("a@x.com")).await.unwrap());
        let d = db.get_delivery("d1").await.unwrap().unwrap();
        assert_eq!((d.status, d.last_smtp_code), (DeliveryStatus::Bounced, Some(550)));
        assert!(db.is_suppressed("a@x.com", Stream::Transactional).await.unwrap());
        let events: Vec<_> = db.due_webhooks(sigill_core::now_ms() + 1, 10).await.unwrap();
        assert_eq!(events.len(), 2, "delivered and bounced webhooks");
    }

    #[tokio::test]
    async fn complaint_suppresses_and_revokes_consent() {
        let db = test_db().await;
        seed_app(&db, None).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "a@x.com", false)]).await.unwrap();
        let contact = db.create_contact("app", "a@x.com", None, &serde_json::json!({})).await.unwrap();
        db.grant_consent(&contact.id, "news", "api").await.unwrap();

        assert!(db.record_complaint("d1", "a@x.com").await.unwrap());
        assert!(!db.record_complaint("d1", "a@x.com").await.unwrap());
        assert!(db.is_suppressed("a@x.com", Stream::Transactional).await.unwrap());
        let consents = db.consents_for(&contact.id).await.unwrap();
        assert!(consents.iter().all(|c| c.revoked_at.is_some()));
        let kinds: Vec<_> = db.events_for_delivery("d1").await.unwrap().into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds.last(), Some(&sigill_core::EventKind::Complained));
    }

    #[tokio::test]
    async fn unsubscribe_is_broadcast_scoped_and_once() {
        let db = test_db().await;
        seed_app(&db, Some("https://hook.test")).await;
        db.insert_message(&msg("m1", None), &[dl("d1", "A@x.com", false)]).await.unwrap();
        let contact = db.create_contact("app", "A@x.com", None, &serde_json::json!({})).await.unwrap();
        db.grant_consent(&contact.id, "news", "api").await.unwrap();

        assert_eq!(db.record_unsubscribe("nope").await.unwrap(), None);
        assert_eq!(db.record_unsubscribe("d1").await.unwrap(), Some(true));
        assert_eq!(db.record_unsubscribe("d1").await.unwrap(), Some(false));
        assert!(db.is_suppressed("a@x.com", Stream::Broadcast).await.unwrap());
        assert!(!db.is_suppressed("a@x.com", Stream::Transactional).await.unwrap());
        assert!(db.consents_for(&contact.id).await.unwrap().iter().all(|c| c.revoked_at.is_some()));
        let hooks = db.due_webhooks(sigill_core::now_ms() + 1, 10).await.unwrap();
        assert!(hooks.iter().any(|h| h.payload.contains("\"unsubscribed\"")));
    }
}
