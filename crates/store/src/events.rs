//! Delivery events, written together with the matching webhook outbox row.

use sigill_core::{EventKind, now_ms};
use sqlx::SqliteConnection;

use crate::{Result, Store, parse};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeliveryEvent {
    pub id: i64,
    pub delivery_id: String,
    pub kind: EventKind,
    pub detail: Option<String>,
    pub at: i64,
}

/// Append an event for a delivery and, when the kind is reported to apps and the app has a
/// webhook URL, queue the webhook in the same transaction.
pub async fn record(
    conn: &mut SqliteConnection,
    delivery_id: &str,
    kind: EventKind,
    detail: Option<&str>,
) -> Result<()> {
    let now = now_ms();
    let kind_s = kind.as_str();
    sqlx::query!(
        "INSERT INTO delivery_events (delivery_id, kind, detail, at) VALUES (?, ?, ?, ?)",
        delivery_id,
        kind_s,
        detail,
        now
    )
    .execute(&mut *conn)
    .await?;
    if let Some(name) = kind.webhook_name() {
        sqlx::query!(
            "INSERT INTO webhook_outbox (app_id, payload, next_attempt_at, created_at)
             SELECT a.id,
                    json_object('id', last_insert_rowid(), 'event', ?, 'at', ?,
                                'message_id', d.message_id, 'delivery_id', d.id,
                                'recipient', d.rcpt, 'stream', d.stream, 'detail', ?,
                                'broadcast_id', m.broadcast_id),
                    ?, ?
             FROM deliveries d
             JOIN messages m ON m.id = d.message_id
             JOIN apps a ON a.id = m.app_id
             WHERE d.id = ? AND a.webhook_url IS NOT NULL",
            name,
            now,
            detail,
            now,
            now,
            delivery_id
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

impl Store {
    pub async fn events_for_delivery(&self, delivery_id: &str) -> Result<Vec<DeliveryEvent>> {
        let rows = sqlx::query!(
            "SELECT id, delivery_id, kind, detail, at FROM delivery_events
             WHERE delivery_id = ? ORDER BY id",
            delivery_id
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DeliveryEvent {
                    id: r.id,
                    delivery_id: r.delivery_id,
                    kind: parse(&r.kind)?,
                    detail: r.detail,
                    at: r.at,
                })
            })
            .collect()
    }

    /// Record an event on its own (outside a larger transaction).
    pub async fn record_event(&self, delivery_id: &str, kind: EventKind, detail: Option<&str>) -> Result<()> {
        let mut tx = self.write.begin().await?;
        record(&mut tx, delivery_id, kind, detail).await?;
        tx.commit().await?;
        Ok(())
    }
}
