//! The webhook outbox.

use crate::{Result, Store};

#[derive(Debug, Clone)]
pub struct OutboxItem {
    pub id: i64,
    pub app_id: String,
    pub webhook_url: Option<String>,
    pub payload: String,
    pub attempts: i64,
}

impl Store {
    pub async fn due_webhooks(&self, now: i64, limit: i64) -> Result<Vec<OutboxItem>> {
        Ok(sqlx::query_as!(
            OutboxItem,
            "SELECT o.id, o.app_id, a.webhook_url, o.payload, o.attempts
             FROM webhook_outbox o JOIN apps a ON a.id = o.app_id
             WHERE o.next_attempt_at <= ? ORDER BY o.next_attempt_at, o.id LIMIT ?",
            now,
            limit
        )
        .fetch_all(&self.read)
        .await?)
    }

    /// Delivered (or dropped): remove from the outbox.
    pub async fn webhook_done(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM webhook_outbox WHERE id = ?", id).execute(&self.write).await?;
        Ok(())
    }

    pub async fn webhook_retry(&self, id: i64, next_attempt_at: i64, error: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE webhook_outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ?",
            next_attempt_at,
            error,
            id
        )
        .execute(&self.write)
        .await?;
        Ok(())
    }

    pub async fn webhook_backlog(&self) -> Result<i64> {
        Ok(sqlx::query_scalar!(r#"SELECT COUNT(*) AS "n!: i64" FROM webhook_outbox"#)
            .fetch_one(&self.read)
            .await?)
    }

    /// Earliest due time in the outbox.
    pub async fn next_webhook_at(&self) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar!(r#"SELECT MIN(next_attempt_at) AS "t: i64" FROM webhook_outbox"#)
            .fetch_one(&self.read)
            .await?)
    }
}
