//! Read-only queries for the admin UI.

use crate::{Result, Store};

#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageSummary {
    pub id: String,
    pub app_name: String,
    pub stream: String,
    pub template_key: String,
    pub subject: String,
    pub created_at: i64,
    pub recipients: i64,
    pub sent: i64,
    pub pending: i64,
    pub failed: i64,
}

impl Store {
    /// Find messages by message id, delivery id, idempotency key or recipient (substring),
    /// newest first. An empty query lists the latest messages.
    pub async fn search_messages(&self, query: &str, limit: i64) -> Result<Vec<MessageSummary>> {
        let q = query.trim();
        let pattern = format!("%{}%", q.to_lowercase());
        let rows = sqlx::query_as!(
            MessageSummary,
            r#"SELECT m.id, a.name AS app_name, m.stream, m.template_key, m.subject, m.created_at,
                      COUNT(d.id) AS "recipients!: i64",
                      SUM(d.status = 'sent') AS "sent!: i64",
                      SUM(d.status IN ('queued', 'sending', 'deferred')) AS "pending!: i64",
                      SUM(d.status IN ('bounced', 'failed', 'suppressed')) AS "failed!: i64"
               FROM messages m
               JOIN apps a ON a.id = m.app_id
               LEFT JOIN deliveries d ON d.message_id = m.id
               WHERE ?1 = '' OR m.id = ?1 OR m.idempotency_key = ?1
                  OR m.id IN (SELECT message_id FROM deliveries WHERE id = ?1 OR lower(rcpt) LIKE ?2)
               GROUP BY m.id
               ORDER BY m.created_at DESC
               LIMIT ?3"#,
            q,
            pattern,
            limit
        )
        .fetch_all(&self.read)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::tests::{dl, msg, seed_app};
    use crate::testing::test_db;

    #[tokio::test]
    async fn searches() {
        let db = test_db().await;
        seed_app(&db, None).await;
        db.insert_message(&msg("m1", Some("key-1")), &[dl("d1", "alice@x.com", false)]).await.unwrap();
        db.insert_message(&msg("m2", None), &[dl("d2", "bob@y.com", false), dl("d3", "carol@y.com", true)])
            .await
            .unwrap();
        assert_eq!(db.search_messages("", 10).await.unwrap().len(), 2);
        assert_eq!(db.search_messages("m1", 10).await.unwrap()[0].id, "m1");
        assert_eq!(db.search_messages("key-1", 10).await.unwrap()[0].id, "m1");
        assert_eq!(db.search_messages("d3", 10).await.unwrap()[0].id, "m2");
        let r = db.search_messages("BOB@", 10).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].recipients, r[0].pending, r[0].failed), (2, 1, 1));
    }
}
