//! Messages (one logical send) and their deliveries (one per recipient).

use sigill_core::{DeliveryStatus, EventKind, Stream, now_ms};

use crate::{Error, Result, Store, events, parse};

pub struct NewMessage<'a> {
    pub id: &'a str,
    pub app_id: &'a str,
    pub idempotency_key: Option<&'a str>,
    pub stream: Stream,
    pub template_key: &'a str,
    pub template_version: i64,
    pub from_addr: &'a str,
    pub subject: &'a str,
    pub rendered_mime: &'a [u8],
    pub broadcast_id: Option<&'a str>,
    pub priority: i64,
    /// When the first attempt may happen (unix ms); `None` means now.
    pub not_before: Option<i64>,
}

pub struct NewDelivery {
    pub id: String,
    pub rcpt: String,
    pub rcpt_domain: String,
    /// Already suppressed: stored with status `suppressed` and never sent.
    pub suppressed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Message {
    pub id: String,
    pub app_id: String,
    pub idempotency_key: Option<String>,
    pub stream: Stream,
    pub template_key: String,
    pub template_version: i64,
    pub from_addr: String,
    pub subject: String,
    pub broadcast_id: Option<String>,
    pub created_at: i64,
    pub has_body: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Delivery {
    pub id: String,
    pub message_id: String,
    pub stream: Stream,
    pub rcpt: String,
    pub rcpt_domain: String,
    pub status: DeliveryStatus,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_smtp_code: Option<i64>,
    pub last_response: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Result of inserting a message.
#[derive(Debug, PartialEq, Eq)]
pub enum Inserted {
    New,
    /// The idempotency key was already used; this is the existing message id.
    Existing(String),
}

impl Store {
    /// Look up a message by its idempotency key.
    pub async fn message_by_idempotency(&self, app_id: &str, key: &str) -> Result<Option<String>> {
        Ok(sqlx::query_scalar!(
            "SELECT id FROM messages WHERE app_id = ? AND idempotency_key = ?",
            app_id,
            key
        )
        .fetch_optional(&self.write)
        .await?)
    }

    /// Insert a message, its deliveries and their first events in one transaction.
    pub async fn insert_message(&self, m: &NewMessage<'_>, deliveries: &[NewDelivery]) -> Result<Inserted> {
        let now = now_ms();
        let not_before = m.not_before.unwrap_or(now);
        let stream = m.stream.as_str();
        let mut tx = self.write.begin().await?;
        let res = sqlx::query!(
            "INSERT INTO messages (id, app_id, idempotency_key, stream, template_key, template_version,
                                   from_addr, subject, rendered_mime, broadcast_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            m.id,
            m.app_id,
            m.idempotency_key,
            stream,
            m.template_key,
            m.template_version,
            m.from_addr,
            m.subject,
            m.rendered_mime,
            m.broadcast_id,
            now
        )
        .execute(&mut *tx)
        .await;
        if let Err(sqlx::Error::Database(d)) = &res
            && d.is_unique_violation()
        {
            drop(tx);
            if let Some(key) = m.idempotency_key
                && let Some(id) = self.message_by_idempotency(m.app_id, key).await?
            {
                return Ok(Inserted::Existing(id));
            }
            return Err(Error::Conflict("duplicate message".into()));
        }
        res?;
        for d in deliveries {
            let status = if d.suppressed { DeliveryStatus::Suppressed } else { DeliveryStatus::Queued };
            let status_s = status.as_str();
            sqlx::query!(
                "INSERT INTO deliveries (id, message_id, stream, rcpt, rcpt_domain, status, attempts,
                                         next_attempt_at, priority, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
                d.id,
                m.id,
                stream,
                d.rcpt,
                d.rcpt_domain,
                status_s,
                not_before,
                m.priority,
                now,
                now
            )
            .execute(&mut *tx)
            .await?;
            let kind = if d.suppressed { EventKind::Suppressed } else { EventKind::Queued };
            events::record(&mut tx, &d.id, kind, None).await?;
        }
        tx.commit().await?;
        Ok(Inserted::New)
    }

    pub async fn get_message(&self, id: &str) -> Result<Option<Message>> {
        let r = sqlx::query!(
            r#"SELECT id, app_id, idempotency_key, stream, template_key, template_version, from_addr,
                      subject, broadcast_id, created_at, rendered_mime IS NOT NULL AS "has_body!: bool"
               FROM messages WHERE id = ?"#,
            id
        )
        .fetch_optional(&self.read)
        .await?;
        r.map(|r| {
            Ok(Message {
                id: r.id,
                app_id: r.app_id,
                idempotency_key: r.idempotency_key,
                stream: parse(&r.stream)?,
                template_key: r.template_key,
                template_version: r.template_version,
                from_addr: r.from_addr,
                subject: r.subject,
                broadcast_id: r.broadcast_id,
                created_at: r.created_at,
                has_body: r.has_body,
            })
        })
        .transpose()
    }

    /// The stored MIME body of a message, if not yet removed by retention.
    pub async fn message_mime(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar!("SELECT rendered_mime FROM messages WHERE id = ?", id)
            .fetch_optional(&self.read)
            .await?
            .flatten())
    }

    pub async fn deliveries_for_message(&self, message_id: &str) -> Result<Vec<Delivery>> {
        let rows = sqlx::query_as!(
            DeliveryRow,
            "SELECT id, message_id, stream, rcpt, rcpt_domain, status, attempts, next_attempt_at,
                    last_smtp_code, last_response, created_at, updated_at
             FROM deliveries WHERE message_id = ? ORDER BY rcpt",
            message_id
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(Delivery::try_from).collect()
    }

    pub async fn get_delivery(&self, id: &str) -> Result<Option<Delivery>> {
        let row = sqlx::query_as!(
            DeliveryRow,
            "SELECT id, message_id, stream, rcpt, rcpt_domain, status, attempts, next_attempt_at,
                    last_smtp_code, last_response, created_at, updated_at
             FROM deliveries WHERE id = ?",
            id
        )
        .fetch_optional(&self.read)
        .await?;
        row.map(Delivery::try_from).transpose()
    }
}

pub(crate) struct DeliveryRow {
    pub id: String,
    pub message_id: String,
    pub stream: String,
    pub rcpt: String,
    pub rcpt_domain: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_smtp_code: Option<i64>,
    pub last_response: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TryFrom<DeliveryRow> for Delivery {
    type Error = Error;
    fn try_from(r: DeliveryRow) -> Result<Self> {
        Ok(Delivery {
            id: r.id,
            message_id: r.message_id,
            stream: parse(&r.stream)?,
            rcpt: r.rcpt,
            rcpt_domain: r.rcpt_domain,
            status: parse(&r.status)?,
            attempts: r.attempts,
            next_attempt_at: r.next_attempt_at,
            last_smtp_code: r.last_smtp_code,
            last_response: r.last_response,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testing::test_db;

    pub async fn seed_app(db: &Store, webhook: Option<&str>) {
        db.create_app("app", "app", "h", webhook, Stream::Transactional).await.unwrap();
    }

    pub fn msg<'a>(id: &'a str, key: Option<&'a str>) -> NewMessage<'a> {
        NewMessage {
            id,
            app_id: "app",
            idempotency_key: key,
            stream: Stream::Transactional,
            template_key: "welcome",
            template_version: 1,
            from_addr: "noreply@mail.example.com",
            subject: "Hi",
            rendered_mime: b"Subject: Hi\r\n\r\nbody",
            broadcast_id: None,
            priority: 0,
            not_before: None,
        }
    }

    pub fn dl(id: &str, rcpt: &str, suppressed: bool) -> NewDelivery {
        NewDelivery {
            id: id.into(),
            rcpt: rcpt.into(),
            rcpt_domain: sigill_core::address::domain_of(rcpt).unwrap(),
            suppressed,
        }
    }

    #[tokio::test]
    async fn insert_and_idempotency() {
        let db = test_db().await;
        seed_app(&db, Some("https://hook.test")).await;
        let r = db
            .insert_message(&msg("m1", Some("k1")), &[dl("d1", "a@x.com", false), dl("d2", "b@y.com", true)])
            .await
            .unwrap();
        assert_eq!(r, Inserted::New);
        let r = db.insert_message(&msg("m2", Some("k1")), &[dl("d3", "a@x.com", false)]).await.unwrap();
        assert_eq!(r, Inserted::Existing("m1".into()));
        let ds = db.deliveries_for_message("m1").await.unwrap();
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].status, DeliveryStatus::Queued);
        assert_eq!(ds[1].status, DeliveryStatus::Suppressed);
        assert_eq!(db.events_for_delivery("d2").await.unwrap()[0].kind, EventKind::Suppressed);
        assert!(db.get_message("m1").await.unwrap().unwrap().has_body);
        assert_eq!(db.message_mime("m1").await.unwrap().unwrap(), b"Subject: Hi\r\n\r\nbody");
        assert!(db.get_message("m2").await.unwrap().is_none());
    }
}
