//! Broadcast announcements.

use sigill_core::{BroadcastStatus, new_id, now_ms};

use crate::{Error, Result, Store, parse};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Broadcast {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub template_key: String,
    pub template_version: Option<i64>,
    pub list: String,
    pub from_addr: Option<String>,
    pub variables: serde_json::Value,
    pub segment_query: serde_json::Value,
    pub status: BroadcastStatus,
    pub scheduled_at: Option<i64>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub audience_count: i64,
    pub sent_count: i64,
    pub created_at: i64,
}

pub struct NewBroadcast<'a> {
    pub app_id: &'a str,
    pub name: &'a str,
    pub template_key: &'a str,
    pub template_version: Option<i64>,
    pub list: &'a str,
    pub from_addr: Option<&'a str>,
    pub variables: &'a serde_json::Value,
    pub segment_query: &'a serde_json::Value,
    pub scheduled_at: Option<i64>,
}

/// A contact in a broadcast audience.
#[derive(Debug, Clone, PartialEq)]
pub struct AudienceMember {
    pub contact_id: String,
    pub email: String,
    pub name: Option<String>,
    pub attributes: serde_json::Value,
}

/// Delivery counts for a broadcast.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BroadcastStats {
    pub pending: i64,
    pub sent: i64,
    pub bounced: i64,
    pub failed: i64,
    pub suppressed: i64,
}

struct Row {
    id: String,
    app_id: String,
    name: String,
    template_key: String,
    template_version: Option<i64>,
    list: String,
    from_addr: Option<String>,
    variables: String,
    segment_query: String,
    status: String,
    scheduled_at: Option<i64>,
    started_at: Option<i64>,
    finished_at: Option<i64>,
    audience_count: i64,
    sent_count: i64,
    created_at: i64,
}

fn json(s: &str) -> Result<serde_json::Value> {
    serde_json::from_str(s).map_err(|e| Error::Invalid(e.to_string()))
}

impl TryFrom<Row> for Broadcast {
    type Error = Error;
    fn try_from(r: Row) -> Result<Self> {
        Ok(Broadcast {
            id: r.id,
            app_id: r.app_id,
            name: r.name,
            template_key: r.template_key,
            template_version: r.template_version,
            list: r.list,
            from_addr: r.from_addr,
            variables: json(&r.variables)?,
            segment_query: json(&r.segment_query)?,
            status: parse(&r.status)?,
            scheduled_at: r.scheduled_at,
            started_at: r.started_at,
            finished_at: r.finished_at,
            audience_count: r.audience_count,
            sent_count: r.sent_count,
            created_at: r.created_at,
        })
    }
}

/// Does a contact's attributes match a segment query? The query is a JSON object whose
/// keys must all equal the contact's attribute values; an array value means "any of".
pub fn segment_matches(query: &serde_json::Value, attributes: &serde_json::Value) -> bool {
    let Some(q) = query.as_object() else { return true };
    q.iter().all(|(k, want)| {
        let have = attributes.get(k).unwrap_or(&serde_json::Value::Null);
        match want {
            serde_json::Value::Array(options) => options.contains(have),
            other => other == have,
        }
    })
}

impl Store {
    pub async fn create_broadcast(&self, b: &NewBroadcast<'_>) -> Result<Broadcast> {
        let id = new_id();
        let now = now_ms();
        let vars = b.variables.to_string();
        let seg = b.segment_query.to_string();
        sqlx::query!(
            "INSERT INTO broadcasts (id, app_id, name, template_key, template_version, list, from_addr,
                                     variables, segment_query, status, scheduled_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)",
            id,
            b.app_id,
            b.name,
            b.template_key,
            b.template_version,
            b.list,
            b.from_addr,
            vars,
            seg,
            b.scheduled_at,
            now
        )
        .execute(&self.write)
        .await?;
        self.get_broadcast(b.app_id, &id).await?.ok_or(Error::NotFound)
    }

    pub async fn get_broadcast(&self, app_id: &str, id: &str) -> Result<Option<Broadcast>> {
        let r = sqlx::query_as!(
            Row,
            "SELECT id, app_id, name, template_key, template_version, list, from_addr, variables, segment_query,
                    status, scheduled_at, started_at, finished_at, audience_count, sent_count, created_at
             FROM broadcasts WHERE app_id = ? AND id = ?",
            app_id,
            id
        )
        .fetch_optional(&self.write)
        .await?;
        r.map(Broadcast::try_from).transpose()
    }

    /// Move a draft to `scheduled`, to start at `at` (unix ms).
    pub async fn schedule_broadcast(&self, app_id: &str, id: &str, at: i64) -> Result<Broadcast> {
        let r = sqlx::query!(
            "UPDATE broadcasts SET status = 'scheduled', scheduled_at = ? WHERE app_id = ? AND id = ? AND status = 'draft'",
            at,
            app_id,
            id
        )
        .execute(&self.write)
        .await?;
        if r.rows_affected() == 0 {
            return match self.get_broadcast(app_id, id).await? {
                None => Err(Error::NotFound),
                Some(b) => Err(Error::Conflict(format!("broadcast is {}", b.status))),
            };
        }
        self.get_broadcast(app_id, id).await?.ok_or(Error::NotFound)
    }

    /// Scheduled broadcasts whose start time has come.
    pub async fn due_broadcasts(&self, now: i64) -> Result<Vec<Broadcast>> {
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, app_id, name, template_key, template_version, list, from_addr, variables, segment_query,
                    status, scheduled_at, started_at, finished_at, audience_count, sent_count, created_at
             FROM broadcasts WHERE status = 'scheduled' AND scheduled_at <= ? ORDER BY scheduled_at",
            now
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(Broadcast::try_from).collect()
    }

    /// Contacts with active consent for `list`, minus suppressed addresses.
    pub async fn broadcast_audience(&self, app_id: &str, list: &str) -> Result<Vec<AudienceMember>> {
        let rows = sqlx::query!(
            "SELECT c.id, c.email, c.name, c.attributes FROM contacts c
             JOIN consents k ON k.contact_id = c.id AND k.list = ? AND k.revoked_at IS NULL
             WHERE c.app_id = ? AND lower(c.email) NOT IN (SELECT address FROM suppressions)
             ORDER BY c.created_at, c.id",
            list,
            app_id
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(AudienceMember {
                    contact_id: r.id,
                    email: r.email,
                    name: r.name,
                    attributes: json(&r.attributes)?,
                })
            })
            .collect()
    }

    pub async fn mark_broadcast_sending(&self, id: &str, audience_count: i64) -> Result<()> {
        let now = now_ms();
        sqlx::query!(
            "UPDATE broadcasts SET status = 'sending', started_at = ?, audience_count = ? WHERE id = ?",
            now,
            audience_count,
            id
        )
        .execute(&self.write)
        .await?;
        Ok(())
    }

    pub async fn cancel_broadcast(&self, app_id: &str, id: &str) -> Result<Broadcast> {
        let r = sqlx::query!(
            "UPDATE broadcasts SET status = 'cancelled' WHERE app_id = ? AND id = ? AND status IN ('draft', 'scheduled')",
            app_id,
            id
        )
        .execute(&self.write)
        .await?;
        if r.rows_affected() == 0 {
            return match self.get_broadcast(app_id, id).await? {
                None => Err(Error::NotFound),
                Some(b) => Err(Error::Conflict(format!("broadcast is {}", b.status))),
            };
        }
        self.get_broadcast(app_id, id).await?.ok_or(Error::NotFound)
    }

    pub async fn broadcast_stats(&self, id: &str) -> Result<BroadcastStats> {
        let rows = sqlx::query!(
            r#"SELECT d.status, COUNT(*) AS "n!: i64" FROM deliveries d JOIN messages m ON m.id = d.message_id
               WHERE m.broadcast_id = ? GROUP BY d.status"#,
            id
        )
        .fetch_all(&self.read)
        .await?;
        let mut s = BroadcastStats::default();
        for r in rows {
            match r.status.as_str() {
                "sent" => s.sent += r.n,
                "bounced" => s.bounced += r.n,
                "failed" => s.failed += r.n,
                "suppressed" => s.suppressed += r.n,
                _ => s.pending += r.n,
            }
        }
        Ok(s)
    }

    /// Mark `sending` broadcasts with nothing left in the queue as finished. Returns the
    /// finished broadcasts.
    pub async fn finish_broadcasts(&self) -> Result<Vec<Broadcast>> {
        let ids = sqlx::query_scalar!(
            "SELECT b.id FROM broadcasts b WHERE b.status = 'sending' AND NOT EXISTS (
                 SELECT 1 FROM deliveries d JOIN messages m ON m.id = d.message_id
                 WHERE m.broadcast_id = b.id AND d.status IN ('queued', 'sending', 'deferred'))"
        )
        .fetch_all(&self.write)
        .await?;
        let mut out = Vec::new();
        for id in ids {
            let stats = self.broadcast_stats(&id).await?;
            let now = now_ms();
            let app_id = sqlx::query_scalar!(
                "UPDATE broadcasts SET status = 'finished', finished_at = ?, sent_count = ? WHERE id = ? RETURNING app_id",
                now,
                stats.sent,
                id
            )
            .fetch_one(&self.write)
            .await?;
            if let Some(b) = self.get_broadcast(&app_id, &id).await? {
                out.push(b);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_db;
    use serde_json::json;
    use sigill_core::{Stream, SuppressionReason, SuppressionScope};

    #[test]
    fn segments() {
        assert!(segment_matches(&json!({}), &json!({"a": 1})));
        assert!(segment_matches(&json!({"plan": "pro"}), &json!({"plan": "pro", "x": 1})));
        assert!(!segment_matches(&json!({"plan": "pro"}), &json!({"plan": "free"})));
        assert!(segment_matches(&json!({"plan": ["pro", "team"]}), &json!({"plan": "team"})));
        assert!(!segment_matches(&json!({"plan": "pro"}), &json!({})));
    }

    #[tokio::test]
    async fn lifecycle_and_audience() {
        let db = test_db().await;
        db.create_app("app", "app", "h", None, Stream::Transactional).await.unwrap();
        let a = db.create_contact("app", "a@x.com", None, &json!({})).await.unwrap();
        let b = db.create_contact("app", "b@x.com", None, &json!({})).await.unwrap();
        let c = db.create_contact("app", "c@x.com", None, &json!({})).await.unwrap();
        for x in [&a, &b, &c] {
            db.grant_consent(&x.id, "news", "test").await.unwrap();
        }
        db.revoke_consent(&b.id, "news").await.unwrap();
        db.add_suppression("c@x.com", SuppressionScope::Broadcast, SuppressionReason::Unsubscribe, None)
            .await
            .unwrap();
        let aud = db.broadcast_audience("app", "news").await.unwrap();
        assert_eq!(aud.iter().map(|m| m.email.as_str()).collect::<Vec<_>>(), vec!["a@x.com"]);

        let empty = json!({});
        let br = db
            .create_broadcast(&NewBroadcast {
                app_id: "app",
                name: "launch",
                template_key: "news",
                template_version: None,
                list: "news",
                from_addr: None,
                variables: &empty,
                segment_query: &empty,
                scheduled_at: None,
            })
            .await
            .unwrap();
        assert_eq!(br.status, BroadcastStatus::Draft);
        let now = now_ms();
        db.schedule_broadcast("app", &br.id, now).await.unwrap();
        assert!(db.schedule_broadcast("app", &br.id, now).await.is_err());
        assert_eq!(db.due_broadcasts(now).await.unwrap().len(), 1);
        db.mark_broadcast_sending(&br.id, 0).await.unwrap();
        let done = db.finish_broadcasts().await.unwrap();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].status, BroadcastStatus::Finished);
    }
}
