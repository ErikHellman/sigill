//! The suppression list. Addresses are stored normalised (see `sigill_core::address`).

use sigill_core::{DAY_MS, Stream, SuppressionReason, SuppressionScope, now_ms};
use sqlx::SqliteConnection;

use crate::{Result, Store, parse};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Suppression {
    pub address: String,
    pub scope: SuppressionScope,
    pub reason: SuppressionReason,
    pub source_delivery_id: Option<String>,
    pub created_at: i64,
}

/// Soft bounces within this window that suppress an address.
pub const SOFT_BOUNCE_LIMIT: i64 = 5;
pub const SOFT_BOUNCE_WINDOW_MS: i64 = 30 * DAY_MS;

pub(crate) async fn insert(
    conn: &mut SqliteConnection,
    address: &str,
    scope: SuppressionScope,
    reason: SuppressionReason,
    source_delivery_id: Option<&str>,
) -> Result<()> {
    let now = now_ms();
    let scope_s = scope.as_str();
    let reason_s = reason.as_str();
    sqlx::query!(
        "INSERT INTO suppressions (address, scope, reason, source_delivery_id, created_at)
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (address, scope) DO NOTHING",
        address,
        scope_s,
        reason_s,
        source_delivery_id,
        now
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

struct Row {
    address: String,
    scope: String,
    reason: String,
    source_delivery_id: Option<String>,
    created_at: i64,
}

impl TryFrom<Row> for Suppression {
    type Error = crate::Error;
    fn try_from(r: Row) -> Result<Self> {
        Ok(Suppression {
            address: r.address,
            scope: parse(&r.scope)?,
            reason: parse(&r.reason)?,
            source_delivery_id: r.source_delivery_id,
            created_at: r.created_at,
        })
    }
}

impl Store {
    pub async fn add_suppression(
        &self,
        address: &str,
        scope: SuppressionScope,
        reason: SuppressionReason,
        source_delivery_id: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.write.acquire().await?;
        insert(&mut conn, address, scope, reason, source_delivery_id).await
    }

    /// Remove every suppression for an address. Returns how many rows were removed.
    pub async fn remove_suppression(&self, address: &str) -> Result<u64> {
        let r =
            sqlx::query!("DELETE FROM suppressions WHERE address = ?", address).execute(&self.write).await?;
        sqlx::query!("DELETE FROM soft_bounces WHERE address = ?", address).execute(&self.write).await?;
        Ok(r.rows_affected())
    }

    /// Remove the suppressions an app may lift itself: manual entries and bounces.
    /// Complaints and unsubscribes are the recipient's own decision and stay. Returns
    /// `(removed, kept)` row counts.
    pub async fn remove_liftable_suppressions(&self, address: &str) -> Result<(u64, u64)> {
        let mut tx = self.write.begin().await?;
        let removed = sqlx::query!(
            "DELETE FROM suppressions WHERE address = ? AND reason IN ('manual', 'hard_bounce', 'soft_bounce')",
            address
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query!("DELETE FROM soft_bounces WHERE address = ?", address).execute(&mut *tx).await?;
        let kept = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM suppressions WHERE address = ?"#,
            address
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((removed, kept as u64))
    }

    pub async fn get_suppressions(&self, address: &str) -> Result<Vec<Suppression>> {
        let rows = sqlx::query_as!(
            Row,
            "SELECT address, scope, reason, source_delivery_id, created_at FROM suppressions
             WHERE address = ? ORDER BY scope",
            address
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(Suppression::try_from).collect()
    }

    /// Is mail on `stream` to this (normalised) address blocked?
    pub async fn is_suppressed(&self, address: &str, stream: Stream) -> Result<bool> {
        let rows = self.get_suppressions(address).await?;
        Ok(rows.iter().any(|s| s.scope.blocks(stream)))
    }

    /// Of the given normalised addresses, which are blocked on `stream`.
    pub async fn suppressed_among(&self, addresses: &[String], stream: Stream) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for a in addresses {
            if self.is_suppressed(a, stream).await? {
                out.push(a.clone());
            }
        }
        Ok(out)
    }

    /// List suppressions, newest first, optionally filtered by an address substring.
    pub async fn list_suppressions(
        &self,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Suppression>> {
        let pattern = format!("%{}%", search.unwrap_or(""));
        let rows = sqlx::query_as!(
            Row,
            "SELECT address, scope, reason, source_delivery_id, created_at FROM suppressions
             WHERE address LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            pattern,
            limit,
            offset
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(Suppression::try_from).collect()
    }

    /// Count a soft bounce. Suppresses the address once it reaches the limit within the
    /// window; returns true when that happened.
    pub async fn record_soft_bounce(&self, address: &str, delivery_id: &str) -> Result<bool> {
        let now = now_ms();
        let since = now - SOFT_BOUNCE_WINDOW_MS;
        let mut tx = self.write.begin().await?;
        sqlx::query!(
            "INSERT INTO soft_bounces (address, delivery_id, at) VALUES (?, ?, ?)",
            address,
            delivery_id,
            now
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("DELETE FROM soft_bounces WHERE at < ?", since).execute(&mut *tx).await?;
        let n = sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "n!: i64" FROM soft_bounces WHERE address = ? AND at >= ?"#,
            address,
            since
        )
        .fetch_one(&mut *tx)
        .await?;
        let suppressed = n >= SOFT_BOUNCE_LIMIT;
        if suppressed {
            insert(&mut tx, address, SuppressionScope::All, SuppressionReason::SoftBounce, Some(delivery_id))
                .await?;
        }
        tx.commit().await?;
        Ok(suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_db;

    #[tokio::test]
    async fn scopes_and_soft_bounces() {
        let db = test_db().await;
        db.add_suppression("a@x.com", SuppressionScope::Broadcast, SuppressionReason::Unsubscribe, None)
            .await
            .unwrap();
        assert!(db.is_suppressed("a@x.com", Stream::Broadcast).await.unwrap());
        assert!(!db.is_suppressed("a@x.com", Stream::Transactional).await.unwrap());
        let among =
            db.suppressed_among(&["a@x.com".into(), "b@x.com".into()], Stream::Broadcast).await.unwrap();
        assert_eq!(among, vec!["a@x.com".to_string()]);
        assert_eq!(db.list_suppressions(Some("x.com"), 10, 0).await.unwrap().len(), 1);
        assert_eq!(db.remove_suppression("a@x.com").await.unwrap(), 1);
        assert!(!db.is_suppressed("a@x.com", Stream::Broadcast).await.unwrap());

        for i in 0..4 {
            assert!(!db.record_soft_bounce("s@x.com", &format!("d{i}")).await.unwrap());
        }
        assert!(db.record_soft_bounce("s@x.com", "d5").await.unwrap());
        assert!(db.is_suppressed("s@x.com", Stream::Transactional).await.unwrap());
        assert_eq!(db.get_suppressions("s@x.com").await.unwrap()[0].reason, SuppressionReason::SoftBounce);
    }
}
