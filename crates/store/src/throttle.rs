//! Per-domain limits and backoff.

use sigill_core::now_ms;

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DomainThrottle {
    pub rcpt_domain: String,
    pub max_conns: i64,
    pub max_per_minute: i64,
    pub backoff_until: Option<i64>,
}

impl Store {
    pub async fn throttles(&self) -> Result<Vec<DomainThrottle>> {
        Ok(sqlx::query_as!(
            DomainThrottle,
            "SELECT rcpt_domain, max_conns, max_per_minute, backoff_until FROM domain_throttle ORDER BY rcpt_domain"
        )
        .fetch_all(&self.read)
        .await?)
    }

    pub async fn upsert_throttle(&self, domain: &str, max_conns: i64, max_per_minute: i64) -> Result<()> {
        sqlx::query!(
            "INSERT INTO domain_throttle (rcpt_domain, max_conns, max_per_minute) VALUES (?, ?, ?)
             ON CONFLICT (rcpt_domain) DO UPDATE SET max_conns = excluded.max_conns,
                                                     max_per_minute = excluded.max_per_minute",
            domain,
            max_conns,
            max_per_minute
        )
        .execute(&self.write)
        .await?;
        Ok(())
    }

    /// Stop sending to a domain until `until` (unix ms). Never shortens an existing backoff.
    /// Domains without a row get one with default limits.
    pub async fn set_backoff(&self, domain: &str, until: i64) -> Result<()> {
        sqlx::query!(
            "INSERT INTO domain_throttle (rcpt_domain, max_conns, max_per_minute, backoff_until)
             VALUES (?, 10, 600, ?)
             ON CONFLICT (rcpt_domain) DO UPDATE SET
                 backoff_until = MAX(COALESCE(backoff_until, 0), excluded.backoff_until)",
            domain,
            until
        )
        .execute(&self.write)
        .await?;
        Ok(())
    }

    /// Domains currently in backoff.
    pub async fn backed_off_domains(&self) -> Result<Vec<(String, i64)>> {
        let now = now_ms();
        let rows = sqlx::query!(
            r#"SELECT rcpt_domain, backoff_until AS "backoff_until!: i64" FROM domain_throttle
               WHERE backoff_until > ? ORDER BY backoff_until DESC"#,
            now
        )
        .fetch_all(&self.read)
        .await?;
        Ok(rows.into_iter().map(|r| (r.rcpt_domain, r.backoff_until)).collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::test_db;
    use sigill_core::now_ms;

    #[tokio::test]
    async fn defaults_and_backoff() {
        let db = test_db().await;
        let t = db.throttles().await.unwrap();
        assert!(t.iter().any(|t| t.rcpt_domain == "gmail.com" && t.max_conns == 5));
        let until = now_ms() + 60_000;
        db.set_backoff("example.org", until).await.unwrap();
        db.set_backoff("example.org", until - 30_000).await.unwrap();
        assert_eq!(db.backed_off_domains().await.unwrap(), vec![("example.org".to_string(), until)]);
        db.upsert_throttle("example.org", 2, 30).await.unwrap();
        let t = db.throttles().await.unwrap();
        let e = t.iter().find(|t| t.rcpt_domain == "example.org").unwrap();
        assert_eq!((e.max_conns, e.max_per_minute, e.backoff_until), (2, 30, Some(until)));
    }
}
