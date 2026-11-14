//! Mirror of config-defined sending domains and IP pools, for the admin view.

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SendingDomain {
    pub domain: String,
    pub stream: String,
    pub dkim_selector: String,
    pub dkim_public_keys: String,
    pub return_path_domain: String,
    pub verified_at: Option<i64>,
}

impl Store {
    /// Replace the sending domains with the configured set, keeping `verified_at` for
    /// domains that stay.
    pub async fn sync_sending_domains(&self, domains: &[SendingDomain]) -> Result<()> {
        let mut tx = self.write.begin().await?;
        let names: Vec<String> = domains.iter().map(|d| d.domain.clone()).collect();
        let keep = serde_json::to_string(&names).expect("strings serialise");
        sqlx::query!(
            "DELETE FROM sending_domains WHERE domain NOT IN (SELECT value FROM json_each(?))",
            keep
        )
        .execute(&mut *tx)
        .await?;
        for d in domains {
            sqlx::query!(
                "INSERT INTO sending_domains (domain, stream, dkim_selector, dkim_public_keys, return_path_domain)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (domain) DO UPDATE SET stream = excluded.stream, dkim_selector = excluded.dkim_selector,
                     dkim_public_keys = excluded.dkim_public_keys, return_path_domain = excluded.return_path_domain",
                d.domain,
                d.stream,
                d.dkim_selector,
                d.dkim_public_keys,
                d.return_path_domain
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn sending_domains(&self) -> Result<Vec<SendingDomain>> {
        Ok(sqlx::query_as!(
            SendingDomain,
            "SELECT domain, stream, dkim_selector, dkim_public_keys, return_path_domain, verified_at
             FROM sending_domains ORDER BY domain"
        )
        .fetch_all(&self.read)
        .await?)
    }

    /// Record that `dns-check` passed for a domain.
    pub async fn mark_domain_verified(&self, domain: &str, at: Option<i64>) -> Result<()> {
        sqlx::query!("UPDATE sending_domains SET verified_at = ? WHERE domain = ?", at, domain)
            .execute(&self.write)
            .await?;
        Ok(())
    }

    pub async fn sync_ip_pool(&self, name: &str, ips: &[String], helo_hostname: &str) -> Result<()> {
        let ips = serde_json::to_string(ips).expect("strings serialise");
        sqlx::query!(
            "INSERT INTO ip_pools (name, ips, helo_hostname) VALUES (?, ?, ?)
             ON CONFLICT (name) DO UPDATE SET ips = excluded.ips, helo_hostname = excluded.helo_hostname",
            name,
            ips,
            helo_hostname
        )
        .execute(&self.write)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_db;

    #[tokio::test]
    async fn sync_replaces_set() {
        let db = test_db().await;
        let d = |name: &str| SendingDomain {
            domain: name.into(),
            stream: "transactional".into(),
            dkim_selector: "s1".into(),
            dkim_public_keys: "{}".into(),
            return_path_domain: "b.example.com".into(),
            verified_at: None,
        };
        db.sync_sending_domains(&[d("a.example.com"), d("b.example.com")]).await.unwrap();
        db.mark_domain_verified("a.example.com", Some(5)).await.unwrap();
        db.sync_sending_domains(&[d("a.example.com")]).await.unwrap();
        let all = db.sending_domains().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].verified_at, Some(5));
        db.sync_ip_pool("transactional", &["192.0.2.1".into()], "mta1.example.com").await.unwrap();
    }
}
