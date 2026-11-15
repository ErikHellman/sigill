//! Calling apps and their API keys.

use sigill_core::{Stream, new_id, now_ms};

use crate::{Result, Store, parse};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct App {
    pub id: String,
    pub name: String,
    #[serde(skip)]
    pub api_key_hash: String,
    pub webhook_url: Option<String>,
    pub default_stream: Stream,
    /// Version of the webhook signing secret; raised to rotate it.
    pub webhook_secret_version: i64,
    pub created_at: i64,
}

struct Row {
    id: String,
    name: String,
    api_key_hash: String,
    webhook_url: Option<String>,
    default_stream: String,
    webhook_secret_version: i64,
    created_at: i64,
}

impl TryFrom<Row> for App {
    type Error = crate::Error;
    fn try_from(r: Row) -> Result<Self> {
        Ok(App {
            id: r.id,
            name: r.name,
            api_key_hash: r.api_key_hash,
            webhook_url: r.webhook_url,
            default_stream: parse(&r.default_stream)?,
            webhook_secret_version: r.webhook_secret_version,
            created_at: r.created_at,
        })
    }
}

impl Store {
    /// Create an app. `id` is chosen by the caller because the API key embeds it.
    pub async fn create_app(
        &self,
        id: &str,
        name: &str,
        api_key_hash: &str,
        webhook_url: Option<&str>,
        default_stream: Stream,
    ) -> Result<App> {
        let now = now_ms();
        let stream = default_stream.as_str();
        sqlx::query!(
            "INSERT INTO apps (id, name, api_key_hash, webhook_url, default_stream, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            id,
            name,
            api_key_hash,
            webhook_url,
            stream,
            now
        )
        .execute(&self.write)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                crate::Error::Conflict(format!("an app named {name:?} already exists"))
            }
            other => other.into(),
        })?;
        self.get_app(id).await?.ok_or(crate::Error::NotFound)
    }

    pub async fn get_app(&self, id: &str) -> Result<Option<App>> {
        let row = sqlx::query_as!(
            Row,
            "SELECT id, name, api_key_hash, webhook_url, default_stream, webhook_secret_version, created_at
             FROM apps WHERE id = ?",
            id
        )
        .fetch_optional(&self.read)
        .await?;
        row.map(App::try_from).transpose()
    }

    pub async fn list_apps(&self) -> Result<Vec<App>> {
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, name, api_key_hash, webhook_url, default_stream, webhook_secret_version, created_at
             FROM apps ORDER BY name"
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(App::try_from).collect()
    }

    pub async fn set_app_webhook(&self, id: &str, webhook_url: Option<&str>) -> Result<()> {
        let r = sqlx::query!("UPDATE apps SET webhook_url = ? WHERE id = ?", webhook_url, id)
            .execute(&self.write)
            .await?;
        if r.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }

    /// Rotate the app's webhook signing secret. Returns the new version.
    pub async fn bump_webhook_secret_version(&self, id: &str) -> Result<i64> {
        let v = sqlx::query_scalar!(
            r#"UPDATE apps SET webhook_secret_version = webhook_secret_version + 1 WHERE id = ?
               RETURNING webhook_secret_version AS "v!: i64""#,
            id
        )
        .fetch_optional(&self.write)
        .await?;
        v.ok_or(crate::Error::NotFound)
    }

    pub async fn set_app_key_hash(&self, id: &str, api_key_hash: &str) -> Result<()> {
        let r = sqlx::query!("UPDATE apps SET api_key_hash = ? WHERE id = ?", api_key_hash, id)
            .execute(&self.write)
            .await?;
        if r.rows_affected() == 0 {
            return Err(crate::Error::NotFound);
        }
        Ok(())
    }
}

/// Fresh app id.
pub fn new_app_id() -> String {
    new_id()
}

#[cfg(test)]
mod tests {
    use crate::testing::test_db;
    use sigill_core::Stream;

    #[tokio::test]
    async fn create_get_and_conflict() {
        let db = test_db().await;
        let app = db.create_app("a1", "shop", "hash", None, Stream::Transactional).await.unwrap();
        assert_eq!(app.name, "shop");
        assert!(db.create_app("a2", "shop", "hash", None, Stream::Transactional).await.is_err());
        db.set_app_webhook("a1", Some("https://x.test/hook")).await.unwrap();
        assert_eq!(
            db.get_app("a1").await.unwrap().unwrap().webhook_url.as_deref(),
            Some("https://x.test/hook")
        );
        assert_eq!(db.list_apps().await.unwrap().len(), 1);
        assert_eq!(app.webhook_secret_version, 0);
        assert_eq!(db.bump_webhook_secret_version("a1").await.unwrap(), 1);
        assert_eq!(db.get_app("a1").await.unwrap().unwrap().webhook_secret_version, 1);
        assert!(db.bump_webhook_secret_version("nope").await.is_err());
    }
}
