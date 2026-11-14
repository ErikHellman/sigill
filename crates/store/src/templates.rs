//! Versioned templates, one row per uploaded version.

use sigill_core::now_ms;

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Template {
    pub app_id: String,
    pub key: String,
    pub version: i64,
    pub subject_tpl: String,
    pub html_tpl: String,
    pub text_tpl: String,
    pub mjml_src: Option<String>,
    pub created_at: i64,
}

pub struct NewTemplate<'a> {
    pub subject_tpl: &'a str,
    pub html_tpl: &'a str,
    pub text_tpl: &'a str,
    pub mjml_src: Option<&'a str>,
}

impl Store {
    /// Store a new version and return it. Versions start at 1 and increase per key.
    pub async fn insert_template(&self, app_id: &str, key: &str, t: NewTemplate<'_>) -> Result<Template> {
        let now = now_ms();
        let mut tx = self.write.begin().await?;
        let version = sqlx::query_scalar!(
            r#"SELECT COALESCE(MAX(version), 0) + 1 AS "v!: i64" FROM templates WHERE app_id = ? AND key = ?"#,
            app_id,
            key
        )
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO templates (app_id, key, version, subject_tpl, html_tpl, text_tpl, mjml_src, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            app_id,
            key,
            version,
            t.subject_tpl,
            t.html_tpl,
            t.text_tpl,
            t.mjml_src,
            now
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Template {
            app_id: app_id.into(),
            key: key.into(),
            version,
            subject_tpl: t.subject_tpl.into(),
            html_tpl: t.html_tpl.into(),
            text_tpl: t.text_tpl.into(),
            mjml_src: t.mjml_src.map(Into::into),
            created_at: now,
        })
    }

    /// A specific version, or the latest when `version` is `None`.
    pub async fn get_template(
        &self,
        app_id: &str,
        key: &str,
        version: Option<i64>,
    ) -> Result<Option<Template>> {
        let t = match version {
            Some(v) => {
                sqlx::query_as!(
                    Template,
                    "SELECT app_id, key, version, subject_tpl, html_tpl, text_tpl, mjml_src, created_at
                     FROM templates WHERE app_id = ? AND key = ? AND version = ?",
                    app_id,
                    key,
                    v
                )
                .fetch_optional(&self.read)
                .await?
            }
            None => {
                sqlx::query_as!(
                    Template,
                    "SELECT app_id, key, version, subject_tpl, html_tpl, text_tpl, mjml_src, created_at
                     FROM templates WHERE app_id = ? AND key = ? ORDER BY version DESC LIMIT 1",
                    app_id,
                    key
                )
                .fetch_optional(&self.read)
                .await?
            }
        };
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::NewTemplate;
    use crate::testing::test_db;
    use sigill_core::Stream;

    #[tokio::test]
    async fn versions_increase() {
        let db = test_db().await;
        db.create_app("a", "a", "h", None, Stream::Transactional).await.unwrap();
        let t = |s| NewTemplate { subject_tpl: s, html_tpl: "<p>x</p>", text_tpl: "x", mjml_src: None };
        assert_eq!(db.insert_template("a", "welcome", t("v1")).await.unwrap().version, 1);
        assert_eq!(db.insert_template("a", "welcome", t("v2")).await.unwrap().version, 2);
        assert_eq!(db.get_template("a", "welcome", None).await.unwrap().unwrap().subject_tpl, "v2");
        assert_eq!(db.get_template("a", "welcome", Some(1)).await.unwrap().unwrap().subject_tpl, "v1");
        assert!(db.get_template("a", "other", None).await.unwrap().is_none());
    }
}
