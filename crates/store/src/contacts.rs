//! Broadcast contacts and their consent records.

use sigill_core::{new_id, now_ms};

use crate::{Error, Result, Store};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Contact {
    pub id: String,
    pub app_id: String,
    pub email: String,
    pub name: Option<String>,
    pub attributes: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Consent {
    pub contact_id: String,
    pub list: String,
    pub granted_at: i64,
    pub source: String,
    pub revoked_at: Option<i64>,
}

struct Row {
    id: String,
    app_id: String,
    email: String,
    name: Option<String>,
    attributes: String,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<Row> for Contact {
    type Error = Error;
    fn try_from(r: Row) -> Result<Self> {
        Ok(Contact {
            id: r.id,
            app_id: r.app_id,
            email: r.email,
            name: r.name,
            attributes: serde_json::from_str(&r.attributes).map_err(|e| Error::Invalid(e.to_string()))?,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

impl Store {
    /// Create a contact. `email` must already be normalised by the caller.
    pub async fn create_contact(
        &self,
        app_id: &str,
        email: &str,
        name: Option<&str>,
        attributes: &serde_json::Value,
    ) -> Result<Contact> {
        let id = new_id();
        let now = now_ms();
        let attrs = attributes.to_string();
        sqlx::query!(
            "INSERT INTO contacts (id, app_id, email, name, attributes, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            id,
            app_id,
            email,
            name,
            attrs,
            now,
            now
        )
        .execute(&self.write)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                Error::Conflict("contact already exists".into())
            }
            other => other.into(),
        })?;
        self.get_contact(app_id, &id).await?.ok_or(Error::NotFound)
    }

    pub async fn get_contact(&self, app_id: &str, id: &str) -> Result<Option<Contact>> {
        let r = sqlx::query_as!(
            Row,
            "SELECT id, app_id, email, name, attributes, created_at, updated_at FROM contacts
             WHERE app_id = ? AND id = ?",
            app_id,
            id
        )
        .fetch_optional(&self.write)
        .await?;
        r.map(Contact::try_from).transpose()
    }

    pub async fn contact_by_email(&self, app_id: &str, email: &str) -> Result<Option<Contact>> {
        let r = sqlx::query_as!(
            Row,
            "SELECT id, app_id, email, name, attributes, created_at, updated_at FROM contacts
             WHERE app_id = ? AND email = ?",
            app_id,
            email
        )
        .fetch_optional(&self.read)
        .await?;
        r.map(Contact::try_from).transpose()
    }

    pub async fn list_contacts(&self, app_id: &str, limit: i64, offset: i64) -> Result<Vec<Contact>> {
        let rows = sqlx::query_as!(
            Row,
            "SELECT id, app_id, email, name, attributes, created_at, updated_at FROM contacts
             WHERE app_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?",
            app_id,
            limit,
            offset
        )
        .fetch_all(&self.read)
        .await?;
        rows.into_iter().map(Contact::try_from).collect()
    }

    /// Update name and/or attributes; `None` leaves a field unchanged.
    pub async fn update_contact(
        &self,
        app_id: &str,
        id: &str,
        name: Option<&str>,
        attributes: Option<&serde_json::Value>,
    ) -> Result<Contact> {
        let now = now_ms();
        let attrs = attributes.map(|a| a.to_string());
        let r = sqlx::query!(
            "UPDATE contacts SET name = COALESCE(?, name), attributes = COALESCE(?, attributes), updated_at = ?
             WHERE app_id = ? AND id = ?",
            name,
            attrs,
            now,
            app_id,
            id
        )
        .execute(&self.write)
        .await?;
        if r.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        self.get_contact(app_id, id).await?.ok_or(Error::NotFound)
    }

    pub async fn delete_contact(&self, app_id: &str, id: &str) -> Result<()> {
        let r = sqlx::query!("DELETE FROM contacts WHERE app_id = ? AND id = ?", app_id, id)
            .execute(&self.write)
            .await?;
        if r.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Record (or renew) consent for a list.
    pub async fn grant_consent(&self, contact_id: &str, list: &str, source: &str) -> Result<Consent> {
        let now = now_ms();
        sqlx::query!(
            "INSERT INTO consents (contact_id, list, granted_at, source, revoked_at) VALUES (?, ?, ?, ?, NULL)
             ON CONFLICT (contact_id, list) DO UPDATE SET granted_at = excluded.granted_at,
                 source = excluded.source, revoked_at = NULL",
            contact_id,
            list,
            now,
            source
        )
        .execute(&self.write)
        .await?;
        Ok(Consent {
            contact_id: contact_id.into(),
            list: list.into(),
            granted_at: now,
            source: source.into(),
            revoked_at: None,
        })
    }

    /// Revoke consent; the record is kept as proof of the earlier opt-in.
    pub async fn revoke_consent(&self, contact_id: &str, list: &str) -> Result<bool> {
        let now = now_ms();
        let r = sqlx::query!(
            "UPDATE consents SET revoked_at = ? WHERE contact_id = ? AND list = ? AND revoked_at IS NULL",
            now,
            contact_id,
            list
        )
        .execute(&self.write)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Revoke every active consent an app's contact with this email has.
    pub async fn revoke_all_consents_by_email(&self, app_id: &str, email: &str) -> Result<u64> {
        let now = now_ms();
        let r = sqlx::query!(
            "UPDATE consents SET revoked_at = ?
             WHERE revoked_at IS NULL AND contact_id IN (SELECT id FROM contacts WHERE app_id = ? AND email = ?)",
            now,
            app_id,
            email
        )
        .execute(&self.write)
        .await?;
        Ok(r.rows_affected())
    }

    pub async fn consents_for(&self, contact_id: &str) -> Result<Vec<Consent>> {
        Ok(sqlx::query_as!(
            Consent,
            "SELECT contact_id, list, granted_at, source, revoked_at FROM consents WHERE contact_id = ? ORDER BY list",
            contact_id
        )
        .fetch_all(&self.write)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::test_db;
    use serde_json::json;
    use sigill_core::Stream;

    #[tokio::test]
    async fn contact_crud_and_consent() {
        let db = test_db().await;
        db.create_app("app", "app", "h", None, Stream::Transactional).await.unwrap();
        let c = db.create_contact("app", "a@x.com", Some("A"), &json!({"plan": "pro"})).await.unwrap();
        assert!(db.create_contact("app", "a@x.com", None, &json!({})).await.is_err());
        let c2 = db.update_contact("app", &c.id, None, Some(&json!({"plan": "free"}))).await.unwrap();
        assert_eq!(c2.name.as_deref(), Some("A"));
        assert_eq!(c2.attributes["plan"], "free");
        assert_eq!(db.contact_by_email("app", "a@x.com").await.unwrap().unwrap().id, c.id);
        db.grant_consent(&c.id, "news", "signup form").await.unwrap();
        assert!(db.revoke_consent(&c.id, "news").await.unwrap());
        assert!(!db.revoke_consent(&c.id, "news").await.unwrap());
        db.grant_consent(&c.id, "news", "settings page").await.unwrap();
        assert_eq!(db.revoke_all_consents_by_email("app", "a@x.com").await.unwrap(), 1);
        let cs = db.consents_for(&c.id).await.unwrap();
        assert!(cs[0].revoked_at.is_some());
        assert_eq!(db.list_contacts("app", 10, 0).await.unwrap().len(), 1);
        db.delete_contact("app", &c.id).await.unwrap();
        assert!(db.get_contact("app", &c.id).await.unwrap().is_none());
    }
}
