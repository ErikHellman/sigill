//! Contacts and consent endpoints. Contacts belong to the calling app.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sigill_core::address::Address;

use crate::AppState;
use crate::auth::AuthApp;
use crate::error::{ApiError, ApiResult};

/// List names: 1 to 64 characters of `a-z 0-9 . _ -`.
pub fn check_list(list: &str) -> ApiResult<()> {
    let ok = !list.is_empty()
        && list.len() <= 64
        && list.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid("list names are 1-64 characters of a-z, 0-9, '.', '_' or '-'"))
    }
}

fn attributes(v: Value) -> ApiResult<Value> {
    match v {
        Value::Null => Ok(json!({})),
        Value::Object(_) => Ok(v),
        _ => Err(ApiError::invalid("`attributes` must be an object")),
    }
}

async fn contact_json(state: &AppState, app_id: &str, id: &str) -> ApiResult<Value> {
    let c = state.store.get_contact(app_id, id).await?.ok_or_else(|| ApiError::not_found("contact"))?;
    let consents = state.store.consents_for(&c.id).await?;
    let mut v = serde_json::to_value(&c).map_err(ApiError::internal)?;
    v["consents"] = serde_json::to_value(consents).map_err(ApiError::internal)?;
    Ok(v)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateContact {
    pub email: String,
    pub name: Option<String>,
    #[serde(default)]
    pub attributes: Value,
    /// Lists to grant consent for right away.
    #[serde(default)]
    pub lists: Vec<String>,
    /// Where the consent came from, such as `signup-form`; defaults to `api`.
    pub source: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Json(req): Json<CreateContact>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let email = Address::parse(&req.email).map_err(|e| ApiError::invalid(format!("invalid `email`: {e}")))?;
    for l in &req.lists {
        check_list(l)?;
    }
    let c = state
        .store
        .create_contact(&app.id, &email.normalized(), req.name.as_deref(), &attributes(req.attributes)?)
        .await?;
    let source = req.source.as_deref().unwrap_or("api");
    for l in &req.lists {
        state.store.grant_consent(&c.id, l, source).await?;
    }
    Ok((StatusCode::CREATED, Json(contact_json(&state, &app.id, &c.id).await?)))
}

#[derive(Debug, Deserialize)]
pub struct Page {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Look a contact up by address instead of listing.
    pub email: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Query(q): Query<Page>,
) -> ApiResult<Json<Value>> {
    if let Some(email) = q.email {
        let email =
            sigill_core::address::normalize(&email).ok_or_else(|| ApiError::invalid("invalid `email`"))?;
        let found = state.store.contact_by_email(&app.id, &email).await?;
        return Ok(Json(json!({ "contacts": found.into_iter().collect::<Vec<_>>() })));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);
    let contacts = state.store.list_contacts(&app.id, limit, offset).await?;
    Ok(Json(json!({ "contacts": contacts, "limit": limit, "offset": offset })))
}

pub async fn get(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(contact_json(&state, &app.id, &id).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateContact {
    pub name: Option<String>,
    pub attributes: Option<Value>,
}

pub async fn update(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
    Json(req): Json<UpdateContact>,
) -> ApiResult<Json<Value>> {
    let attrs = req.attributes.map(attributes).transpose()?;
    state.store.update_contact(&app.id, &id, req.name.as_deref(), attrs.as_ref()).await?;
    Ok(Json(contact_json(&state, &app.id, &id).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state.store.delete_contact(&app.id, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConsent {
    pub source: Option<String>,
}

pub async fn grant(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path((id, list)): Path<(String, String)>,
    body: Option<Json<GrantConsent>>,
) -> ApiResult<Json<Value>> {
    check_list(&list)?;
    let c = state.store.get_contact(&app.id, &id).await?.ok_or_else(|| ApiError::not_found("contact"))?;
    let source = body.and_then(|Json(b)| b.source).unwrap_or_else(|| "api".into());
    let consent = state.store.grant_consent(&c.id, &list, &source).await?;
    Ok(Json(serde_json::to_value(consent).map_err(ApiError::internal)?))
}

pub async fn revoke(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path((id, list)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let c = state.store.get_contact(&app.id, &id).await?.ok_or_else(|| ApiError::not_found("contact"))?;
    if state.store.revoke_consent(&c.id, &list).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("consent"))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use serde_json::json;

    use crate::testing::TestApp;

    #[tokio::test]
    async fn contact_lifecycle() {
        let t = TestApp::new().await;
        let (s, c) = t
            .call(
                Method::POST,
                "/v1/contacts",
                Some(json!({"email": "Ann@Example.com", "name": "Ann", "attributes": {"plan": "pro"}, "lists": ["news"]})),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{c}");
        assert_eq!(c["email"], "ann@example.com");
        assert_eq!(c["consents"][0]["list"], "news");
        let id = c["id"].as_str().unwrap().to_string();

        let (s, _) = t.call(Method::POST, "/v1/contacts", Some(json!({"email": "ann@example.com"}))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _) = t
            .call(Method::POST, "/v1/contacts", Some(json!({"email": "x@y.z", "lists": ["Bad List"]})))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        let (s, v) = t.call(Method::GET, "/v1/contacts?email=ANN@example.com", None).await;
        assert_eq!((s, v["contacts"][0]["id"].as_str()), (StatusCode::OK, Some(id.as_str())));

        let (s, v) = t
            .call(Method::PATCH, &format!("/v1/contacts/{id}"), Some(json!({"attributes": {"plan": "free"}})))
            .await;
        assert_eq!((s, &v["attributes"]["plan"]), (StatusCode::OK, &json!("free")));
        assert_eq!(v["name"], "Ann");

        let (s, _) = t.call(Method::PUT, &format!("/v1/contacts/{id}/consents/updates"), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = t.call(Method::DELETE, &format!("/v1/contacts/{id}/consents/news"), None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, v) = t.call(Method::GET, &format!("/v1/contacts/{id}"), None).await;
        let consents = v["consents"].as_array().unwrap();
        assert_eq!(consents.len(), 2);
        assert!(consents.iter().any(|c| c["list"] == "news" && !c["revoked_at"].is_null()));

        let (s, v) = t.call(Method::GET, "/v1/contacts", None).await;
        assert_eq!((s, v["contacts"].as_array().unwrap().len()), (StatusCode::OK, 1));
        let (s, _) = t.call(Method::DELETE, &format!("/v1/contacts/{id}"), None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = t.call(Method::GET, &format!("/v1/contacts/{id}"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}
