//! Suppression list endpoints. The list is global: Sigill serves one owner's apps.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sigill_core::address::normalize;
use sigill_core::{SuppressionReason, SuppressionScope};

use crate::AppState;
use crate::auth::AuthApp;
use crate::error::{ApiError, ApiResult};

fn norm(address: &str) -> ApiResult<String> {
    normalize(address).ok_or_else(|| ApiError::invalid("invalid address"))
}

pub async fn get(
    State(state): State<AppState>,
    _app: AuthApp,
    Path(address): Path<String>,
) -> ApiResult<Json<Value>> {
    let address = norm(&address)?;
    let rows = state.store.get_suppressions(&address).await?;
    if rows.is_empty() {
        return Err(ApiError::not_found("suppression"));
    }
    Ok(Json(json!({"address": address, "suppressions": rows})))
}

pub async fn delete(
    State(state): State<AppState>,
    _app: AuthApp,
    Path(address): Path<String>,
) -> ApiResult<StatusCode> {
    let address = norm(&address)?;
    if state.store.remove_suppression(&address).await? == 0 {
        return Err(ApiError::not_found("suppression"));
    }
    tracing::info!("suppression removed via API");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSuppression {
    pub address: String,
    pub scope: Option<SuppressionScope>,
}

pub async fn create(
    State(state): State<AppState>,
    _app: AuthApp,
    Json(req): Json<CreateSuppression>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let address = norm(&req.address)?;
    let scope = req.scope.unwrap_or(SuppressionScope::All);
    state.store.add_suppression(&address, scope, SuppressionReason::Manual, None).await?;
    Ok((StatusCode::CREATED, Json(json!({"address": address, "scope": scope}))))
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use serde_json::json;

    use crate::testing::TestApp;

    #[tokio::test]
    async fn crud() {
        let t = TestApp::new().await;
        let (s, _) = t.call(Method::GET, "/v1/suppressions/a@x.com", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, v) = t
            .call(Method::POST, "/v1/suppressions", Some(json!({"address": "A@X.com", "scope": "broadcast"})))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let (s, v) = t.call(Method::GET, "/v1/suppressions/a@x.com", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["suppressions"][0]["reason"], "manual");
        assert_eq!(v["suppressions"][0]["scope"], "broadcast");
        let (s, _) = t.call(Method::DELETE, "/v1/suppressions/a@x.com", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = t.call(Method::DELETE, "/v1/suppressions/a@x.com", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}
