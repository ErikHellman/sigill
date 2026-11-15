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
    // Apps may lift manual and bounce suppressions. A complaint or an unsubscribe is the
    // recipient's decision; only the owner can remove those, in the admin UI.
    match state.store.remove_liftable_suppressions(&address).await? {
        (0, 0) => Err(ApiError::not_found("suppression")),
        (_, 0) => {
            tracing::info!("suppression removed via API");
            Ok(StatusCode::NO_CONTENT)
        }
        _ => Err(ApiError::new(
            StatusCode::CONFLICT,
            "suppression_protected",
            "the recipient complained or unsubscribed; this suppression can only be removed in the admin UI",
        )),
    }
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

    #[tokio::test]
    async fn complaints_and_unsubscribes_cannot_be_lifted_by_apps() {
        use sigill_core::{Stream, SuppressionReason, SuppressionScope};
        let t = TestApp::new().await;
        for (addr, scope, reason) in [
            ("c@x.com", SuppressionScope::All, SuppressionReason::Complaint),
            ("u@x.com", SuppressionScope::Broadcast, SuppressionReason::Unsubscribe),
            ("b@x.com", SuppressionScope::All, SuppressionReason::HardBounce),
        ] {
            t.db.add_suppression(addr, scope, reason, None).await.unwrap();
        }
        for addr in ["c@x.com", "u@x.com"] {
            let (s, v) = t.call(Method::DELETE, &format!("/v1/suppressions/{addr}"), None).await;
            assert_eq!(s, StatusCode::CONFLICT, "{v}");
            assert_eq!(v["error"]["code"], "suppression_protected");
            assert!(t.db.is_suppressed(addr, Stream::Broadcast).await.unwrap());
        }
        let (s, _) = t.call(Method::DELETE, "/v1/suppressions/b@x.com", None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        assert!(!t.db.is_suppressed("b@x.com", Stream::Transactional).await.unwrap());
    }
}
