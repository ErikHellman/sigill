//! Sigill HTTP API (JSON, for apps) and admin UI (server-rendered HTML).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use sigill_core::Config;
use sigill_store::Store;
use tokio_util::sync::CancellationToken;

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    Router::new().route("/healthz", get(healthz)).with_state(state)
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match state.store.ping().await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(e) => {
            tracing::error!(error = %e, "health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}

/// Serve the API until `shutdown` is cancelled.
pub async fn serve(state: AppState, shutdown: CancellationToken) -> std::io::Result<()> {
    let addr = state.config.server.listen;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP API listening");
    axum::serve(listener, router(state)).with_graceful_shutdown(shutdown.cancelled_owned()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_ok() {
        let db = sigill_store::testing::test_db().await;
        let state = AppState { store: db.store.clone(), config: Arc::new(Config::default()) };
        let res = router(state).oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
