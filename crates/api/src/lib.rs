//! Sigill HTTP API (JSON, for apps) and admin UI (server-rendered HTML).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};

pub use broadcasts::Scheduler as BroadcastScheduler;
use sigill_core::Config;
use sigill_core::secrets::Secrets;
use sigill_render::Signers;
use sigill_store::Store;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub mod admin;
pub mod auth;
pub mod broadcasts;
pub mod contacts;
pub mod error;
pub mod messages;
pub mod ratelimit;
pub mod send;
pub mod suppressions;
pub mod templates;
pub mod unsubscribe;

/// Shared state for every handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Arc<Config>,
    pub inner: Arc<Inner>,
}

pub struct Inner {
    pub secrets: Secrets,
    pub signers: Signers,
    pub key_cache: auth::KeyCache,
    pub rate_limiter: ratelimit::RateLimiter,
    /// Wakes the dispatcher when new deliveries are queued.
    pub wake: Arc<Notify>,
    /// Admin UI password; the admin UI is off without one.
    pub admin_password: Option<String>,
}

impl AppState {
    pub fn new(
        store: Store,
        config: Arc<Config>,
        secrets: Secrets,
        signers: Signers,
        wake: Arc<Notify>,
    ) -> Self {
        let rate_limiter = ratelimit::RateLimiter::new(config.server.rate_limit_per_sec);
        Self {
            store,
            config,
            inner: Arc::new(Inner {
                secrets,
                signers,
                key_cache: auth::KeyCache::default(),
                rate_limiter,
                wake,
                admin_password: None,
            }),
        }
    }

    /// Enable the admin UI with this password. Call before the state is shared.
    pub fn with_admin_password(mut self, password: Option<String>) -> Self {
        let password = password.filter(|p| !p.is_empty());
        match Arc::get_mut(&mut self.inner) {
            Some(inner) => inner.admin_password = password,
            None => panic!("with_admin_password must be called before the state is cloned"),
        }
        self
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/messages", post(messages::create))
        .route("/v1/messages/{id}", get(messages::get))
        .route("/v1/templates/{key}", put(templates::upload).get(templates::get))
        .route("/v1/templates/{key}/preview", post(templates::preview))
        .route("/v1/suppressions", post(suppressions::create))
        .route("/v1/suppressions/{address}", get(suppressions::get).delete(suppressions::delete))
        .route("/v1/contacts", post(contacts::create).get(contacts::list))
        .route("/v1/contacts/{id}", get(contacts::get).patch(contacts::update).delete(contacts::delete))
        .route("/v1/contacts/{id}/consents/{list}", put(contacts::grant).delete(contacts::revoke))
        .route("/v1/broadcasts", post(broadcasts::create))
        .route("/v1/broadcasts/{id}", get(broadcasts::get))
        .route("/v1/broadcasts/{id}/send", post(broadcasts::send_broadcast))
        .route("/v1/broadcasts/{id}/cancel", post(broadcasts::cancel))
        .route("/u/{token}", get(unsubscribe::confirm_page).post(unsubscribe::unsubscribe))
        .merge(admin::router())
        .with_state(state)
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
pub(crate) mod testing;
