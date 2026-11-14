//! Test harness: router over a temp database with one app and the testkit domains.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sigill_core::Stream;
use sigill_store::testing::{TestDb, test_db};
use tower::ServiceExt;

use crate::{AppState, router};

pub struct TestApp {
    pub db: TestDb,
    pub state: AppState,
    pub key: String,
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with_config(sigill_testkit::config()).await
    }

    pub async fn with_config(config: sigill_core::Config) -> Self {
        let db = test_db().await;
        let secrets = sigill_testkit::secrets();
        let signers = sigill_render::Signers::load(&config.domains).unwrap();
        let app_id = sigill_core::new_id();
        let (key, hash) = crate::auth::generate_key(&app_id, &secrets.api_key_pepper());
        db.create_app(&app_id, "shop", &hash, Some("https://hooks.test/sigill"), Stream::Transactional)
            .await
            .unwrap();
        let state = AppState::new(db.store.clone(), Arc::new(config), secrets, signers, Default::default());
        Self { db, state, key }
    }

    pub async fn call(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call_with_key(method, path, body, Some(&self.key)).await
    }

    pub async fn call_with_key(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(k) = key {
            req = req.header("authorization", format!("Bearer {k}"));
        }
        let req = match body {
            Some(b) => {
                req.header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()
            }
            None => req.body(Body::empty()).unwrap(),
        };
        let res = router(self.state.clone()).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, value)
    }

    /// Upload a simple template under `key` and return its version.
    pub async fn template(&self, key: &str) -> i64 {
        let (s, v) = self
            .call(
                Method::PUT,
                &format!("/v1/templates/{key}"),
                Some(serde_json::json!({
                    "subject": "Hello {{ name }}",
                    "html": "<p>Hello {{ name }}</p>",
                    "text": "Hello {{ name }}",
                })),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        v["version"].as_i64().unwrap()
    }
}
