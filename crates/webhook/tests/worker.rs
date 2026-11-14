//! The worker against a local HTTP receiver.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sigill_core::Stream;
use sigill_core::config::WebhookConfig;
use sigill_store::messages::{NewDelivery, NewMessage};
use sigill_store::queue::Outcome;
use sigill_store::testing::{TestDb, test_db};
use sigill_webhook::{WebhookWorker, signature};

#[derive(Default)]
struct Receiver {
    /// Status codes to answer with, in order; 200 once exhausted.
    script: Vec<u16>,
    got: Vec<(String, String)>,
}

async fn receiver(script: Vec<u16>) -> (String, Arc<Mutex<Receiver>>) {
    let state = Arc::new(Mutex::new(Receiver { script, got: Vec::new() }));
    let s = state.clone();
    let app = Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: String| {
            let s = s.clone();
            async move {
                let mut r = s.lock().unwrap();
                let sig = headers.get("sigill-signature").unwrap().to_str().unwrap().to_string();
                r.got.push((sig, body));
                let code = if r.script.is_empty() { 200 } else { r.script.remove(0) };
                StatusCode::from_u16(code).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state)
}

async fn seed(db: &TestDb, url: &str) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    db.create_app("app1", "app", "h", Some(url), Stream::Transactional).await.unwrap();
    let msg = NewMessage {
        id: "m1",
        app_id: "app1",
        idempotency_key: None,
        stream: Stream::Transactional,
        template_key: "t",
        template_version: 1,
        from_addr: "noreply@mail.example.com",
        subject: "s",
        rendered_mime: b"x",
        broadcast_id: None,
        priority: 0,
        not_before: None,
    };
    let d = NewDelivery {
        id: "d1".into(),
        rcpt: "a@x.test".into(),
        rcpt_domain: "x.test".into(),
        suppressed: false,
    };
    db.insert_message(&msg, &[d]).await.unwrap();
    db.complete(&[("d1".into(), Outcome::Sent { code: 250, response: "OK".into() })]).await.unwrap();
}

#[tokio::test]
async fn signs_retries_and_completes() {
    let db = test_db().await;
    let (url, rx) = receiver(vec![500]).await;
    seed(&db, &url).await;
    let secrets = sigill_testkit::secrets();
    let secret = secrets.webhook_secret("app1");
    let worker = WebhookWorker::new(db.store.clone(), secrets, &WebhookConfig::default()).unwrap();

    let now = sigill_core::now_ms() + 1;
    assert_eq!(worker.tick_at(now).await.unwrap(), 1);
    assert_eq!(db.webhook_backlog().await.unwrap(), 1, "kept for a retry");
    assert_eq!(worker.tick_at(now).await.unwrap(), 0, "not due yet");

    assert_eq!(worker.tick_at(now + sigill_webhook::BASE_DELAY_MS + 1).await.unwrap(), 1);
    assert_eq!(db.webhook_backlog().await.unwrap(), 0);

    let got = rx.lock().unwrap().got.clone();
    assert_eq!(got.len(), 2);
    let (sig, body) = &got[1];
    let payload: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!((payload["event"].as_str(), payload["delivery_id"].as_str()), (Some("delivered"), Some("d1")));
    let ts: i64 = sig.trim_start_matches("t=").split(',').next().unwrap().parse().unwrap();
    assert_eq!(sig, &signature(&secret, ts, body));
}

#[tokio::test]
async fn gives_up_after_max_attempts() {
    let db = test_db().await;
    let (url, rx) = receiver(vec![500, 500, 500]).await;
    seed(&db, &url).await;
    let cfg = WebhookConfig { max_attempts: 2, ..Default::default() };
    let worker = WebhookWorker::new(db.store.clone(), sigill_testkit::secrets(), &cfg).unwrap();
    let far = sigill_core::now_ms() + sigill_webhook::MAX_DELAY_MS + 1;
    worker.tick_at(far).await.unwrap();
    worker.tick_at(far * 2).await.unwrap();
    assert_eq!(db.webhook_backlog().await.unwrap(), 0, "dropped after two attempts");
    assert_eq!(rx.lock().unwrap().got.len(), 2);
}
