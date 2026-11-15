use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use crate::router;
use crate::testing::TestApp;

async fn admin_app() -> TestApp {
    TestApp::with_admin("s3cret").await
}

async fn req(
    t: &TestApp,
    method: Method,
    path: &str,
    auth: Option<&str>,
    form: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(path).header(header::HOST, "admin.test");
    if let Some(pw) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("admin:{pw}"));
        b = b.header(header::AUTHORIZATION, format!("Basic {token}"));
    }
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    let body = match form {
        Some(f) => {
            b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(f.to_string())
        }
        None => Body::empty(),
    };
    let res = router(t.state.clone()).oneshot(b.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn disabled_without_password() {
    let t = TestApp::new().await;
    let (s, _) = req(&t, Method::GET, "/admin/messages", Some("x"), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn requires_basic_auth() {
    let t = admin_app().await;
    assert_eq!(req(&t, Method::GET, "/admin/queue", None, None, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        req(&t, Method::GET, "/admin/queue", Some("wrong"), None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, body) = req(&t, Method::GET, "/admin/queue", Some("s3cret"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("gmail.com"), "seeded throttles are listed");
}

#[tokio::test]
async fn pages_render() {
    let t = admin_app().await;
    t.template("welcome").await;
    let (s, v) = t
        .call(
            Method::POST,
            "/v1/messages",
            Some(json!({"template": "welcome", "to": ["<b>x</b>@x.test", "ann@x.test"], "variables": {"name": "<script>"}})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = t
        .call(
            Method::POST,
            "/v1/messages",
            Some(json!({"template": "welcome", "to": ["ann@x.test"], "variables": {"name": "<i>Ann</i>"}})),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let id = v["message_id"].as_str().unwrap();

    let (s, body) = req(&t, Method::GET, "/admin/messages?q=ann@", Some("s3cret"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains(id));
    assert!(
        body.contains("Hello &#60;i&#62;Ann&#60;/i&#62;") || body.contains("Hello &lt;i&gt;Ann&lt;/i&gt;"),
        "escaped: {body}"
    );

    let (s, body) = req(&t, Method::GET, &format!("/admin/messages/{id}"), Some("s3cret"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("ann@x.test") && body.contains("queued"));
    assert_eq!(
        req(&t, Method::GET, "/admin/messages/nope", Some("s3cret"), None, None).await.0,
        StatusCode::NOT_FOUND
    );

    for page in ["/admin/dns", "/admin/dmarc", "/admin/suppressions"] {
        let (s, body) = req(&t, Method::GET, page, Some("s3cret"), None, None).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        assert!(body.contains("<nav>"));
    }
    let (_, body) = req(&t, Method::GET, "/admin/dns", Some("s3cret"), None, None).await;
    assert!(body.contains("t1r._domainkey.mail.example.com"));
    assert!(body.contains("v=DMARC1; p=none; rua=mailto:dmarc@bounces.example.com"));
}

#[tokio::test]
async fn manages_suppressions_same_origin_only() {
    let t = admin_app().await;
    let (s, _) = req(
        &t,
        Method::POST,
        "/admin/suppressions",
        Some("s3cret"),
        Some("address=x%40y.test&scope=all"),
        Some("https://evil.test"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(t.db.get_suppressions("x@y.test").await.unwrap().is_empty());

    let (s, _) = req(
        &t,
        Method::POST,
        "/admin/suppressions",
        Some("s3cret"),
        Some("address=X%40y.test&scope=broadcast"),
        Some("http://admin.test"),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(t.db.get_suppressions("x@y.test").await.unwrap().len(), 1);
    let (_, body) =
        req(&t, Method::GET, "/admin/suppressions?notice=added", Some("s3cret"), None, None).await;
    assert!(body.contains("Suppression added.") && body.contains("x@y.test"));

    let (s, _) =
        req(&t, Method::POST, "/admin/suppressions/delete", Some("s3cret"), Some("address=x%40y.test"), None)
            .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(t.db.get_suppressions("x@y.test").await.unwrap().is_empty());
}

#[tokio::test]
async fn failed_logins_are_throttled() {
    let t = admin_app().await;
    for _ in 0..super::throttle::MAX_FAILURES_PER_CLIENT {
        let (s, _) = req(&t, Method::GET, "/admin/queue", Some("wrong"), None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _) = req(&t, Method::GET, "/admin/queue", Some("wrong"), None, None).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (s, _) = req(&t, Method::GET, "/admin/queue", Some("s3cret"), None, None).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "a blocked client cannot keep guessing");
}

#[tokio::test]
async fn missing_credentials_are_not_counted() {
    let t = admin_app().await;
    for _ in 0..(super::throttle::MAX_FAILURES_PER_CLIENT * 2) {
        let (s, _) = req(&t, Method::GET, "/admin/queue", None, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _) = req(&t, Method::GET, "/admin/queue", Some("s3cret"), None, None).await;
    assert_eq!(s, StatusCode::OK);
}
