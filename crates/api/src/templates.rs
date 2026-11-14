//! Template upload (`PUT /v1/templates/{key}`), fetch and preview.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sigill_render::TemplateSource;
use sigill_store::templates::NewTemplate;

use crate::AppState;
use crate::auth::AuthApp;
use crate::error::{ApiError, ApiResult};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadTemplate {
    pub subject: String,
    pub text: String,
    /// HTML template (MiniJinja). Give either `html` or `mjml`.
    pub html: Option<String>,
    /// MJML layout, compiled to HTML now; MiniJinja expressions pass through.
    pub mjml: Option<String>,
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 100
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub async fn upload(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(key): Path<String>,
    Json(req): Json<UploadTemplate>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if !valid_key(&key) {
        return Err(ApiError::invalid("template keys use letters, digits, '-', '_' and '.' (max 100)"));
    }
    let html = match (&req.html, &req.mjml) {
        (Some(h), None) => h.clone(),
        (None, Some(m)) => sigill_render::compile_mjml(m)?,
        _ => return Err(ApiError::invalid("give exactly one of `html` or `mjml`")),
    };
    sigill_render::validate(&TemplateSource { subject: &req.subject, html: &html, text: &req.text })?;
    let t = state
        .store
        .insert_template(
            &app.id,
            &key,
            NewTemplate {
                subject_tpl: &req.subject,
                html_tpl: &html,
                text_tpl: &req.text,
                mjml_src: req.mjml.as_deref(),
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(json!({"key": t.key, "version": t.version, "created_at": t.created_at}))))
}

#[derive(Debug, Deserialize)]
pub struct VersionQuery {
    pub version: Option<i64>,
}

pub async fn get(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(key): Path<String>,
    Query(q): Query<VersionQuery>,
) -> ApiResult<Json<Value>> {
    let t = state
        .store
        .get_template(&app.id, &key, q.version)
        .await?
        .ok_or_else(|| ApiError::not_found("template"))?;
    Ok(Json(json!({
        "key": t.key, "version": t.version, "subject": t.subject_tpl, "html": t.html_tpl,
        "text": t.text_tpl, "mjml": t.mjml_src, "created_at": t.created_at,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub version: Option<i64>,
    #[serde(default)]
    pub variables: Value,
}

pub async fn preview(
    State(state): State<AppState>,
    AuthApp(app): AuthApp,
    Path(key): Path<String>,
    Json(req): Json<Preview>,
) -> ApiResult<Json<Value>> {
    let t = state
        .store
        .get_template(&app.id, &key, req.version)
        .await?
        .ok_or_else(|| ApiError::not_found("template"))?;
    let vars = if req.variables.is_null() { json!({}) } else { req.variables };
    let r = sigill_render::render(
        &TemplateSource { subject: &t.subject_tpl, html: &t.html_tpl, text: &t.text_tpl },
        &vars,
    )?;
    Ok(Json(
        json!({"key": t.key, "version": t.version, "subject": r.subject, "html": r.html, "text": r.text}),
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, StatusCode};
    use serde_json::json;

    use crate::testing::TestApp;

    #[tokio::test]
    async fn upload_versions_and_preview() {
        let t = TestApp::new().await;
        assert_eq!(t.template("welcome").await, 1);
        let (s, v) = t
            .call(
                Method::PUT,
                "/v1/templates/welcome",
                Some(json!({
                    "subject": "Hi {{ name }}",
                    "mjml": "<mjml><mj-body><mj-section><mj-column><mj-text>Hi {{ name }}</mj-text></mj-column></mj-section></mj-body></mjml>",
                    "text": "Hi {{ name }}",
                })),
            )
            .await;
        assert_eq!((s, v["version"].as_i64()), (StatusCode::CREATED, Some(2)));
        let (s, p) = t
            .call(Method::POST, "/v1/templates/welcome/preview", Some(json!({"variables": {"name": "<b>"}})))
            .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(p["version"], 2);
        assert_eq!(p["subject"], "Hi <b>");
        assert!(p["html"].as_str().unwrap().contains("Hi &lt;b&gt;"));
        let (_, p1) = t
            .call(
                Method::POST,
                "/v1/templates/welcome/preview",
                Some(json!({"version": 1, "variables": {"name": "A"}})),
            )
            .await;
        assert_eq!(p1["subject"], "Hello A");
        let (s, g) = t.call(Method::GET, "/v1/templates/welcome?version=2", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(g["mjml"].as_str().unwrap().starts_with("<mjml>"));
    }

    #[tokio::test]
    async fn upload_errors() {
        let t = TestApp::new().await;
        let bad = [
            ("welcome", json!({"subject": "x", "text": "x"})),
            ("welcome", json!({"subject": "x", "text": "x", "html": "a", "mjml": "<mjml/>"})),
            ("welcome", json!({"subject": "{% if %}", "text": "x", "html": "a"})),
            ("welcome", json!({"subject": "x", "text": "x", "mjml": "<mjml><mj-body>"})),
            ("bad key!", json!({"subject": "x", "text": "x", "html": "a"})),
        ];
        for (key, body) in bad {
            let (s, v) =
                t.call(Method::PUT, &format!("/v1/templates/{}", key.replace(' ', "%20")), Some(body)).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        }
        let (s, _) = t.call(Method::POST, "/v1/templates/none/preview", Some(json!({}))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        t.template("strict").await;
        let (s, v) = t.call(Method::POST, "/v1/templates/strict/preview", Some(json!({}))).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(v["error"]["code"], "template_error");
    }
}
