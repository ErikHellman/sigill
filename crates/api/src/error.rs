//! JSON error responses: `{"error": {"code": "...", "message": "...", "details": ...}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), details: None }
    }
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    pub fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", format!("{what} not found"))
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", message)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid API key")
    }
    pub fn internal(e: impl std::error::Error + 'static) -> Self {
        tracing::error!(error = %e, "internal error");
        sigill_core::telemetry::capture_error(&e);
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({"code": self.code, "message": self.message});
        if let Some(d) = self.details {
            body["details"] = d;
        }
        (self.status, Json(json!({ "error": body }))).into_response()
    }
}

impl From<sigill_store::Error> for ApiError {
    fn from(e: sigill_store::Error) -> Self {
        match e {
            sigill_store::Error::NotFound => ApiError::not_found("resource"),
            sigill_store::Error::Conflict(m) => ApiError::new(StatusCode::CONFLICT, "conflict", m),
            other => ApiError::internal(other),
        }
    }
}

impl From<sigill_render::TemplateError> for ApiError {
    fn from(e: sigill_render::TemplateError) -> Self {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "template_error", e.to_string())
    }
}

impl From<sigill_render::MimeError> for ApiError {
    fn from(e: sigill_render::MimeError) -> Self {
        match e {
            sigill_render::MimeError::Io(io) => ApiError::internal(io),
            other => ApiError::invalid(other.to_string()),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
