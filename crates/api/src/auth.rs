//! API keys: `sgl_<app id, 32 hex>_<secret>`, stored as an Argon2id hash with the pepper
//! as the Argon2 secret. Verified keys are cached by SHA-256 so Argon2 runs once per key.

use std::collections::HashMap;
use std::sync::Mutex;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};
use sigill_core::secrets::{random_bytes, random_token};
use sigill_store::apps::App;

use crate::AppState;
use crate::error::ApiError;

fn argon(pepper: &[u8]) -> Argon2<'_> {
    Argon2::new_with_secret(pepper, Algorithm::Argon2id, Version::V0x13, Params::default())
        .expect("valid argon2 parameters")
}

/// A new API key for an app, and its hash for storage.
pub fn generate_key(app_id: &str, pepper: &[u8]) -> (String, String) {
    let id =
        uuid::Uuid::parse_str(app_id).map(|u| u.simple().to_string()).unwrap_or_else(|_| app_id.to_string());
    let key = format!("sgl_{id}_{}", random_token::<32>());
    (key.clone(), hash_key(&key, pepper))
}

pub fn hash_key(key: &str, pepper: &[u8]) -> String {
    let salt = SaltString::encode_b64(&random_bytes::<16>()).expect("16-byte salt");
    argon(pepper).hash_password(key.as_bytes(), &salt).expect("argon2 hashing").to_string()
}

pub fn verify_key(key: &str, hash: &str, pepper: &[u8]) -> bool {
    PasswordHash::new(hash)
        .map(|h| argon(pepper).verify_password(key.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// App id embedded in a key.
fn app_id_of(key: &str) -> Option<String> {
    let rest = key.strip_prefix("sgl_")?;
    let (id, _) = rest.split_once('_')?;
    uuid::Uuid::try_parse(id).ok().map(|u| u.hyphenated().to_string())
}

#[derive(Default)]
pub struct KeyCache(Mutex<HashMap<[u8; 32], String>>);

impl KeyCache {
    fn get(&self, digest: &[u8; 32]) -> Option<String> {
        self.0.lock().expect("key cache lock").get(digest).cloned()
    }
    fn put(&self, digest: [u8; 32], app_id: String) {
        let mut m = self.0.lock().expect("key cache lock");
        if m.len() > 10_000 {
            m.clear();
        }
        m.insert(digest, app_id);
    }
}

/// The calling app, from `Authorization: Bearer <key>`.
pub struct AuthApp(pub App);

impl FromRequestParts<AppState> for AuthApp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let key = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or_else(ApiError::unauthorized)?;
        let digest: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let app_id = match state.inner.key_cache.get(&digest) {
            Some(id) => id,
            None => {
                let id = app_id_of(key).ok_or_else(ApiError::unauthorized)?;
                let app = state.store.get_app(&id).await?.ok_or_else(ApiError::unauthorized)?;
                let pepper = state.inner.secrets.api_key_pepper();
                let hash = app.api_key_hash.clone();
                let key_owned = key.to_string();
                let ok = tokio::task::spawn_blocking(move || verify_key(&key_owned, &hash, &pepper))
                    .await
                    .map_err(ApiError::internal)?;
                if !ok {
                    return Err(ApiError::unauthorized());
                }
                state.inner.key_cache.put(digest, id.clone());
                id
            }
        };
        let app = state.store.get_app(&app_id).await?.ok_or_else(ApiError::unauthorized)?;
        if !state.inner.rate_limiter.allow(&app.id) {
            return Err(ApiError::new(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests; slow down",
            ));
        }
        Ok(AuthApp(app))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trip() {
        let app_id = sigill_core::new_id();
        let pepper = [9u8; 32];
        let (key, hash) = generate_key(&app_id, &pepper);
        assert!(key.starts_with("sgl_"));
        assert_eq!(app_id_of(&key), Some(app_id));
        assert!(verify_key(&key, &hash, &pepper));
        assert!(!verify_key(&key, &hash, &[8u8; 32]));
        assert!(!verify_key("sgl_x_y", &hash, &pepper));
        assert_eq!(app_id_of("nope"), None);
    }
}
