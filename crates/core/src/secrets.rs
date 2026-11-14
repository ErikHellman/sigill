//! Secrets. Everything is derived from one master key read from `SIGILL_MASTER_KEY` or a
//! file, so no secret is ever stored in the repository or the database.
//!
//! Subkeys are `HMAC-SHA256(master, label)`: the API key pepper, the VERP key, the
//! unsubscribe-token key and one webhook signing secret per app.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("master key missing: set SIGILL_MASTER_KEY or secrets.master_key_file")]
    Missing,
    #[error("master key must be at least 32 bytes")]
    TooShort,
    #[error("cannot read secret file: {0}")]
    Io(#[from] std::io::Error),
}

/// Keys derived from the master key.
#[derive(Clone)]
pub struct Secrets {
    master: Vec<u8>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(..)")
    }
}

/// Read a secret from an env var, or else from a file (trailing newline trimmed).
pub fn read_secret(env: &str, file: Option<&Path>) -> Result<Option<String>, SecretError> {
    if let Ok(v) = std::env::var(env)
        && !v.is_empty()
    {
        return Ok(Some(v));
    }
    match file {
        Some(p) => Ok(Some(std::fs::read_to_string(p)?.trim_end().to_string())),
        None => Ok(None),
    }
}

impl Secrets {
    pub fn new(master: impl Into<Vec<u8>>) -> Result<Self, SecretError> {
        let master = master.into();
        if master.len() < 32 {
            return Err(SecretError::TooShort);
        }
        Ok(Self { master })
    }

    /// Load from `SIGILL_MASTER_KEY` or the configured file.
    pub fn load(file: Option<&Path>) -> Result<Self, SecretError> {
        let v = read_secret("SIGILL_MASTER_KEY", file)?.ok_or(SecretError::Missing)?;
        Self::new(v.into_bytes())
    }

    fn derive(&self, label: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.master).expect("any key length");
        mac.update(label.as_bytes());
        mac.finalize().into_bytes().into()
    }

    pub fn api_key_pepper(&self) -> [u8; 32] {
        self.derive("sigill/api-key-pepper")
    }

    pub fn verp_key(&self) -> [u8; 32] {
        self.derive("sigill/verp")
    }

    pub fn unsubscribe_key(&self) -> [u8; 32] {
        self.derive("sigill/unsubscribe")
    }

    /// Webhook signing secret for one app, shown to the app owner as base64url.
    pub fn webhook_secret(&self, app_id: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.derive(&format!("sigill/webhook/{app_id}")))
    }
}

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `n` random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random source");
    buf
}

/// Random URL-safe token with `N` bytes of entropy.
pub fn random_token<const N: usize>() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<N>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_distinct_stable_keys() {
        let s = Secrets::new(vec![7u8; 32]).unwrap();
        assert_ne!(s.verp_key(), s.api_key_pepper());
        assert_eq!(s.webhook_secret("a"), s.webhook_secret("a"));
        assert_ne!(s.webhook_secret("a"), s.webhook_secret("b"));
        assert!(Secrets::new(vec![1u8; 8]).is_err());
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert_ne!(random_token::<16>(), random_token::<16>());
    }
}
