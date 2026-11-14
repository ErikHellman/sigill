//! One-click unsubscribe tokens: `<delivery id, 32 hex>.<mac>`, where the MAC is the first
//! 12 bytes of `HMAC-SHA256(unsubscribe_key, delivery id)` in base64url.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sigill_core::secrets::{ct_eq, hmac_sha256};

fn mac(key: &[u8], id: &uuid::Uuid) -> String {
    URL_SAFE_NO_PAD.encode(&hmac_sha256(key, id.as_bytes())[..12])
}

pub fn token(key: &[u8], delivery_id: &str) -> String {
    let id = uuid::Uuid::parse_str(delivery_id).expect("delivery ids are UUIDs");
    format!("{}.{}", id.simple(), mac(key, &id))
}

/// The delivery id in a valid token.
pub fn verify(key: &[u8], token: &str) -> Option<String> {
    let (id, given) = token.split_once('.')?;
    let id = uuid::Uuid::try_parse(id).ok()?;
    ct_eq(mac(key, &id).as_bytes(), given.as_bytes()).then(|| id.hyphenated().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = sigill_core::new_id();
        let t = token(&[1u8; 32], &id);
        assert_eq!(verify(&[1u8; 32], &t), Some(id));
        assert_eq!(verify(&[2u8; 32], &t), None);
        assert_eq!(verify(&[1u8; 32], "garbage"), None);
    }
}
