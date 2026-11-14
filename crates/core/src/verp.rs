//! VERP return paths with an HMAC, so forged bounces are ignored.
//!
//! `b+d<delivery-id>.<mac>@<bounce-domain>` names one delivery. When several recipients of
//! one message share an SMTP transaction, the return path names the message instead:
//! `b+m<message-id>.<mac>@<bounce-domain>`, and the bounce handler matches the recipient
//! from the DSN. Ids are UUIDs written as 32 hex digits; the MAC is the first 8 bytes of
//! `HMAC-SHA256(verp_key, kind || id)` in lower-case hex.

use crate::secrets::{ct_eq, hmac_sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerpTarget {
    Delivery(uuid::Uuid),
    Message(uuid::Uuid),
}

fn mac(key: &[u8], kind: char, id: &uuid::Uuid) -> String {
    let mut data = Vec::with_capacity(33);
    data.push(kind as u8);
    data.extend_from_slice(id.as_bytes());
    hmac_sha256(key, &data)[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the return-path address for a target.
pub fn encode(key: &[u8], target: &VerpTarget, bounce_domain: &str) -> String {
    let (kind, id) = match target {
        VerpTarget::Delivery(id) => ('d', id),
        VerpTarget::Message(id) => ('m', id),
    };
    format!("b+{kind}{}.{}@{bounce_domain}", id.simple(), mac(key, kind, id))
}

/// Decode a return-path address. Returns `None` for anything that is not a valid,
/// correctly signed VERP address (the domain is checked by the caller).
pub fn decode(key: &[u8], address: &str) -> Option<VerpTarget> {
    let local = address.trim_matches(|c| c == '<' || c == '>').rsplit_once('@')?.0;
    let rest = local.strip_prefix("b+").or_else(|| local.strip_prefix("B+"))?;
    let (tagged, mac_given) = rest.split_once('.')?;
    let mut chars = tagged.chars();
    let kind = chars.next()?.to_ascii_lowercase();
    let id = uuid::Uuid::try_parse(chars.as_str()).ok()?;
    let expected = mac(key, kind, &id);
    if !ct_eq(expected.as_bytes(), mac_given.to_ascii_lowercase().as_bytes()) {
        return None;
    }
    match kind {
        'd' => Some(VerpTarget::Delivery(id)),
        'm' => Some(VerpTarget::Message(id)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = [3u8; 32];
        let id = uuid::Uuid::now_v7();
        for t in [VerpTarget::Delivery(id), VerpTarget::Message(id)] {
            let a = encode(&key, &t, "bounces.example.com");
            assert!(a.split('@').next().unwrap().len() <= 64);
            assert_eq!(decode(&key, &a), Some(t.clone()));
            assert_eq!(decode(&key, &format!("<{}>", a.to_uppercase())), Some(t.clone()));
            assert_eq!(decode(&[4u8; 32], &a), None);
        }
        let a = encode(&key, &VerpTarget::Delivery(id), "b.example");
        let tampered = a.replacen("b+d", "b+m", 1);
        assert_eq!(decode(&key, &tampered), None);
        assert_eq!(decode(&key, "postmaster@b.example"), None);
        assert_eq!(decode(&key, "b+dnothex.abc@b.example"), None);
    }
}
