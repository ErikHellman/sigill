//! Building the multipart/alternative message.

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::raw::Raw;

#[derive(Debug, thiserror::Error)]
pub enum MimeError {
    #[error("header {0:?} is not allowed")]
    HeaderNotAllowed(String),
    #[error("header {0:?} has an invalid value")]
    BadHeaderValue(String),
    #[error("cannot write message: {0}")]
    Io(#[from] std::io::Error),
}

/// Everything that goes into one message.
pub struct MimeParts<'a> {
    /// Our message id; the `Message-ID` header is `<id@from_domain>`.
    pub message_id: &'a str,
    pub from_name: Option<&'a str>,
    pub from: &'a str,
    pub to: &'a [String],
    pub subject: &'a str,
    pub html: &'a str,
    pub text: &'a str,
    /// Extra headers from the API call (already allowed by [`check_custom_header`]).
    pub headers: &'a [(String, String)],
    /// One-click unsubscribe URL (RFC 8058) for broadcast mail.
    pub list_unsubscribe: Option<&'a str>,
    /// `Date` header as unix seconds.
    pub date: i64,
}

/// Apps may set `Reply-To` and `X-*` headers; everything else is ours.
pub fn check_custom_header(name: &str, value: &str) -> Result<(), MimeError> {
    let lower = name.to_ascii_lowercase();
    let name_ok = !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
        && (lower == "reply-to" || lower.starts_with("x-"))
        && !lower.starts_with("x-sigill");
    if !name_ok {
        return Err(MimeError::HeaderNotAllowed(name.to_string()));
    }
    if value.contains(['\r', '\n']) || value.len() > 998 {
        return Err(MimeError::BadHeaderValue(name.to_string()));
    }
    Ok(())
}

pub fn build_mime(p: &MimeParts<'_>) -> Result<Vec<u8>, MimeError> {
    let from_domain = p.from.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost");
    let from: Address<'_> = match p.from_name {
        Some(n) => Address::new_address(Some(n), p.from),
        None => Address::new_address(None::<&str>, p.from),
    };
    let to: Vec<Address<'_>> = p.to.iter().map(|t| Address::new_address(None::<&str>, t.as_str())).collect();
    let mut b = MessageBuilder::new()
        .message_id(format!("{}@{}", p.message_id, from_domain))
        .date(p.date)
        .from(from)
        .to(Address::new_list(to))
        .subject(p.subject)
        .text_body(p.text)
        .html_body(p.html);
    for (name, value) in p.headers {
        check_custom_header(name, value)?;
        if name.eq_ignore_ascii_case("reply-to") {
            b = b.reply_to(Address::new_address(None::<&str>, value.as_str()));
        } else {
            b = b.header(name.as_str(), Raw::new(value.as_str()));
        }
    }
    if let Some(url) = p.list_unsubscribe {
        b = b
            .header("List-Unsubscribe", Raw::new(format!("<{url}>")))
            .header("List-Unsubscribe-Post", Raw::new("List-Unsubscribe=One-Click"));
    }
    Ok(b.write_to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts<'a>(to: &'a [String], headers: &'a [(String, String)]) -> MimeParts<'a> {
        MimeParts {
            message_id: "0192-abc",
            from_name: Some("Shop"),
            from: "noreply@mail.example.com",
            to,
            subject: "Your order ✓",
            html: "<p>Hi</p>",
            text: "Hi",
            headers,
            list_unsubscribe: Some("https://api.example.com/u/tok"),
            date: 1_700_000_000,
        }
    }

    #[test]
    fn builds_multipart() {
        let to = vec!["a@x.com".to_string(), "b@y.com".to_string()];
        let headers = vec![("X-Order".to_string(), "42".to_string())];
        let raw = String::from_utf8(build_mime(&parts(&to, &headers)).unwrap()).unwrap();
        assert!(raw.contains("Message-ID: <0192-abc@mail.example.com>"));
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("text/plain"));
        assert!(raw.contains("text/html"));
        assert!(raw.contains("X-Order: 42"));
        assert!(raw.contains("List-Unsubscribe: <https://api.example.com/u/tok>"));
        assert!(raw.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
        assert!(raw.contains("<a@x.com>") && raw.contains("<b@y.com>"));
        assert!(raw.contains("=?utf-8?"), "non-ASCII subject is encoded");
    }

    #[test]
    fn rejects_headers() {
        assert!(check_custom_header("Reply-To", "a@x.com").is_ok());
        assert!(check_custom_header("X-Thing", "1").is_ok());
        assert!(check_custom_header("From", "evil@x.com").is_err());
        assert!(check_custom_header("X-Sigill-Delivery", "1").is_err());
        assert!(check_custom_header("X-Bad", "a\r\nBcc: x@y.com").is_err());
        assert!(check_custom_header("X Bad", "1").is_err());
    }
}
