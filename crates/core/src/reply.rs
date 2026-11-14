//! Classification of SMTP replies: 2xx sent, 4xx defer, 5xx bounce.

/// An SMTP reply: the code and the full text (all lines joined by newlines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub text: String,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self { code, text: text.into() }
    }

    /// Enhanced status code (RFC 3463) at the start of the text, such as `5.1.1`.
    pub fn enhanced_status(&self) -> Option<EnhancedStatus> {
        self.text.split_whitespace().next().and_then(EnhancedStatus::parse)
    }

    pub fn outcome(&self) -> Outcome {
        classify(self.code, &self.text)
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code, self.text)
    }
}

/// RFC 3463 enhanced status code `class.subject.detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnhancedStatus {
    pub class: u8,
    pub subject: u16,
    pub detail: u16,
}

impl EnhancedStatus {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_end_matches(|c: char| !c.is_ascii_digit());
        let mut it = s.split('.');
        let class: u8 = it.next()?.parse().ok()?;
        let subject: u16 = it.next()?.parse().ok()?;
        let detail: u16 = it.next()?.parse().ok()?;
        if it.next().is_some() || !matches!(class, 2 | 4 | 5) {
            return None;
        }
        Some(Self { class, subject, detail })
    }
}

impl std::fmt::Display for EnhancedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

/// What a reply means for the delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// Temporary failure; retry later. `rate_limited` means back off the whole domain.
    Defer {
        rate_limited: bool,
    },
    /// Permanent failure. `hard` means the address itself is bad and must be suppressed.
    Bounce {
        hard: bool,
    },
}

/// Classify a reply code and text.
pub fn classify(code: u16, text: &str) -> Outcome {
    let lower = text.to_ascii_lowercase();
    match code / 100 {
        2 => Outcome::Sent,
        4 => Outcome::Defer { rate_limited: code == 421 || is_rate_limit(&lower) },
        5 => {
            // Some providers answer rate limiting with a 5xx; treat it as temporary.
            if is_rate_limit(&lower) && !is_bad_mailbox(code, text, &lower) {
                return Outcome::Defer { rate_limited: true };
            }
            Outcome::Bounce { hard: is_bad_mailbox(code, text, &lower) }
        }
        _ => Outcome::Defer { rate_limited: false },
    }
}

fn is_rate_limit(lower: &str) -> bool {
    ["rate limit", "ratelimit", "too many", "try again later", "throttl", "4.7.28", "4.7.0 [ts"]
        .iter()
        .any(|p| lower.contains(p))
}

/// Does a permanent reply say the mailbox or domain does not exist?
pub fn is_bad_mailbox(code: u16, text: &str, lower: &str) -> bool {
    if let Some(es) = text.split_whitespace().next().and_then(EnhancedStatus::parse) {
        if es.class == 5 {
            // 5.1.x addressing errors (unknown user, bad domain, 5.1.10 null MX),
            // 5.2.1 mailbox disabled.
            return es.subject == 1 || (es.subject == 2 && es.detail == 1);
        }
        return false;
    }
    if code == 550 || code == 551 || code == 553 {
        return [
            "user unknown",
            "unknown user",
            "no such user",
            "does not exist",
            "mailbox unavailable",
            "invalid recipient",
            "recipient rejected",
            "address rejected",
            "mailbox not found",
            "no mailbox",
        ]
        .iter()
        .any(|p| lower.contains(p));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_codes() {
        assert_eq!(classify(250, "2.0.0 OK"), Outcome::Sent);
        assert_eq!(classify(451, "4.3.0 Temporary failure"), Outcome::Defer { rate_limited: false });
        assert_eq!(classify(421, "4.7.0 Try later"), Outcome::Defer { rate_limited: true });
        assert_eq!(
            classify(
                450,
                "4.2.1 The user you are trying to contact is receiving mail at a rate that prevents additional messages"
            ),
            Outcome::Defer { rate_limited: false }
        );
        assert_eq!(
            classify(452, "4.7.28 Our system has detected an unusual rate"),
            Outcome::Defer { rate_limited: true }
        );
        assert_eq!(
            classify(550, "5.1.1 The email account that you tried to reach does not exist"),
            Outcome::Bounce { hard: true }
        );
        assert_eq!(classify(556, "5.1.10 Recipient address has null MX"), Outcome::Bounce { hard: true });
        assert_eq!(classify(550, "5.7.1 Message rejected as spam"), Outcome::Bounce { hard: false });
        assert_eq!(
            classify(550, "Requested action not taken: mailbox unavailable"),
            Outcome::Bounce { hard: true }
        );
        assert_eq!(classify(554, "Transaction failed"), Outcome::Bounce { hard: false });
        assert_eq!(
            classify(550, "5.7.1 Too many messages, rate limited"),
            Outcome::Defer { rate_limited: true }
        );
    }

    #[test]
    fn parses_enhanced_status() {
        let r = Reply::new(550, "5.1.1 <x@y>: Recipient address rejected");
        assert_eq!(r.enhanced_status(), Some(EnhancedStatus { class: 5, subject: 1, detail: 1 }));
        assert_eq!(EnhancedStatus::parse("5.1.10").unwrap().to_string(), "5.1.10");
        assert_eq!(EnhancedStatus::parse("abc"), None);
        assert_eq!(EnhancedStatus::parse("3.1.1"), None);
    }
}
