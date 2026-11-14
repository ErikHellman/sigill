//! Email address syntax checks and normalisation.
//!
//! The check is deliberately practical rather than a full RFC 5322 parser: it accepts
//! `local@domain` with a dot-atom local part (or a quoted one) and an LDH domain with at
//! least one dot, which is what real mailboxes look like.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address is empty")]
    Empty,
    #[error("address is too long")]
    TooLong,
    #[error("address has no @")]
    NoAt,
    #[error("invalid local part")]
    LocalPart,
    #[error("invalid domain")]
    Domain,
}

/// A syntactically valid address, with the domain in lower case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    local: String,
    domain: String,
}

impl Address {
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(AddressError::Empty);
        }
        if s.len() > 254 {
            return Err(AddressError::TooLong);
        }
        let at = s.rfind('@').ok_or(AddressError::NoAt)?;
        let (local, domain) = (&s[..at], &s[at + 1..]);
        if !valid_local(local) {
            return Err(AddressError::LocalPart);
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(AddressError::Domain);
        }
        Ok(Self { local: local.to_string(), domain })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Form used for suppression lookups: the whole address in lower case.
    pub fn normalized(&self) -> String {
        format!("{}@{}", self.local.to_lowercase(), self.domain)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Normalise an address string for suppression lookups, or `None` if it is invalid.
pub fn normalize(input: &str) -> Option<String> {
    Address::parse(input).ok().map(|a| a.normalized())
}

/// Domain of an address string, lower case, without validating the local part.
pub fn domain_of(input: &str) -> Option<String> {
    input.rsplit_once('@').map(|(_, d)| d.trim().trim_end_matches('.').to_ascii_lowercase())
}

fn valid_local(local: &str) -> bool {
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if local.len() >= 2 && local.starts_with('"') && local.ends_with('"') {
        let inner = &local[1..local.len() - 1];
        return inner.chars().all(|c| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\');
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    local.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || "!#$%&'*+-/=?^_`{|}~.".contains(c)
            || (!c.is_ascii() && c.is_alphanumeric())
    })
}

pub(crate) fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && c.is_alphanumeric()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_addresses() {
        for a in [
            "a@example.com",
            "first.last+tag@sub.example.co.uk",
            "\"odd one\"@example.org",
            "x_y-z@ex-ample.io",
        ] {
            assert!(Address::parse(a).is_ok(), "{a}");
        }
    }

    #[test]
    fn rejects_bad_addresses() {
        assert_eq!(Address::parse(""), Err(AddressError::Empty));
        assert_eq!(Address::parse("nope"), Err(AddressError::NoAt));
        assert_eq!(Address::parse(".a@example.com"), Err(AddressError::LocalPart));
        assert_eq!(Address::parse("a..b@example.com"), Err(AddressError::LocalPart));
        assert_eq!(Address::parse("a b@example.com"), Err(AddressError::LocalPart));
        assert_eq!(Address::parse("a@localhost"), Err(AddressError::Domain));
        assert_eq!(Address::parse("a@-bad.com"), Err(AddressError::Domain));
        assert_eq!(Address::parse(&format!("{}@example.com", "a".repeat(65))), Err(AddressError::LocalPart));
    }

    #[test]
    fn normalizes() {
        let a = Address::parse(" Alice@Example.COM. ").unwrap();
        assert_eq!(a.domain(), "example.com");
        assert_eq!(a.to_string(), "Alice@example.com");
        assert_eq!(a.normalized(), "alice@example.com");
        assert_eq!(domain_of("x@Gmail.com"), Some("gmail.com".into()));
    }
}
