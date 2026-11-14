//! Parsing of bounce messages (RFC 3464 DSNs, with heuristics for non-standard ones) and
//! complaint reports (RFC 5965 ARF).

use mail_parser::{MessageParser, PartKind};
use sigill_core::reply::{EnhancedStatus, Outcome, classify};

/// What a received report says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub kind: ReportKind,
    /// Per-recipient results from a DSN, or one guessed result for a non-standard bounce.
    pub recipients: Vec<RecipientStatus>,
    /// Present for an ARF complaint report.
    pub feedback: Option<Feedback>,
    /// VERP-shaped addresses found anywhere in the report, such as the original message's
    /// `Return-Path`. They are not verified here.
    pub verp_candidates: Vec<String>,
    /// `Message-ID` values of the original message, without angle brackets.
    pub original_message_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReportKind {
    /// A standard delivery status notification.
    Dsn,
    /// An ARF feedback report.
    Feedback,
    /// A bounce without a `message/delivery-status` part, classified from its text.
    Heuristic,
    /// Nothing to act on: an auto-reply, a challenge, or unrecognised mail.
    #[default]
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Failed,
    Delayed,
    Delivered,
    Relayed,
    Expanded,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientStatus {
    /// `Final-Recipient` (or `Original-Recipient`) address, if given.
    pub recipient: Option<String>,
    pub action: Action,
    pub status: Option<EnhancedStatus>,
    /// SMTP reply code from `Diagnostic-Code`, if any.
    pub code: Option<u16>,
    /// Diagnostic text, starting with the enhanced status when one is known.
    pub diagnostic: String,
}

/// What to do about one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The address does not exist: suppress it.
    Hard,
    /// Permanent failure for another reason (policy, full mailbox): count it.
    Soft,
    /// Not a failure (delayed, delivered, relayed).
    Ignore,
}

impl RecipientStatus {
    /// SMTP code used for classification: the diagnostic code, or one implied by the status.
    pub fn effective_code(&self) -> Option<u16> {
        self.code.or(match self.status.map(|s| s.class) {
            Some(5) => Some(550),
            Some(4) => Some(450),
            _ => None,
        })
    }

    pub fn verdict(&self) -> Verdict {
        if self.action != Action::Failed {
            return Verdict::Ignore;
        }
        let Some(code) = self.effective_code() else { return Verdict::Soft };
        match classify(code, &self.diagnostic) {
            Outcome::Bounce { hard: true } => Verdict::Hard,
            Outcome::Sent => Verdict::Ignore,
            _ => Verdict::Soft,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feedback {
    /// `abuse`, `fraud`, `not-spam`, ...; lower case.
    pub feedback_type: String,
    /// `Original-Rcpt-To` or `Removal-Recipient`, when the provider did not redact it.
    pub original_rcpt: Option<String>,
}

impl Feedback {
    /// Feedback types that mean "the recipient does not want this mail".
    pub fn is_complaint(&self) -> bool {
        !matches!(self.feedback_type.as_str(), "not-spam")
    }
}

/// Parse a received report.
pub fn parse(raw: &[u8]) -> Report {
    let mut report =
        Report { verp_candidates: find_verp(&String::from_utf8_lossy(raw)), ..Default::default() };
    let Some(message) = MessageParser::new().parse(raw) else { return report };

    for part in message.parts() {
        let Some(ct) = part.content_type() else { continue };
        let ctype = ct.ctype().to_ascii_lowercase();
        let subtype = ct.subtype().unwrap_or("").to_ascii_lowercase();
        match (ctype.as_str(), subtype.as_str()) {
            ("message", "delivery-status" | "global-delivery-status") => {
                let text = String::from_utf8_lossy(&part.decoded()).into_owned();
                report.kind = ReportKind::Dsn;
                report.recipients.extend(parse_delivery_status(&text));
            }
            ("message", "feedback-report") => {
                let text = String::from_utf8_lossy(&part.decoded()).into_owned();
                report.kind = ReportKind::Feedback;
                report.feedback = Some(parse_feedback(&text));
            }
            ("message", "rfc822" | "global") => {
                if let PartKind::Message(nested) = part.kind() {
                    if let Some(id) = nested.message_id() {
                        push_unique(&mut report.original_message_ids, id.to_string());
                    }
                } else {
                    original_ids_from_headers(&String::from_utf8_lossy(&part.decoded()), &mut report);
                }
            }
            ("text", "rfc822-headers") | ("message", "rfc822-headers") => {
                original_ids_from_headers(&String::from_utf8_lossy(&part.decoded()), &mut report);
            }
            _ => {}
        }
    }

    if report.kind == ReportKind::Ignored {
        let root = message.root();
        let auto_reply = root.headers().iter().any(|h| {
            h.raw_name().eq_ignore_ascii_case("Auto-Submitted")
                && !String::from_utf8_lossy(h.raw_value()).trim().eq_ignore_ascii_case("no")
        }) && !looks_like_bounce_subject(root.subject().unwrap_or(""));
        if !auto_reply {
            let mut text = String::from(root.subject().unwrap_or(""));
            for body in root.text_bodies() {
                text.push('\n');
                text.push_str(&body);
            }
            if let Some(status) = heuristic(&text) {
                report.kind = ReportKind::Heuristic;
                report.recipients.push(status);
            }
        }
    }
    report
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

fn original_ids_from_headers(text: &str, report: &mut Report) {
    if let Some(block) = parse_fields(text).into_iter().next() {
        for (name, value) in block {
            if name == "message-id" {
                let id = value.trim().trim_start_matches('<').trim_end_matches('>').to_string();
                if !id.is_empty() {
                    push_unique(&mut report.original_message_ids, id);
                }
            }
        }
    }
}

/// Split header-style text into blocks (separated by blank lines) of `(lower-case name,
/// value)` pairs, unfolding continuation lines.
fn parse_fields(text: &str) -> Vec<Vec<(String, String)>> {
    let mut blocks = Vec::new();
    let mut block: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if !block.is_empty() {
                blocks.push(std::mem::take(&mut block));
            }
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = block.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            block.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    if !block.is_empty() {
        blocks.push(block);
    }
    blocks
}

/// `rfc822; user@example.com` → `user@example.com`.
fn strip_type(value: &str) -> &str {
    value.split_once(';').map_or(value, |(_, v)| v).trim().trim_start_matches('<').trim_end_matches('>')
}

fn parse_delivery_status(text: &str) -> Vec<RecipientStatus> {
    // The first block holds per-message fields; the rest describe one recipient each.
    let mut out = Vec::new();
    for block in parse_fields(text) {
        let get = |n: &str| block.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        let Some(action) = get("action") else { continue };
        let recipient = get("final-recipient")
            .or_else(|| get("original-recipient"))
            .map(strip_type)
            .filter(|s| s.contains('@'))
            .map(str::to_string);
        let action = match action.trim().to_ascii_lowercase().as_str() {
            "failed" => Action::Failed,
            "delayed" => Action::Delayed,
            "delivered" => Action::Delivered,
            "relayed" => Action::Relayed,
            "expanded" => Action::Expanded,
            _ => Action::Unknown,
        };
        let status = get("status").and_then(|s| EnhancedStatus::parse(s.split_whitespace().next()?));
        let diag =
            get("diagnostic-code").map(|d| d.split_once(';').map_or(d, |(_, v)| v).trim()).unwrap_or("");
        let (code, rest) = split_code(diag);
        let diagnostic = match status {
            Some(s) if rest.split_whitespace().next().and_then(EnhancedStatus::parse).is_some() => {
                // The diagnostic already starts with a status; keep the one from `Status`.
                let tail = rest.split_once(char::is_whitespace).map_or("", |(_, t)| t);
                format!("{s} {tail}").trim_end().to_string()
            }
            Some(s) => format!("{s} {rest}").trim_end().to_string(),
            None => rest.to_string(),
        };
        out.push(RecipientStatus { recipient, action, status, code, diagnostic: truncate(&diagnostic, 500) });
    }
    out
}

/// `550 5.1.1 no such user` → `(Some(550), "5.1.1 no such user")`; also accepts `550-5.1.1`.
fn split_code(text: &str) -> (Option<u16>, &str) {
    let t = text.trim();
    if t.len() >= 3
        && t.as_bytes()[..3].iter().all(u8::is_ascii_digit)
        && matches!(t.as_bytes()[0], b'2' | b'4' | b'5')
    {
        let rest = &t[3..];
        if rest.is_empty() || rest.starts_with([' ', '-']) {
            return (t[..3].parse().ok(), rest.trim_start_matches(['-', ' ']));
        }
    }
    (None, t)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn parse_feedback(text: &str) -> Feedback {
    let fields: Vec<(String, String)> = parse_fields(text).into_iter().flatten().collect();
    let get = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    Feedback {
        feedback_type: get("feedback-type").unwrap_or("abuse").trim().to_ascii_lowercase(),
        original_rcpt: get("original-rcpt-to")
            .or_else(|| get("removal-recipient"))
            .map(strip_type)
            .filter(|s| s.contains('@') && !s.contains("redacted"))
            .map(str::to_string),
    }
}

fn looks_like_bounce_subject(subject: &str) -> bool {
    let s = subject.to_ascii_lowercase();
    [
        "undeliver",
        "delivery status",
        "delivery failure",
        "returned mail",
        "failure notice",
        "mail delivery failed",
    ]
    .iter()
    .any(|p| s.contains(p))
}

const HARD_PHRASES: &[&str] = &[
    "user unknown",
    "unknown user",
    "no such user",
    "does not exist",
    "invalid recipient",
    "recipient address rejected",
    "mailbox not found",
    "no mailbox",
    "address rejected",
    "unknown recipient",
];
const SOFT_PHRASES: &[&str] =
    &["mailbox full", "mailbox is full", "over quota", "quota exceeded", "insufficient storage"];

/// Classify a bounce without a DSN part from its text: the first line with an enhanced
/// status code, or a well-known phrase. Returns `None` when the text does not look like a
/// bounce at all.
fn heuristic(text: &str) -> Option<RecipientStatus> {
    let failure = |code, status, diagnostic: String| RecipientStatus {
        recipient: None,
        action: Action::Failed,
        status,
        code,
        diagnostic: truncate(&diagnostic, 500),
    };
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            let token = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            if token.matches('.').count() != 2 {
                continue;
            }
            if let Some(status) = EnhancedStatus::parse(token).filter(|s| s.class != 2) {
                let code = words[..i]
                    .iter()
                    .rev()
                    .take(2)
                    .find_map(|w| split_code(w.trim_matches(|c: char| !c.is_ascii_digit())).0);
                let rest = words[i + 1..].join(" ");
                return Some(failure(code, Some(status), format!("{status} {rest}")));
            }
        }
    }
    let lower = text.to_ascii_lowercase();
    let line_with =
        |p: &str| text.lines().find(|l| l.to_ascii_lowercase().contains(p)).unwrap_or(p).trim().to_string();
    if let Some(p) = HARD_PHRASES.iter().find(|p| lower.contains(*p)) {
        return Some(failure(Some(550), None, line_with(p)));
    }
    if let Some(p) = SOFT_PHRASES.iter().find(|p| lower.contains(*p)) {
        return Some(failure(Some(552), None, line_with(p)));
    }
    None
}

/// Find VERP-shaped addresses (`b+<d|m><32 hex>.<16 hex>@domain`) anywhere in `text`.
pub fn find_verp(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if (bytes[i] == b'b' || bytes[i] == b'B')
            && bytes[i + 1] == b'+'
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && let Some(len) = verp_len(&bytes[i..])
        {
            let addr = text[i..i + len].to_ascii_lowercase();
            if !out.contains(&addr) {
                out.push(addr);
            }
            i += len;
            continue;
        }
        i += 1;
    }
    out
}

fn verp_len(b: &[u8]) -> Option<usize> {
    // "b+" kind 32hex "." 16hex "@" domain
    let fixed = 2 + 1 + 32 + 1 + 16 + 1;
    if b.len() <= fixed || !matches!(b[2].to_ascii_lowercase(), b'd' | b'm') {
        return None;
    }
    if !b[3..35].iter().all(u8::is_ascii_hexdigit) || b[35] != b'.' {
        return None;
    }
    if !b[36..52].iter().all(u8::is_ascii_hexdigit) || b[52] != b'@' {
        return None;
    }
    let domain =
        b[fixed..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'.' || **c == b'-').count();
    let domain =
        b[fixed..fixed + domain].iter().rposition(|c| c.is_ascii_alphanumeric()).map_or(0, |p| p + 1);
    (domain > 0).then_some(fixed + domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_unfold_and_split() {
        let blocks = parse_fields(
            "Reporting-MTA: dns; a\r\n\r\nFinal-Recipient: rfc822;x@y\r\nDiagnostic-Code: smtp; 550\r\n  more\r\n",
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1][1], ("diagnostic-code".into(), "smtp; 550 more".into()));
    }

    #[test]
    fn split_codes() {
        assert_eq!(split_code("550 5.1.1 gone"), (Some(550), "5.1.1 gone"));
        assert_eq!(split_code("550-5.1.1 gone"), (Some(550), "5.1.1 gone"));
        assert_eq!(split_code("5.1.1 gone"), (None, "5.1.1 gone"));
        assert_eq!(split_code("5501 x"), (None, "5501 x"));
    }

    #[test]
    fn finds_verp() {
        let a = format!("b+d{}.{}@bounces.example.com", "a".repeat(32), "0".repeat(16));
        let text =
            format!("Return-Path: <{a}>\nX: B+D{}.{}@Bounces.Example.com.\n", "a".repeat(32), "0".repeat(16));
        assert_eq!(find_verp(&text), vec![a]);
        assert!(find_verp("ab+d1234@x").is_empty());
    }

    #[test]
    fn heuristics() {
        let s =
            heuristic("Sorry.\n\n<a@x.com>: host mx said: 550 5.1.1 <a@x.com>: Recipient address rejected\n")
                .unwrap();
        assert_eq!((s.code, s.verdict()), (Some(550), Verdict::Hard));
        let s = heuristic("The mailbox is full, try later").unwrap();
        assert_eq!(s.verdict(), Verdict::Soft);
        assert!(heuristic("I am out of the office until Monday.").is_none());
    }
}
