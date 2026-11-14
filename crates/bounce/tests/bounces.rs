//! Bounce handling against a fixture corpus of real-world bounce and complaint formats, and
//! end to end through the listener over SMTP.

use std::net::SocketAddr;
use std::time::Duration;

use sigill_bounce::parse::{self, ReportKind, Verdict};
use sigill_bounce::{Listener, Processor, Settings};
use sigill_core::config::BounceConfig;
use sigill_core::verp::{self, VerpTarget};
use sigill_core::{DeliveryStatus, EventKind, Stream};
use sigill_mta::client::{SmtpClient, TlsConnectors};
use sigill_store::messages::{NewDelivery, NewMessage};
use sigill_store::queue::Outcome;
use sigill_store::testing::{TestDb, test_db};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const VERP_KEY: [u8; 32] = [9u8; 32];
const BOUNCE_DOMAIN: &str = "bounces.example.com";
const RCPT: &str = "Someone@Example.org";
const RCPT_NORM: &str = "someone@example.org";

fn fixture(name: &str, verp: &str, msgid: &str) -> Vec<u8> {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("{{VERP}}", verp)
        .replace("{{RCPT}}", RCPT)
        .replace("{{MSGID}}", msgid)
        .into_bytes()
}

#[test]
fn corpus_classification() {
    let verp = format!("b+d{}.{}@{BOUNCE_DOMAIN}", "1".repeat(32), "2".repeat(16));
    let msgid = "0190f0a0-0000-7000-8000-000000000001@mail.example.com";
    // (fixture, kind, verdict of the first recipient)
    let cases = [
        ("gmail_hard.eml", ReportKind::Dsn, Some(Verdict::Hard)),
        ("outlook_hard.eml", ReportKind::Dsn, Some(Verdict::Hard)),
        ("postfix_mailbox_full.eml", ReportKind::Dsn, Some(Verdict::Soft)),
        ("exim_nonstandard.eml", ReportKind::Heuristic, Some(Verdict::Hard)),
        ("qmail_nonstandard.eml", ReportKind::Heuristic, Some(Verdict::Hard)),
        ("delayed.eml", ReportKind::Dsn, Some(Verdict::Ignore)),
        ("yahoo_arf.eml", ReportKind::Feedback, None),
        ("microsoft_jmrp.eml", ReportKind::Feedback, None),
        ("auto_reply.eml", ReportKind::Ignored, None),
    ];
    for (name, kind, verdict) in cases {
        let report = parse::parse(&fixture(name, &verp, msgid));
        assert_eq!(report.kind, kind, "{name}");
        assert_eq!(report.recipients.first().map(|r| r.verdict()), verdict, "{name}");
        assert!(report.verp_candidates.contains(&verp) || name == "microsoft_jmrp.eml", "{name}");
        if kind == ReportKind::Dsn {
            assert_eq!(report.recipients[0].recipient.as_deref(), Some(RCPT), "{name}");
        }
        if matches!(kind, ReportKind::Feedback) || name.ends_with("_hard.eml") || name.starts_with("postfix")
        {
            assert_eq!(report.original_message_ids, vec![msgid.to_string()], "{name}");
        }
    }
    let gmail = parse::parse(&fixture("gmail_hard.eml", &verp, msgid));
    assert_eq!(gmail.recipients[0].code, Some(550));
    assert!(gmail.recipients[0].diagnostic.starts_with("5.1.1 The email account"));
    let yahoo = parse::parse(&fixture("yahoo_arf.eml", &verp, msgid)).feedback.unwrap();
    assert_eq!((yahoo.feedback_type.as_str(), yahoo.original_rcpt.as_deref()), ("abuse", Some(RCPT)));
    let jmrp = parse::parse(&fixture("microsoft_jmrp.eml", &verp, msgid)).feedback.unwrap();
    assert_eq!(jmrp.original_rcpt, None, "redacted recipients are dropped");
}

struct Env {
    db: TestDb,
    addr: SocketAddr,
    token: CancellationToken,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

async fn start(tweak: impl FnOnce(&mut Settings), tls: Option<tokio_rustls::TlsAcceptor>) -> Env {
    let db = test_db().await;
    db.create_app("app", "app", "h", Some("https://hooks.test"), Stream::Transactional).await.unwrap();
    let mut settings = Settings::new(&BounceConfig::default(), vec![BOUNCE_DOMAIN.into()]);
    settings.timeout = Duration::from_secs(5);
    tweak(&mut settings);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let l = Listener::new(settings, Processor::new(db.store.clone(), VERP_KEY), VERP_KEY, tls);
    tokio::spawn(l.run(listener, token.clone()));
    Env { db, addr, token }
}

/// Insert a sent message with one delivery per recipient; returns the delivery ids.
async fn sent_message(db: &TestDb, message_id: &str, rcpts: &[&str]) -> Vec<String> {
    let deliveries: Vec<NewDelivery> = rcpts
        .iter()
        .map(|r| NewDelivery {
            id: sigill_core::new_id(),
            rcpt: sigill_core::address::normalize(r).unwrap(),
            rcpt_domain: sigill_core::address::domain_of(r).unwrap(),
            suppressed: false,
        })
        .collect();
    let msg = NewMessage {
        id: message_id,
        app_id: "app",
        idempotency_key: None,
        stream: Stream::Transactional,
        template_key: "receipt",
        template_version: 1,
        from_addr: "noreply@mail.example.com",
        subject: "Your receipt",
        rendered_mime: b"Subject: x\r\n\r\nx",
        broadcast_id: None,
        priority: 0,
        not_before: None,
    };
    db.insert_message(&msg, &deliveries).await.unwrap();
    let done: Vec<_> = deliveries
        .iter()
        .map(|d| (d.id.clone(), Outcome::Sent { code: 250, response: "OK".into() }))
        .collect();
    db.complete(&done).await.unwrap();
    deliveries.into_iter().map(|d| d.id).collect()
}

fn verp_for_delivery(id: &str) -> String {
    verp::encode(&VERP_KEY, &VerpTarget::Delivery(uuid::Uuid::parse_str(id).unwrap()), BOUNCE_DOMAIN)
}

async fn send(addr: SocketAddr, from: &str, rcpts: &[&str], data: &[u8]) -> Vec<u16> {
    let mut c = SmtpClient::connect(addr, None, Duration::from_secs(5)).await.unwrap();
    assert_eq!(c.ehlo("mx.remote.test").await.unwrap().code, 250);
    let mut codes = vec![c.mail_from(from, data.len()).await.unwrap().code];
    for r in rcpts {
        codes.push(c.rcpt_to(r).await.unwrap().code);
    }
    if codes[1..].contains(&250) {
        codes.push(c.data(data).await.unwrap().code);
    }
    c.quit().await;
    codes
}

#[tokio::test]
async fn hard_bounce_suppresses_and_notifies() {
    let env = start(|_| {}, None).await;
    let mid = sigill_core::new_id();
    let ids = sent_message(&env.db, &mid, &[RCPT]).await;
    let verp = verp_for_delivery(&ids[0]);
    let raw = fixture("gmail_hard.eml", &verp, &format!("{mid}@mail.example.com"));
    assert_eq!(send(env.addr, "", &[&verp], &raw).await, vec![250, 250, 250]);

    let d = env.db.get_delivery(&ids[0]).await.unwrap().unwrap();
    assert_eq!((d.status, d.last_smtp_code), (DeliveryStatus::Bounced, Some(550)));
    assert!(env.db.is_suppressed(RCPT_NORM, Stream::Transactional).await.unwrap());
    let kinds: Vec<_> =
        env.db.events_for_delivery(&d.id).await.unwrap().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Queued, EventKind::Sent, EventKind::Bounced]);
    let hooks = env.db.due_webhooks(sigill_core::now_ms() + 1, 10).await.unwrap();
    assert!(hooks.iter().any(|h| h.payload.contains("\"bounced\"")));

    // The same bounce again changes nothing.
    assert_eq!(send(env.addr, "", &[&verp], &raw).await, vec![250, 250, 250]);
    assert_eq!(env.db.events_for_delivery(&d.id).await.unwrap().len(), 3);
}

#[tokio::test]
async fn soft_and_message_level_bounces() {
    let env = start(|_| {}, None).await;
    let mid = sigill_core::new_id();
    let ids = sent_message(&env.db, &mid, &[RCPT, "other@example.org"]).await;
    // A message-level VERP: the DSN's Final-Recipient picks the delivery.
    let verp =
        verp::encode(&VERP_KEY, &VerpTarget::Message(uuid::Uuid::parse_str(&mid).unwrap()), BOUNCE_DOMAIN);
    let raw = fixture("postfix_mailbox_full.eml", &verp, &format!("{mid}@mail.example.com"));
    assert_eq!(send(env.addr, "", &[&verp], &raw).await, vec![250, 250, 250]);

    let ds = env.db.deliveries_for_message(&mid).await.unwrap();
    let bounced: Vec<_> = ds.iter().filter(|d| d.status == DeliveryStatus::Bounced).collect();
    assert_eq!(bounced.len(), 1);
    assert_eq!(bounced[0].rcpt, "someone@example.org");
    assert!(ids.contains(&bounced[0].id));
    // A full mailbox is a soft bounce: counted, not suppressed.
    assert!(!env.db.is_suppressed(RCPT_NORM, Stream::Transactional).await.unwrap());

    // Delayed notices and auto-replies are accepted and ignored.
    let other = ds.iter().find(|d| d.rcpt == "other@example.org").unwrap();
    let verp = verp_for_delivery(&other.id);
    for name in ["delayed.eml", "auto_reply.eml"] {
        assert_eq!(send(env.addr, "", &[&verp], &fixture(name, &verp, "x@y")).await, vec![250, 250, 250]);
    }
    assert_eq!(env.db.get_delivery(&other.id).await.unwrap().unwrap().status, DeliveryStatus::Sent);
}

#[tokio::test]
async fn complaints_via_fbl_address() {
    let env = start(|_| {}, None).await;
    // Yahoo: matched through the VERP return path of the original message.
    let mid = sigill_core::new_id();
    let ids = sent_message(&env.db, &mid, &[RCPT]).await;
    let raw = fixture("yahoo_arf.eml", &verp_for_delivery(&ids[0]), &format!("{mid}@mail.example.com"));
    let fbl = format!("fbl@{BOUNCE_DOMAIN}");
    assert_eq!(send(env.addr, "feedback@arf.mail.yahoo.com", &[&fbl], &raw).await, vec![250, 250, 250]);
    let kinds: Vec<_> =
        env.db.events_for_delivery(&ids[0]).await.unwrap().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds.last(), Some(&EventKind::Complained));
    assert!(env.db.is_suppressed(RCPT_NORM, Stream::Broadcast).await.unwrap());

    // Microsoft JMRP: recipient redacted and no return path; matched by Message-ID.
    let mid = sigill_core::new_id();
    let ids = sent_message(&env.db, &mid, &["jmrp@hotmail.test"]).await;
    let raw = fixture("microsoft_jmrp.eml", "unused", &format!("{mid}@mail.example.com"));
    assert_eq!(send(env.addr, "staff@hotmail.com", &[&fbl], &raw).await, vec![250, 250, 250]);
    assert!(env.db.is_suppressed("jmrp@hotmail.test", Stream::Transactional).await.unwrap());
    let kinds: Vec<_> =
        env.db.events_for_delivery(&ids[0]).await.unwrap().into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds.last(), Some(&EventKind::Complained));
}

#[tokio::test]
async fn rejects_unknown_and_forged_recipients() {
    let env = start(|_| {}, None).await;
    let id = sigill_core::new_id();
    let good = verp_for_delivery(&id);
    let mut forged = good.clone();
    forged.replace_range(36..52, "0000000000000000");
    assert_ne!(good, forged);
    let codes = send(
        env.addr,
        "",
        &[
            &forged,
            &format!("postmaster@{BOUNCE_DOMAIN}"),
            &good.replace(BOUNCE_DOMAIN, "evil.test"),
            "abuse@bounces.example.com",
        ],
        b"Subject: x\r\n\r\nx\r\n",
    )
    .await;
    assert_eq!(codes, vec![250, 550, 550, 550, 550], "nothing accepted, so no DATA");
}

#[tokio::test]
async fn enforces_size_and_connection_limits() {
    let env = start(
        |s| {
            s.max_message_bytes = 200;
            s.max_connections = 1;
        },
        None,
    )
    .await;
    let id = sigill_core::new_id();
    let verp = verp_for_delivery(&id);
    let big = format!("Subject: x\r\n\r\n{}\r\n", "y".repeat(500));
    let mut c = SmtpClient::connect(env.addr, None, Duration::from_secs(5)).await.unwrap();
    c.ehlo("a.test").await.unwrap();
    // SIZE above the limit is refused at MAIL.
    assert_eq!(c.mail_from("", 10_000).await.unwrap().code, 552);
    assert_eq!(c.mail_from("", 10).await.unwrap().code, 250);
    assert_eq!(c.rcpt_to(&verp).await.unwrap().code, 250);
    assert_eq!(c.data(big.as_bytes()).await.unwrap().code, 552);

    // A second connection while the first is open is turned away.
    let second = SmtpClient::connect(env.addr, None, Duration::from_secs(5)).await;
    assert!(second.is_err());
    c.quit().await;
}

#[tokio::test]
async fn starttls_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["bounces.example.com".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let tls = sigill_bounce::load_tls(&cert_path, &key_path).unwrap();
    let env = start(|_| {}, Some(tls)).await;

    let mid = sigill_core::new_id();
    let ids = sent_message(&env.db, &mid, &[RCPT]).await;
    let verp = verp_for_delivery(&ids[0]);
    let raw = fixture("outlook_hard.eml", &verp, &format!("{mid}@mail.example.com"));
    let mut c = SmtpClient::connect(env.addr, None, Duration::from_secs(5)).await.unwrap();
    c.ehlo("mx.remote.test").await.unwrap();
    assert!(c.capabilities.starttls);
    let connectors = TlsConnectors::new();
    let mut c = c.starttls(&connectors.opportunistic, "bounces.example.com", "mx.remote.test").await.unwrap();
    assert_eq!(c.mail_from("", raw.len()).await.unwrap().code, 250);
    assert_eq!(c.rcpt_to(&verp).await.unwrap().code, 250);
    assert_eq!(c.data(&raw).await.unwrap().code, 250);
    c.quit().await;
    assert_eq!(env.db.get_delivery(&ids[0]).await.unwrap().unwrap().status, DeliveryStatus::Bounced);
}
