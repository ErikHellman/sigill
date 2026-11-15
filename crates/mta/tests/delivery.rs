//! End-to-end delivery tests against the in-repo fake SMTP server. No network access:
//! DNS answers come from a static table that points at 127.0.0.1.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use sigill_core::config::DeliveryMode;
use sigill_core::verp::{self, VerpTarget};
use sigill_core::{Config, DeliveryStatus, Stream};
use sigill_mta::dns::{DnsError, MxTarget, StaticResolver};
use sigill_mta::mta_sts::PolicyFetcher;
use sigill_mta::{Dispatcher, Mta};
use sigill_store::messages::{NewDelivery, NewMessage};
use sigill_store::testing::{TestDb, test_db};
use sigill_testkit::{FakeSmtp, Script};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;
const VERP_KEY: [u8; 32] = [5u8; 32];

struct NoPolicies;
impl PolicyFetcher for NoPolicies {
    fn fetch(&self, _d: &str) -> sigill_mta::dns::BoxFut<'_, Result<String, String>> {
        Box::pin(async { Err("no policies in tests".into()) })
    }
}

struct EnforcePolicy;
impl PolicyFetcher for EnforcePolicy {
    fn fetch(&self, _d: &str) -> sigill_mta::dns::BoxFut<'_, Result<String, String>> {
        Box::pin(async { Ok("version: STSv1\nmode: enforce\nmx: mx.sts.test\nmax_age: 600\n".into()) })
    }
}

fn config(port: u16) -> Config {
    let mut c = sigill_testkit::config();
    c.delivery.mx_port = port;
    c.delivery.poll_interval_secs = 1;
    c.delivery.smtp_timeout_secs = 5;
    c.streams.transactional.helo_hostname = "mta1.example.com".into();
    c
}

fn resolver() -> StaticResolver {
    StaticResolver::default()
        .with_mx("x.test", Ok(MxTarget::Hosts(vec!["mx.x.test".into()])))
        .with_mx("y.test", Ok(MxTarget::Hosts(vec!["dead.y.test".into(), "mx.y.test".into()])))
        .with_mx("null.test", Ok(MxTarget::NullMx))
        .with_mx("temp.test", Err(DnsError::Temporary("SERVFAIL".into())))
        .with_mx("sts.test", Ok(MxTarget::Hosts(vec!["mx.sts.test".into()])))
        .with_txt("_mta-sts.sts.test", &["v=STSv1; id=1"])
        .with_a("mx.x.test", &[LOCAL])
        .with_a("mx.y.test", &[LOCAL])
        .with_a("dead.y.test", &[Ipv4Addr::new(127, 0, 0, 2)])
        .with_a("mx.sts.test", &[LOCAL])
}

async fn seed(db: &TestDb, message_id: &str, rcpts: &[&str]) -> Vec<String> {
    if db.get_app("app").await.unwrap().is_none() {
        db.create_app("app", "app", "h", None, Stream::Transactional).await.unwrap();
    }
    let ids: Vec<String> = rcpts.iter().map(|_| sigill_core::new_id()).collect();
    let deliveries: Vec<NewDelivery> = rcpts
        .iter()
        .zip(&ids)
        .map(|(r, id)| NewDelivery {
            id: id.clone(),
            rcpt: r.to_string(),
            rcpt_domain: r.rsplit_once('@').unwrap().1.into(),
            suppressed: false,
        })
        .collect();
    db.insert_message(
        &NewMessage {
            id: message_id,
            app_id: "app",
            idempotency_key: None,
            stream: Stream::Transactional,
            template_key: "t",
            template_version: 1,
            from_addr: "noreply@mail.example.com",
            subject: "s",
            rendered_mime: b"From: noreply@mail.example.com\r\nSubject: s\r\n\r\nhello\r\n",
            broadcast_id: None,
            priority: 0,
            not_before: None,
        },
        &deliveries,
    )
    .await
    .unwrap();
    ids
}

struct Running {
    token: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

fn start(db: &TestDb, config: Config, resolver: StaticResolver, fetcher: Arc<dyn PolicyFetcher>) -> Running {
    let mta = Arc::new(Mta::new(db.store.clone(), Arc::new(config), Arc::new(resolver), fetcher, VERP_KEY));
    let token = CancellationToken::new();
    let handle = tokio::spawn(Dispatcher::new(mta, Arc::new(Notify::new())).run(token.clone()));
    Running { token, handle }
}

impl Running {
    async fn stop(self) {
        self.token.cancel();
        self.handle.await.unwrap();
    }
}

/// Wait until none of the deliveries is queued or sending.
async fn settle(db: &TestDb, ids: &[String]) -> Vec<sigill_store::messages::Delivery> {
    for _ in 0..300 {
        let mut all = Vec::new();
        for id in ids {
            all.push(db.get_delivery(id).await.unwrap().unwrap());
        }
        if all.iter().all(|d| !matches!(d.status, DeliveryStatus::Queued | DeliveryStatus::Sending)) {
            return all;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("deliveries did not settle");
}

#[tokio::test]
async fn mixed_replies_in_one_transaction() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(
        &db,
        &sigill_core::new_id(),
        &["ok1@x.test", "ok2@x.test", "reject@x.test", "defer@x.test", "blocked@x.test"],
    )
    .await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;

    let status: Vec<_> = ds.iter().map(|d| d.status).collect();
    assert_eq!(
        status,
        vec![
            DeliveryStatus::Sent,
            DeliveryStatus::Sent,
            DeliveryStatus::Bounced,
            DeliveryStatus::Deferred,
            DeliveryStatus::Bounced
        ]
    );
    assert_eq!(ds[2].last_smtp_code, Some(550));
    assert!(ds[3].next_attempt_at > sigill_core::now_ms() + 4 * 60_000, "first retry in about 5 minutes");
    assert!(
        db.is_suppressed("reject@x.test", Stream::Transactional).await.unwrap(),
        "hard bounce suppresses"
    );
    assert!(
        !db.is_suppressed("blocked@x.test", Stream::Transactional).await.unwrap(),
        "policy bounce does not"
    );

    let got = srv.received();
    assert_eq!(got.len(), 1, "one transaction for the shared MX");
    assert_eq!(got[0].rcpt_to, vec!["ok1@x.test".to_string(), "ok2@x.test".to_string()]);
    assert!(got[0].tls, "STARTTLS used when offered");
    assert_eq!(got[0].helo, "mta1.example.com");
    // Several recipients share a transaction, so the return path names the message.
    let target = verp::decode(&VERP_KEY, &got[0].mail_from).unwrap();
    assert!(matches!(target, VerpTarget::Message(_)));
    assert!(got[0].mail_from.ends_with("@bounces.example.com"));
}

#[tokio::test]
async fn single_recipient_verp_failover_and_pooling() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let a = seed(&db, &sigill_core::new_id(), &["one@y.test"]).await;
    let b = seed(&db, &sigill_core::new_id(), &["two@y.test"]).await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let all: Vec<String> = a.iter().chain(&b).cloned().collect();
    let ds = settle(&db, &all).await;
    run.stop().await;
    assert!(ds.iter().all(|d| d.status == DeliveryStatus::Sent), "{ds:?}");
    let got = srv.received();
    assert_eq!(got.len(), 2);
    let target = verp::decode(&VERP_KEY, &got[0].mail_from).unwrap();
    assert!(matches!(target, VerpTarget::Delivery(_)));
    assert!(srv.connections() <= 2, "connections are reused ({})", srv.connections());
}

#[tokio::test]
async fn dns_failures() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["a@null.test"]).await;
    let ids2 = seed(&db, &sigill_core::new_id(), &["a@nowhere.test"]).await;
    let ids3 = seed(&db, &sigill_core::new_id(), &["a@temp.test"]).await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let all: Vec<String> = ids.iter().chain(&ids2).chain(&ids3).cloned().collect();
    let ds = settle(&db, &all).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Bounced);
    assert!(ds[0].last_response.as_deref().unwrap().contains("null MX"));
    assert_eq!(ds[1].status, DeliveryStatus::Bounced);
    assert_eq!(ds[2].status, DeliveryStatus::Deferred);
    assert!(db.is_suppressed("a@null.test", Stream::Transactional).await.unwrap());
}

#[tokio::test]
async fn rate_limit_backs_off_domain() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["ratelimit@x.test"]).await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Deferred);
    assert_eq!(ds[0].last_smtp_code, Some(421));
    let backoff = db.backed_off_domains().await.unwrap();
    assert_eq!(backoff.len(), 1);
    assert_eq!(backoff[0].0, "x.test");
}

#[tokio::test]
async fn dropped_connection_defers() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["drop@x.test"]).await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Deferred);
    assert_eq!(ds[0].attempts, 1);
}

#[tokio::test]
async fn mta_sts_enforce_refuses_untrusted_tls() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["a@sts.test"]).await;
    let run = start(&db, config(srv.port()), resolver(), Arc::new(EnforcePolicy));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Deferred, "never falls back to plain text");
    assert!(ds[0].last_response.as_deref().unwrap().contains("TLS"));
    assert!(srv.received().is_empty());
}

#[tokio::test]
async fn smarthost_without_tls() {
    let srv = FakeSmtp::start(Script { starttls: false, ..Default::default() }).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["anyone@gmail.com", "other@outlook.com"]).await;
    let mut cfg = config(1);
    cfg.delivery.mode = DeliveryMode::Smarthost;
    cfg.delivery.smarthost = format!("127.0.0.1:{}", srv.port());
    let run = start(&db, cfg, StaticResolver::default(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert!(ds.iter().all(|d| d.status == DeliveryStatus::Sent));
    let got = srv.received();
    assert_eq!(got.len(), 2, "different domains are separate transactions");
    assert!(!got[0].tls);
}

#[tokio::test]
async fn crash_recovery_sends_once() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["ok@x.test"]).await;
    // A previous process claimed the row and died mid-send.
    let claimed = db.claim_due(Stream::Transactional, sigill_core::now_ms() + 1, 10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(db.get_delivery(&ids[0]).await.unwrap().unwrap().status, DeliveryStatus::Sending);
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Sent);
    assert_eq!(srv.received().len(), 1);
}

#[tokio::test]
async fn suppressed_just_before_delivery() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["late@x.test"]).await;
    db.add_suppression(
        "late@x.test",
        sigill_core::SuppressionScope::All,
        sigill_core::SuppressionReason::Complaint,
        None,
    )
    .await
    .unwrap();
    let run = start(&db, config(srv.port()), resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Suppressed);
    assert!(srv.received().is_empty());
}

#[tokio::test]
async fn refuses_mx_on_private_addresses() {
    let srv = FakeSmtp::start(Script::default()).await;
    let db = test_db().await;
    let ids = seed(&db, &sigill_core::new_id(), &["a@x.test"]).await;
    let mut cfg = config(srv.port());
    cfg.delivery.allow_private_mx = false;
    let run = start(&db, cfg, resolver(), Arc::new(NoPolicies));
    let ds = settle(&db, &ids).await;
    run.stop().await;
    assert_eq!(ds[0].status, DeliveryStatus::Bounced);
    assert!(ds[0].last_response.as_deref().unwrap().contains("non-public"));
    assert!(srv.received().is_empty(), "nothing was sent to the loopback address");
}
