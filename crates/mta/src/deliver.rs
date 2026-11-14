//! Delivering one job: one message to one or more recipients at the same domain.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sigill_core::address::normalize;
use sigill_core::config::DeliveryMode;
use sigill_core::reply::{Outcome as ReplyOutcome, Reply};
use sigill_core::retry::{RetryDecision, next_attempt};
use sigill_core::verp::{self, VerpTarget};
use sigill_core::{Config, MINUTE_MS, Stream, now_ms};
use sigill_store::Store;
use sigill_store::queue::{Claimed, Outcome};

use crate::client::{SmtpClient, SmtpError, TlsConnectors};
use crate::dns::{DnsError, MxTarget, Resolver};
use crate::mta_sts::{Mode, MtaSts, PolicyFetcher};
use crate::pool::{Pool, PoolKey};
use crate::throttle::Throttle;

/// How long a domain is skipped after a rate-limit reply.
pub const RATE_LIMIT_BACKOFF_MS: i64 = 10 * MINUTE_MS;

/// Deliveries of one message to one recipient domain.
#[derive(Debug, Clone)]
pub struct Job {
    pub message_id: String,
    pub stream: Stream,
    pub rcpt_domain: String,
    pub deliveries: Vec<Claimed>,
}

/// Group claimed rows (sorted by message, then domain) into jobs of at most `max` recipients.
pub fn group(rows: Vec<Claimed>, max: usize) -> Vec<Job> {
    let mut jobs: Vec<Job> = Vec::new();
    for row in rows {
        match jobs.last_mut() {
            Some(j)
                if j.message_id == row.message_id
                    && j.rcpt_domain == row.rcpt_domain
                    && j.deliveries.len() < max =>
            {
                j.deliveries.push(row)
            }
            _ => jobs.push(Job {
                message_id: row.message_id.clone(),
                stream: row.stream,
                rcpt_domain: row.rcpt_domain.clone(),
                deliveries: vec![row],
            }),
        }
    }
    jobs
}

/// One place to connect to.
#[derive(Debug, Clone)]
struct Target {
    host: String,
    addr: SocketAddr,
}

/// TLS requirements for a job.
#[derive(Debug, Clone, Copy, Default)]
struct TlsPolicy {
    /// MTA-STS enforce: STARTTLS with a valid certificate or nothing.
    required: bool,
}

/// The delivery engine shared by all workers.
pub struct Mta {
    pub store: Store,
    pub config: Arc<Config>,
    pub resolver: Arc<dyn Resolver>,
    pub throttle: Throttle,
    pub pool: Pool,
    sts: MtaSts,
    tls: TlsConnectors,
    verp_key: [u8; 32],
    next_ip: AtomicUsize,
}

/// What came back from a transaction attempt.
enum Attempt {
    /// The server answered; per-delivery replies (or one reply for all).
    Replies(Vec<(String, Reply)>),
    /// Could not talk to this host; try the next one.
    TryNext(String),
}

impl Mta {
    pub fn new(
        store: Store,
        config: Arc<Config>,
        resolver: Arc<dyn Resolver>,
        fetcher: Arc<dyn PolicyFetcher>,
        verp_key: [u8; 32],
    ) -> Self {
        let pool =
            Pool::new(Duration::from_secs(config.delivery.pool_idle_secs), config.delivery.pool_max_messages);
        Self {
            sts: MtaSts::new(resolver.clone(), fetcher),
            store,
            config,
            resolver,
            throttle: Throttle::default(),
            pool,
            tls: TlsConnectors::new(),
            verp_key,
            next_ip: AtomicUsize::new(0),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.delivery.smtp_timeout_secs)
    }

    /// Next source IP of the stream's pool, round robin.
    fn source_ip(&self, stream: Stream) -> Option<Ipv4Addr> {
        let ips = &self.config.streams.get(stream).ips;
        (!ips.is_empty()).then(|| ips[self.next_ip.fetch_add(1, Ordering::Relaxed) % ips.len()])
    }

    /// Deliver a job and return an outcome for every delivery in it.
    pub async fn deliver(&self, job: &Job) -> Vec<(String, Outcome)> {
        match self.deliver_inner(job).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(message_id = %job.message_id, error = %e, "delivery failed internally");
                sigill_core::telemetry::capture_error(&e);
                let now = now_ms();
                job.deliveries
                    .iter()
                    .map(|d| (d.id.clone(), self.temp_failure(d, None, format!("internal error: {e}"), now)))
                    .collect()
            }
        }
    }

    async fn deliver_inner(&self, job: &Job) -> Result<Vec<(String, Outcome)>, sigill_store::Error> {
        let now = now_ms();
        let mut results = Vec::new();
        let (Some(msg), Some(mime)) =
            (self.store.get_message(&job.message_id).await?, self.store.message_mime(&job.message_id).await?)
        else {
            return Ok(job
                .deliveries
                .iter()
                .map(|d| {
                    (
                        d.id.clone(),
                        Outcome::Failed { code: None, response: "message body no longer stored".into() },
                    )
                })
                .collect());
        };

        // Suppressions are checked again right before sending.
        let mut active = Vec::new();
        for d in &job.deliveries {
            let addr = normalize(&d.rcpt).unwrap_or_else(|| d.rcpt.to_lowercase());
            if self.store.is_suppressed(&addr, job.stream).await? {
                results.push((d.id.clone(), Outcome::Suppressed));
            } else {
                active.push(d.clone());
            }
        }
        if active.is_empty() {
            return Ok(results);
        }

        let from_domain = sigill_core::address::domain_of(&msg.from_addr).unwrap_or_default();
        let bounce_domain = self
            .config
            .domain(&from_domain)
            .map(|d| d.return_path_domain.clone())
            .unwrap_or_else(|| from_domain.clone());
        let target = if active.len() == 1 {
            VerpTarget::Delivery(uuid_of(&active[0].id))
        } else {
            VerpTarget::Message(uuid_of(&job.message_id))
        };
        let mail_from = verp::encode(&self.verp_key, &target, &bounce_domain);

        let (targets, policy) = match self.route(&job.rcpt_domain).await {
            Ok(r) => r,
            Err(RouteError::Permanent(why)) => {
                results.extend(active.iter().map(|d| {
                    let suppress = normalize(&d.rcpt);
                    (d.id.clone(), Outcome::Bounced { code: None, response: why.clone(), suppress })
                }));
                return Ok(results);
            }
            Err(RouteError::Temporary(why)) => {
                results.extend(
                    active.iter().map(|d| (d.id.clone(), self.temp_failure(d, None, why.clone(), now))),
                );
                return Ok(results);
            }
        };

        let _conn = self.throttle.connection(&job.rcpt_domain).await;
        let source = self.source_ip(job.stream);
        let helo = self.config.streams.get(job.stream).helo_hostname.clone();
        let mut last_error = String::from("no MX host could be reached");
        let mut replies = None;
        for t in &targets {
            match self.attempt(t, source, &helo, policy, &mail_from, &active, &mime).await {
                Attempt::Replies(r) => {
                    replies = Some(r);
                    break;
                }
                Attempt::TryNext(why) => {
                    tracing::warn!(message_id = %job.message_id, rcpt_domain = %job.rcpt_domain, mx = %t.host, error = %why, "MX attempt failed");
                    last_error = format!("{}: {why}", t.host);
                }
            }
        }
        let now = now_ms();
        let Some(replies) = replies else {
            results.extend(
                active.iter().map(|d| (d.id.clone(), self.temp_failure(d, None, last_error.clone(), now))),
            );
            return Ok(results);
        };
        let mut rate_limited = false;
        for (id, reply) in replies {
            let d = active.iter().find(|d| d.id == id).expect("reply for an active delivery");
            let (outcome, limited) = self.map_reply(d, &reply, now);
            rate_limited |= limited;
            results.push((id, outcome));
        }
        if rate_limited {
            tracing::warn!(rcpt_domain = %job.rcpt_domain, "rate limited; backing off domain");
            self.store.set_backoff(&job.rcpt_domain, now + RATE_LIMIT_BACKOFF_MS).await?;
        }
        Ok(results)
    }

    /// Outcome for a temporary failure: retry later, or fail once the window is over.
    fn temp_failure(&self, d: &Claimed, code: Option<u16>, response: String, now: i64) -> Outcome {
        match next_attempt(d.created_at, d.attempts + 1, now, self.config.delivery.max_retry_hours) {
            RetryDecision::RetryAt(t) => Outcome::Deferred { code, response, next_attempt_at: t },
            RetryDecision::GiveUp => Outcome::Failed { code, response },
        }
    }

    /// Map a server reply to an outcome; the flag says whether it was a rate limit.
    fn map_reply(&self, d: &Claimed, reply: &Reply, now: i64) -> (Outcome, bool) {
        match reply.outcome() {
            ReplyOutcome::Sent => (Outcome::Sent { code: reply.code, response: reply.text.clone() }, false),
            ReplyOutcome::Defer { rate_limited } => {
                (self.temp_failure(d, Some(reply.code), reply.text.clone(), now), rate_limited)
            }
            ReplyOutcome::Bounce { hard } => (
                Outcome::Bounced {
                    code: Some(reply.code),
                    response: reply.text.clone(),
                    suppress: if hard { normalize(&d.rcpt) } else { None },
                },
                false,
            ),
        }
    }

    async fn route(&self, domain: &str) -> Result<(Vec<Target>, TlsPolicy), RouteError> {
        if self.config.delivery.mode == DeliveryMode::Smarthost {
            let addr = tokio::net::lookup_host(&self.config.delivery.smarthost)
                .await
                .map_err(|e| RouteError::Temporary(format!("smarthost lookup failed: {e}")))?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| RouteError::Temporary("smarthost has no IPv4 address".into()))?;
            let host =
                self.config.delivery.smarthost.rsplit_once(':').map_or("smarthost", |(h, _)| h).to_string();
            return Ok((vec![Target { host, addr }], TlsPolicy::default()));
        }
        let mut hosts = match self.resolver.mx(domain).await {
            Ok(MxTarget::Hosts(h)) => h,
            Ok(MxTarget::NullMx) => {
                return Err(RouteError::Permanent("5.1.10 recipient domain has a null MX".into()));
            }
            Err(DnsError::NxDomain) => {
                return Err(RouteError::Permanent("5.1.2 recipient domain does not exist".into()));
            }
            Err(DnsError::Temporary(e)) => return Err(RouteError::Temporary(e)),
        };
        let mut policy = TlsPolicy::default();
        if self.config.delivery.mta_sts
            && let Some(p) = self.sts.policy(domain).await
            && p.mode == Mode::Enforce
        {
            hosts.retain(|h| p.allows(h));
            if hosts.is_empty() {
                return Err(RouteError::Temporary("no MX host matches the domain's MTA-STS policy".into()));
            }
            policy.required = true;
        }
        let mut targets = Vec::new();
        let mut last = String::new();
        for host in hosts {
            match self.resolver.ipv4(&host).await {
                Ok(ips) => targets.extend(ips.into_iter().map(|ip| Target {
                    host: host.clone(),
                    addr: SocketAddr::from((ip, self.config.delivery.mx_port)),
                })),
                Err(e) => last = format!("{host}: {e}"),
            }
        }
        if targets.is_empty() {
            return Err(RouteError::Temporary(format!("no MX host has an IPv4 address ({last})")));
        }
        Ok((targets, policy))
    }

    /// Open a connection and negotiate TLS as far as policy and the server allow.
    async fn open(
        &self,
        t: &Target,
        source: Option<Ipv4Addr>,
        helo: &str,
        policy: TlsPolicy,
    ) -> Result<SmtpClient, String> {
        let timeout = self.timeout();
        let mut c = SmtpClient::connect(t.addr, source, timeout).await.map_err(|e| e.to_string())?;
        let r = c.ehlo(helo).await.map_err(|e| e.to_string())?;
        if r.code != 250 {
            return Err(format!("EHLO refused: {r}"));
        }
        if !c.capabilities.starttls {
            if policy.required {
                c.quit().await;
                return Err("STARTTLS not offered but the MTA-STS policy requires TLS".into());
            }
            return Ok(c);
        }
        let connector = if policy.required { &self.tls.verified } else { &self.tls.opportunistic };
        match c.starttls(connector, &t.host, helo).await {
            Ok(c) => Ok(c),
            Err(e) if policy.required => Err(format!("TLS required by MTA-STS: {e}")),
            Err(e) => {
                // Opportunistic TLS failed: retry in plain text, as other MTAs do.
                tracing::warn!(mx = %t.host, error = %e, "STARTTLS failed; retrying without TLS");
                let mut c = SmtpClient::connect(t.addr, source, timeout).await.map_err(|e| e.to_string())?;
                c.ehlo(helo).await.map_err(|e| e.to_string())?;
                Ok(c)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        t: &Target,
        source: Option<Ipv4Addr>,
        helo: &str,
        policy: TlsPolicy,
        mail_from: &str,
        active: &[Claimed],
        mime: &[u8],
    ) -> Attempt {
        let key = PoolKey { addr: t.addr, source, verified_tls: policy.required };
        // A pooled connection may have been closed by the server; fall back to a new one.
        let mut client = None;
        if let Some(mut c) = self.pool.take(&key) {
            match c.mail_from(mail_from, mime.len()).await {
                Ok(r) => client = Some((c, r)),
                Err(_) => tracing::debug!(mx = %t.host, "pooled connection was stale"),
            }
        }
        let (mut c, mail_reply) = match client {
            Some(x) => x,
            None => {
                let mut c = match self.open(t, source, helo, policy).await {
                    Ok(c) => c,
                    Err(e) => return Attempt::TryNext(e),
                };
                match c.mail_from(mail_from, mime.len()).await {
                    Ok(r) => (c, r),
                    Err(e) => return Attempt::TryNext(e.to_string()),
                }
            }
        };
        if mail_reply.code / 100 != 2 {
            let _ = c.rset().await;
            self.release(key, c, &mail_reply).await;
            return Attempt::Replies(active.iter().map(|d| (d.id.clone(), mail_reply.clone())).collect());
        }
        let mut replies = Vec::new();
        let mut accepted = Vec::new();
        for d in active {
            match c.rcpt_to(&d.rcpt).await {
                Ok(r) if r.code / 100 == 2 => accepted.push(d.id.clone()),
                Ok(r) => replies.push((d.id.clone(), r)),
                Err(e) => return self.broken(c, active, e).await,
            }
        }
        if accepted.is_empty() {
            let _ = c.rset().await;
            self.release(key, c, &Reply::new(250, "")).await;
            return Attempt::Replies(replies);
        }
        match c.data(mime).await {
            Ok(r) => {
                replies.extend(accepted.into_iter().map(|id| (id, r.clone())));
                self.release(key, c, &r).await;
                Attempt::Replies(replies)
            }
            Err(e) => self.broken(c, active, e).await,
        }
    }

    /// Pool the connection unless the server is going away.
    async fn release(&self, key: PoolKey, c: SmtpClient, last: &Reply) {
        if last.code == 421 {
            c.quit().await;
        } else if let Some(c) = self.pool.put(key, c) {
            c.quit().await;
        }
    }

    /// The connection broke mid-transaction: nothing was confirmed, so retry elsewhere.
    async fn broken(&self, c: SmtpClient, _active: &[Claimed], e: SmtpError) -> Attempt {
        drop(c);
        Attempt::TryNext(e.to_string())
    }

    /// Close idle pooled connections.
    pub async fn reap_pool(&self) {
        for c in self.pool.expired() {
            c.quit().await;
        }
    }

    pub async fn close_pool(&self) {
        for c in self.pool.drain() {
            c.quit().await;
        }
    }
}

enum RouteError {
    Permanent(String),
    Temporary(String),
}

fn uuid_of(id: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(id).unwrap_or_else(|_| uuid::Uuid::nil())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(m: &str, d: &str, id: &str) -> Claimed {
        Claimed {
            id: id.into(),
            message_id: m.into(),
            stream: Stream::Transactional,
            rcpt: format!("{id}@{d}"),
            rcpt_domain: d.into(),
            attempts: 0,
            created_at: 0,
        }
    }

    #[test]
    fn groups_by_message_and_domain() {
        let rows = vec![
            row("m1", "a.com", "1"),
            row("m1", "a.com", "2"),
            row("m1", "b.com", "3"),
            row("m2", "a.com", "4"),
        ];
        let jobs = group(rows, 50);
        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].deliveries.len(), 2);
        let jobs = group(vec![row("m1", "a.com", "1"), row("m1", "a.com", "2")], 1);
        assert_eq!(jobs.len(), 2);
    }
}
