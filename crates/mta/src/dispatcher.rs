//! The dispatcher: claims due deliveries per stream and runs them on per-stream worker
//! slots, so transactional mail never waits behind a broadcast.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sigill_core::address::normalize;
use sigill_core::{Stream, now_ms, telemetry};
use sigill_store::queue::Outcome;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::deliver::{Job, Mta, group};
use crate::throttle::{Limits, Reservation};

/// Most recipients sent in one SMTP transaction.
pub const MAX_RCPTS_PER_TRANSACTION: usize = 50;

pub struct Dispatcher {
    mta: Arc<Mta>,
    wake: Arc<Notify>,
    slots: HashMap<Stream, Arc<Semaphore>>,
}

impl Dispatcher {
    pub fn new(mta: Arc<Mta>, wake: Arc<Notify>) -> Self {
        let slots = Stream::ALL
            .iter()
            .map(|s| (*s, Arc::new(Semaphore::new(mta.config.streams.get(*s).workers.max(1)))))
            .collect();
        Self { mta, wake, slots }
    }

    async fn refresh_limits(&self) {
        match self.mta.store.throttles().await {
            Ok(rows) => self.mta.throttle.set_limits(
                rows.into_iter()
                    .map(|t| {
                        (t.rcpt_domain, Limits { max_conns: t.max_conns, max_per_minute: t.max_per_minute })
                    })
                    .collect(),
            ),
            Err(e) => tracing::error!(error = %e, "cannot load domain throttles"),
        }
    }

    async fn report_queue_depth(&self) {
        for s in Stream::ALL {
            if let Ok(n) = self.mta.store.queue_depth(*s).await {
                telemetry::track("queue_depth", &[("stream", s.as_str()), ("depth", &n.to_string())]);
            }
        }
    }

    /// Run until `shutdown` is cancelled, then finish in-flight sends and put anything
    /// unfinished back in the queue.
    pub async fn run(self, shutdown: CancellationToken) {
        match self.mta.store.reset_sending().await {
            Ok(0) => {}
            Ok(n) => tracing::warn!(count = n, "crash recovery: returned deliveries to the queue"),
            Err(e) => tracing::error!(error = %e, "crash recovery failed"),
        }
        self.refresh_limits().await;
        let poll = Duration::from_secs(self.mta.config.delivery.poll_interval_secs.max(1));
        let mut tasks = JoinSet::new();
        let mut last_minute = Instant::now();
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            if last_minute.elapsed() >= Duration::from_secs(60) {
                last_minute = Instant::now();
                self.refresh_limits().await;
                self.report_queue_depth().await;
                self.mta.reap_pool().await;
            }
            while tasks.try_join_next().is_some() {}
            let claimed = self.dispatch_round(&mut tasks).await;
            if claimed {
                continue;
            }
            let sleep = match self.mta.store.next_due_at().await {
                Ok(Some(t)) => Duration::from_millis((t - now_ms()).clamp(0, poll.as_millis() as i64) as u64),
                _ => poll,
            };
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(sleep.max(Duration::from_millis(50))) => {}
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tracing::info!(in_flight = tasks.len(), "dispatcher stopping; finishing in-flight sends");
        let drain = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(Duration::from_secs(60), drain).await.is_err() {
            tasks.abort_all();
        }
        if let Ok(n) = self.mta.store.reset_sending().await
            && n > 0
        {
            tracing::info!(count = n, "returned unfinished deliveries to the queue");
        }
        self.mta.close_pool().await;
    }

    /// Claim and start work for each stream. Returns true if anything was claimed.
    async fn dispatch_round(&self, tasks: &mut JoinSet<()>) -> bool {
        let mut claimed_any = false;
        let now = now_ms();
        for stream in Stream::ALL {
            let slots = self.slots[stream].clone();
            let free = slots.available_permits() as i64;
            if free == 0 {
                continue;
            }
            let limit = (free * 10).min(self.mta.config.delivery.batch_size.max(1));
            let rows = match self.mta.store.claim_due(*stream, now, limit).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "claiming deliveries failed");
                    continue;
                }
            };
            if rows.is_empty() {
                continue;
            }
            claimed_any = true;
            for job in group(rows, MAX_RCPTS_PER_TRANSACTION) {
                if let Reservation::RetryIn(d) =
                    self.mta.throttle.reserve(&job.rcpt_domain, job.deliveries.len() as i64)
                {
                    let at = now_ms() + d.as_millis() as i64;
                    let released: Vec<_> = job
                        .deliveries
                        .iter()
                        .map(|x| (x.id.clone(), Outcome::Released { next_attempt_at: at }))
                        .collect();
                    if let Err(e) = self.mta.store.complete(&released).await {
                        tracing::error!(error = %e, "releasing throttled deliveries failed");
                    }
                    continue;
                }
                let mta = self.mta.clone();
                let slots = slots.clone();
                tasks.spawn(async move {
                    let _slot = slots.acquire_owned().await.expect("semaphore never closed");
                    run_job(&mta, job).await;
                });
            }
        }
        claimed_any
    }
}

async fn run_job(mta: &Mta, job: Job) {
    let results = mta.deliver(&job).await;
    if let Err(e) = mta.store.complete(&results).await {
        tracing::error!(message_id = %job.message_id, error = %e, "recording delivery results failed");
        sigill_core::telemetry::capture_error(&e);
        return;
    }
    for (id, outcome) in &results {
        let (event, code) = match outcome {
            Outcome::Sent { code, .. } => ("delivery_sent", Some(*code)),
            Outcome::Deferred { code, .. } => ("delivery_deferred", *code),
            Outcome::Bounced { code, .. } => ("delivery_bounced", *code),
            Outcome::Failed { code, .. } => ("delivery_failed", *code),
            Outcome::Suppressed => ("delivery_suppressed", None),
            Outcome::Released { .. } => continue,
        };
        tracing::info!(message_id = %job.message_id, delivery_id = %id, rcpt_domain = %job.rcpt_domain,
            stream = %job.stream, smtp_code = code, "{event}");
        telemetry::track(event, &[("stream", job.stream.as_str()), ("rcpt_domain", &job.rcpt_domain)]);
        // Synchronous soft bounces count towards suppression too.
        if let Outcome::Bounced { suppress: None, .. } = outcome
            && let Some(d) = job.deliveries.iter().find(|d| &d.id == id)
            && let Some(addr) = normalize(&d.rcpt)
            && let Err(e) = mta.store.record_soft_bounce(&addr, id).await
        {
            tracing::error!(error = %e, "recording soft bounce failed");
        }
    }
}
