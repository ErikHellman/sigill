//! Acting on received reports: matching them to deliveries and recording bounces and
//! complaints.

use sigill_core::address::normalize;
use sigill_core::telemetry;
use sigill_core::verp::{self, VerpTarget};
use sigill_store::Store;
use sigill_store::messages::Delivery;
use tracing::{debug, info};

use crate::parse::{self, Feedback, RecipientStatus, Report, ReportKind, Verdict};

/// Who a received message was addressed to (its accepted RCPT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A signed VERP return path.
    Verp(VerpTarget),
    /// The complaint (feedback loop) address.
    Complaint,
    /// The DMARC aggregate report address.
    Dmarc,
}

/// What processing one message changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub hard_bounces: usize,
    pub soft_bounces: usize,
    pub complaints: usize,
    pub dmarc_reports: usize,
}

#[derive(Clone)]
pub struct Processor {
    store: Store,
    verp_key: [u8; 32],
}

impl Processor {
    pub fn new(store: Store, verp_key: [u8; 32]) -> Self {
        Self { store, verp_key }
    }

    /// Process one received message for its accepted recipients.
    pub async fn process(&self, targets: &[Target], raw: &[u8]) -> sigill_store::Result<Summary> {
        let report = parse::parse(raw);
        let mut summary = Summary::default();
        debug!(kind = ?report.kind, recipients = report.recipients.len(), "report parsed");
        for target in targets {
            match target {
                Target::Verp(t) if report.kind == ReportKind::Feedback => {
                    self.complaint(&report, Some(t.clone()), &mut summary).await?
                }
                Target::Verp(t) => self.bounce(t, &report, &mut summary).await?,
                Target::Complaint => self.complaint(&report, None, &mut summary).await?,
                Target::Dmarc => self.dmarc(raw, &mut summary).await?,
            }
        }
        Ok(summary)
    }

    async fn bounce(
        &self,
        target: &VerpTarget,
        report: &Report,
        summary: &mut Summary,
    ) -> sigill_store::Result<()> {
        let failed: Vec<&RecipientStatus> =
            report.recipients.iter().filter(|r| r.verdict() != Verdict::Ignore).collect();
        if failed.is_empty() {
            return Ok(());
        }
        let pairs: Vec<(Delivery, &RecipientStatus)> = match target {
            VerpTarget::Delivery(id) => {
                let Some(d) = self.store.get_delivery(&id.hyphenated().to_string()).await? else {
                    return Ok(());
                };
                let status = failed
                    .iter()
                    .find(|r| same_address(r.recipient.as_deref(), &d.rcpt))
                    .unwrap_or(&failed[0]);
                vec![(d, *status)]
            }
            VerpTarget::Message(id) => {
                let deliveries = self.store.deliveries_for_message(&id.hyphenated().to_string()).await?;
                match_recipients(deliveries, &failed)
            }
        };
        for (d, status) in pairs {
            let verdict = status.verdict();
            let address = normalize(&d.rcpt).unwrap_or_else(|| d.rcpt.clone());
            let suppress = (verdict == Verdict::Hard).then_some(address.as_str());
            if !self
                .store
                .record_async_bounce(&d.id, status.effective_code(), &status.diagnostic, suppress)
                .await?
            {
                continue;
            }
            let kind = if verdict == Verdict::Hard {
                summary.hard_bounces += 1;
                "hard"
            } else {
                summary.soft_bounces += 1;
                if self.store.record_soft_bounce(&address, &d.id).await? {
                    info!(delivery_id = %d.id, rcpt_domain = %d.rcpt_domain, "address suppressed after repeated soft bounces");
                }
                "soft"
            };
            info!(delivery_id = %d.id, rcpt_domain = %d.rcpt_domain, kind, "asynchronous bounce");
            telemetry::track(
                "delivery_bounced",
                &[
                    ("stream", d.stream.as_str()),
                    ("rcpt_domain", &d.rcpt_domain),
                    ("kind", kind),
                    ("source", "dsn"),
                ],
            );
        }
        Ok(())
    }

    async fn dmarc(&self, raw: &[u8], summary: &mut Summary) -> sigill_store::Result<()> {
        for r in crate::dmarc::extract_reports(raw) {
            let stored = self
                .store
                .insert_dmarc_report(&sigill_store::dmarc::NewDmarcReport {
                    org_name: &r.org_name,
                    report_id: &r.report_id,
                    domain: &r.domain,
                    date_begin: r.date_begin,
                    date_end: r.date_end,
                    policy: &r.policy,
                    records: &r.records,
                })
                .await?;
            if stored {
                summary.dmarc_reports += 1;
                let failed: i64 = r.records.iter().filter(|x| !x.passed()).map(|x| x.count).sum();
                let total: i64 = r.records.iter().map(|x| x.count).sum();
                info!(org = %r.org_name, domain = %r.domain, total, failed, "DMARC report stored");
                telemetry::track(
                    "dmarc_report",
                    &[("domain", &r.domain), ("total", &total.to_string()), ("failed", &failed.to_string())],
                );
            }
        }
        Ok(())
    }

    async fn complaint(
        &self,
        report: &Report,
        hint: Option<VerpTarget>,
        summary: &mut Summary,
    ) -> sigill_store::Result<()> {
        let Some(feedback) = report.feedback.as_ref().filter(|f| f.is_complaint()) else { return Ok(()) };
        let Some(d) = self.complained_delivery(report, feedback, hint).await? else {
            debug!("complaint could not be matched to a delivery");
            return Ok(());
        };
        let address = normalize(&d.rcpt).unwrap_or_else(|| d.rcpt.clone());
        if self.store.record_complaint(&d.id, &address).await? {
            summary.complaints += 1;
            info!(delivery_id = %d.id, rcpt_domain = %d.rcpt_domain, "complaint");
            telemetry::track(
                "complaint_received",
                &[("stream", d.stream.as_str()), ("rcpt_domain", &d.rcpt_domain)],
            );
        }
        Ok(())
    }

    /// Find the delivery a complaint is about: from a VERP address (the envelope or the
    /// original's `Return-Path`), else from the original `Message-ID`.
    async fn complained_delivery(
        &self,
        report: &Report,
        feedback: &Feedback,
        hint: Option<VerpTarget>,
    ) -> sigill_store::Result<Option<Delivery>> {
        let mut message_ids: Vec<String> = Vec::new();
        let targets = hint
            .into_iter()
            .chain(report.verp_candidates.iter().filter_map(|a| verp::decode(&self.verp_key, a)));
        for t in targets {
            match t {
                VerpTarget::Delivery(id) => {
                    if let Some(d) = self.store.get_delivery(&id.hyphenated().to_string()).await? {
                        return Ok(Some(d));
                    }
                }
                VerpTarget::Message(id) => message_ids.push(id.hyphenated().to_string()),
            }
        }
        message_ids.extend(
            report
                .original_message_ids
                .iter()
                .filter_map(|m| m.split_once('@').map(|(local, _)| local.to_string())),
        );
        for id in message_ids {
            let deliveries = self.store.deliveries_for_message(&id).await?;
            if let Some(rcpt) = &feedback.original_rcpt
                && let Some(d) = deliveries.iter().find(|d| same_address(Some(rcpt), &d.rcpt))
            {
                return Ok(Some(d.clone()));
            }
            if deliveries.len() == 1 {
                return Ok(deliveries.into_iter().next());
            }
        }
        Ok(None)
    }
}

fn same_address(a: Option<&str>, b: &str) -> bool {
    match (a.and_then(normalize), normalize(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Pair DSN recipients with the deliveries of one message.
fn match_recipients<'a>(
    deliveries: Vec<Delivery>,
    failed: &[&'a RecipientStatus],
) -> Vec<(Delivery, &'a RecipientStatus)> {
    if deliveries.len() == 1 && failed.len() == 1 && failed[0].recipient.is_none() {
        return deliveries.into_iter().map(|d| (d, failed[0])).collect();
    }
    deliveries
        .into_iter()
        .filter_map(|d| {
            failed.iter().find(|r| same_address(r.recipient.as_deref(), &d.rcpt)).map(|r| (d, *r))
        })
        .collect()
}
