//! DMARC aggregate reports.

use sigill_core::{new_id, now_ms};

use crate::{Result, Store};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DmarcReport {
    pub id: String,
    pub org_name: String,
    pub report_id: String,
    pub domain: String,
    pub date_begin: i64,
    pub date_end: i64,
    pub policy: String,
    pub total_count: i64,
    pub fail_count: i64,
    pub received_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: i64,
    pub disposition: String,
    pub dkim_result: String,
    pub spf_result: String,
    pub header_from: String,
}

impl DmarcRecord {
    /// DMARC passes when either aligned DKIM or aligned SPF passes.
    pub fn passed(&self) -> bool {
        self.dkim_result == "pass" || self.spf_result == "pass"
    }
}

pub struct NewDmarcReport<'a> {
    pub org_name: &'a str,
    pub report_id: &'a str,
    pub domain: &'a str,
    pub date_begin: i64,
    pub date_end: i64,
    pub policy: &'a str,
    pub records: &'a [DmarcRecord],
}

impl Store {
    /// Store a report. Returns false if this report was already stored.
    pub async fn insert_dmarc_report(&self, r: &NewDmarcReport<'_>) -> Result<bool> {
        let id = new_id();
        let now = now_ms();
        let total: i64 = r.records.iter().map(|x| x.count).sum();
        let fail: i64 = r.records.iter().filter(|x| !x.passed()).map(|x| x.count).sum();
        let mut tx = self.write.begin().await?;
        let res = sqlx::query!(
            "INSERT INTO dmarc_reports (id, org_name, report_id, domain, date_begin, date_end, policy,
                                        total_count, fail_count, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (org_name, report_id) DO NOTHING",
            id,
            r.org_name,
            r.report_id,
            r.domain,
            r.date_begin,
            r.date_end,
            r.policy,
            total,
            fail,
            now
        )
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(false);
        }
        for rec in r.records {
            sqlx::query!(
                "INSERT INTO dmarc_records (report_id, source_ip, count, disposition, dkim_result, spf_result, header_from)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                id,
                rec.source_ip,
                rec.count,
                rec.disposition,
                rec.dkim_result,
                rec.spf_result,
                rec.header_from
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn recent_dmarc_reports(&self, limit: i64) -> Result<Vec<DmarcReport>> {
        Ok(sqlx::query_as!(
            DmarcReport,
            "SELECT id, org_name, report_id, domain, date_begin, date_end, policy, total_count, fail_count, received_at
             FROM dmarc_reports ORDER BY date_end DESC LIMIT ?",
            limit
        )
        .fetch_all(&self.read)
        .await?)
    }

    /// Failing records across recent reports.
    pub async fn dmarc_failures(&self, limit: i64) -> Result<Vec<(DmarcReport, DmarcRecord)>> {
        let rows = sqlx::query!(
            "SELECT r.id, r.org_name, r.report_id, r.domain, r.date_begin, r.date_end, r.policy, r.total_count,
                    r.fail_count, r.received_at, x.source_ip, x.count, x.disposition, x.dkim_result, x.spf_result,
                    x.header_from
             FROM dmarc_records x JOIN dmarc_reports r ON r.id = x.report_id
             WHERE x.dkim_result != 'pass' AND x.spf_result != 'pass'
             ORDER BY r.date_end DESC LIMIT ?",
            limit
        )
        .fetch_all(&self.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    DmarcReport {
                        id: r.id,
                        org_name: r.org_name,
                        report_id: r.report_id,
                        domain: r.domain,
                        date_begin: r.date_begin,
                        date_end: r.date_end,
                        policy: r.policy,
                        total_count: r.total_count,
                        fail_count: r.fail_count,
                        received_at: r.received_at,
                    },
                    DmarcRecord {
                        source_ip: r.source_ip,
                        count: r.count,
                        disposition: r.disposition,
                        dkim_result: r.dkim_result,
                        spf_result: r.spf_result,
                        header_from: r.header_from,
                    },
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_db;

    #[tokio::test]
    async fn stores_once_and_counts_failures() {
        let db = test_db().await;
        let recs = vec![
            DmarcRecord {
                source_ip: "192.0.2.1".into(),
                count: 10,
                disposition: "none".into(),
                dkim_result: "pass".into(),
                spf_result: "pass".into(),
                header_from: "example.com".into(),
            },
            DmarcRecord {
                source_ip: "198.51.100.7".into(),
                count: 3,
                disposition: "none".into(),
                dkim_result: "fail".into(),
                spf_result: "fail".into(),
                header_from: "example.com".into(),
            },
        ];
        let r = NewDmarcReport {
            org_name: "google.com",
            report_id: "1",
            domain: "example.com",
            date_begin: 1,
            date_end: 2,
            policy: "none",
            records: &recs,
        };
        assert!(db.insert_dmarc_report(&r).await.unwrap());
        assert!(!db.insert_dmarc_report(&r).await.unwrap());
        let reports = db.recent_dmarc_reports(10).await.unwrap();
        assert_eq!((reports[0].total_count, reports[0].fail_count), (13, 3));
        let f = db.dmarc_failures(10).await.unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1.source_ip, "198.51.100.7");
    }
}
