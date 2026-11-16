//! DMARC aggregate report ingestion: XML, gzip and zip attachments, and over SMTP.

use std::time::Duration;

use base64::Engine;
use sigill_bounce::dmarc::{extract_reports, gunzip, parse_xml, unzip_first};
use sigill_bounce::{Listener, Processor, Settings};
use sigill_core::config::BounceConfig;
use sigill_mta::client::SmtpClient;
use sigill_store::testing::test_db;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn xml() -> String {
    std::fs::read_to_string(format!("{}/fixtures/dmarc_google.xml", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend([0u8; 4]); // CRC (not checked)
    out.extend((data.len() as u32).to_le_bytes());
    out
}

fn zip(name: &str, data: &[u8]) -> Vec<u8> {
    let body = miniz_oxide::deflate::compress_to_vec(data, 6);
    let mut out = b"PK\x03\x04".to_vec();
    out.extend(20u16.to_le_bytes()); // version
    out.extend(0u16.to_le_bytes()); // flags
    out.extend(8u16.to_le_bytes()); // deflate
    out.extend([0u8; 8]); // time, date, crc
    out.extend((body.len() as u32).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out.extend((name.len() as u16).to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(name.as_bytes());
    out.extend(body);
    out
}

fn email(content_type: &str, filename: &str, payload: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    format!(
        "From: noreply-dmarc-support@google.com\r\nTo: dmarc@bounces.example.com\r\n\
         Subject: Report domain: example.com Submitter: google.com\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n\
         This is an aggregate report from google.com.\r\n--b\r\nContent-Type: {content_type}; name=\"{filename}\"\r\n\
         Content-Disposition: attachment; filename=\"{filename}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n\
         {b64}\r\n--b--\r\n"
    )
    .into_bytes()
}

#[test]
fn parses_report_xml() {
    let r = parse_xml(&xml()).unwrap();
    assert_eq!(
        (r.org_name.as_str(), r.domain.as_str(), r.policy.as_str()),
        ("google.com", "example.com", "quarantine")
    );
    assert_eq!(r.report_id, "17035471826845392219");
    assert_eq!((r.date_begin, r.date_end), (1_763_078_400_000, 1_763_164_799_000));
    assert_eq!(r.records.len(), 2);
    assert!(r.records[0].passed());
    assert_eq!((r.records[1].source_ip.as_str(), r.records[1].count), ("198.51.100.66", 3));
    assert!(!r.records[1].passed());
    assert!(parse_xml("<feedback></feedback>").is_err());
    assert!(parse_xml("<feedback><report_metadata>").is_err());
}

#[test]
fn decompresses_and_extracts() {
    let x = xml();
    assert_eq!(gunzip(&gzip(x.as_bytes())).unwrap(), x.as_bytes());
    assert_eq!(unzip_first(&zip("r.xml", x.as_bytes())).unwrap(), x.as_bytes());
    assert!(gunzip(b"not gzip at all, no").is_none());
    for (ct, name, payload) in [
        ("application/gzip", "google.com!example.com!1763078400!1763164799.xml.gz", gzip(x.as_bytes())),
        ("application/zip", "google.com!example.com!1763078400!1763164799.zip", zip("r.xml", x.as_bytes())),
        ("text/xml", "report.xml", x.clone().into_bytes()),
        ("application/octet-stream", "report.xml.gz", gzip(x.as_bytes())),
    ] {
        let reports = extract_reports(&email(ct, name, &payload));
        assert_eq!(reports.len(), 1, "{ct} {name}");
        assert_eq!(reports[0].records.len(), 2);
    }
    assert!(extract_reports(&email("image/png", "x.png", b"\x89PNG")).is_empty());
}

#[tokio::test]
async fn ingests_over_smtp_once() {
    let db = test_db().await;
    let mut settings = Settings::new(&BounceConfig::default(), vec!["bounces.example.com".into()]);
    settings.timeout = Duration::from_secs(5);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let key = [1u8; 32];
    // Reports are kept only for our own sending domains (here a subdomain of the report's).
    let processor =
        Processor::new(db.store.clone(), key).with_dmarc_domains(["mail.example.com".to_string()]);
    tokio::spawn(Listener::new(settings, processor, key, None).run(listener, token.clone()));

    let raw = email("application/gzip", "r.xml.gz", &gzip(xml().as_bytes()));
    for _ in 0..2 {
        let mut c = SmtpClient::connect(addr, None, Duration::from_secs(5)).await.unwrap();
        c.ehlo("mx.google.test").await.unwrap();
        assert_eq!(c.mail_from("noreply-dmarc-support@google.com", raw.len()).await.unwrap().code, 250);
        assert_eq!(c.rcpt_to("dmarc@bounces.example.com").await.unwrap().code, 250);
        assert_eq!(c.data(&raw).await.unwrap().code, 250);
        c.quit().await;
    }
    let reports = db.recent_dmarc_reports(10).await.unwrap();
    assert_eq!(reports.len(), 1, "the same report twice is stored once");
    assert_eq!((reports[0].total_count, reports[0].fail_count), (45, 3));
    assert_eq!(db.dmarc_failures(10).await.unwrap().len(), 1);

    // A report about someone else's domain is accepted at SMTP level but not stored.
    let other = xml()
        .replace("<domain>example.com</domain>", "<domain>other.test</domain>")
        .replace("17035471826845392219", "999");
    let raw = email("application/gzip", "r.xml.gz", &gzip(other.as_bytes()));
    let mut c = SmtpClient::connect(addr, None, Duration::from_secs(5)).await.unwrap();
    c.ehlo("mx.evil.test").await.unwrap();
    c.mail_from("x@evil.test", raw.len()).await.unwrap();
    c.rcpt_to("dmarc@bounces.example.com").await.unwrap();
    assert_eq!(c.data(&raw).await.unwrap().code, 250);
    c.quit().await;
    assert_eq!(db.recent_dmarc_reports(10).await.unwrap().len(), 1);
    token.cancel();
}

#[test]
fn caps_attachments_and_records() {
    use sigill_bounce::dmarc::{MAX_ATTACHMENTS, MAX_RECORDS};
    // Many attachments in one email: only the first few are opened.
    let x = xml();
    let mut raw = String::from(
        "From: a@b.test\r\nTo: dmarc@bounces.example.com\r\nSubject: r\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n",
    );
    for i in 0..(MAX_ATTACHMENTS + 6) {
        let payload = x.replace("17035471826845392219", &format!("id{i}"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(gzip(payload.as_bytes()));
        raw.push_str(&format!(
            "--b\r\nContent-Type: application/gzip; name=\"r{i}.xml.gz\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n"
        ));
    }
    raw.push_str("--b--\r\n");
    assert_eq!(extract_reports(raw.as_bytes()).len(), MAX_ATTACHMENTS);

    // A report with too many records is refused whole.
    let record = "<record><row><source_ip>192.0.2.1</source_ip><count>1</count></row></record>";
    let big = format!(
        "<feedback><report_metadata><org_name>o</org_name><report_id>1</report_id></report_metadata>\
         <policy_published><domain>example.com</domain></policy_published>{}</feedback>",
        record.repeat(MAX_RECORDS + 1)
    );
    assert!(parse_xml(&big).is_err());
}
