//! DMARC aggregate reports (RFC 7489 appendix C): XML, usually gzip- or zip-compressed and
//! attached to an email sent to the `rua` address.

use mail_parser::MessageParser;
use quick_xml::Reader;
use quick_xml::events::Event;
use sigill_store::dmarc::DmarcRecord;

/// Largest decompressed report accepted.
const MAX_XML_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AggregateReport {
    pub org_name: String,
    pub report_id: String,
    pub domain: String,
    /// Unix milliseconds.
    pub date_begin: i64,
    pub date_end: i64,
    /// Published policy (`p=`).
    pub policy: String,
    pub records: Vec<DmarcRecord>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DmarcError {
    #[error("XML: {0}")]
    Xml(String),
    #[error("report is missing {0}")]
    Missing(&'static str),
}

/// Every aggregate report attached to (or forming the body of) an email.
pub fn extract_reports(raw: &[u8]) -> Vec<AggregateReport> {
    let Some(message) = MessageParser::new().parse(raw) else { return Vec::new() };
    let mut out = Vec::new();
    for part in message.parts() {
        if part.is_multipart() {
            continue;
        }
        let ct = part.content_type();
        let mime = ct
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("")).to_ascii_lowercase())
            .unwrap_or_default();
        let name = part.attachment_name().unwrap_or("").to_ascii_lowercase();
        let data = part.decoded();
        let xml = if mime.contains("zip") && !mime.contains("gzip") || name.ends_with(".zip") {
            unzip_first(&data)
        } else if mime.contains("gzip") || name.ends_with(".gz") {
            gunzip(&data)
        } else if mime.ends_with("/xml") || name.ends_with(".xml") {
            Some(data.into_owned())
        } else {
            None
        };
        if let Some(xml) = xml
            && let Ok(report) = parse_xml(&String::from_utf8_lossy(&xml))
        {
            out.push(report);
        }
    }
    out
}

/// Parse the XML of one aggregate report.
pub fn parse_xml(xml: &str) -> Result<AggregateReport, DmarcError> {
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut report = AggregateReport::default();
    let mut record: Option<DmarcRecord> = None;
    let mut text = String::new();
    loop {
        match reader.read_event().map_err(|e| DmarcError::Xml(e.to_string()))? {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                if name == "record" && path.last().map(String::as_str) == Some("feedback") {
                    record = Some(DmarcRecord {
                        source_ip: String::new(),
                        count: 0,
                        disposition: String::new(),
                        dkim_result: String::new(),
                        spf_result: String::new(),
                        header_from: String::new(),
                    });
                }
                path.push(name);
                text.clear();
            }
            Event::Text(t) => text.push_str(&t.decode().map_err(|e| DmarcError::Xml(e.to_string()))?),
            Event::CData(t) => text.push_str(&String::from_utf8_lossy(&t.into_inner())),
            Event::GeneralRef(r) => {
                let name = String::from_utf8_lossy(&r.into_inner()).into_owned();
                text.push_str(match name.as_str() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => "",
                });
            }
            Event::End(_) => {
                let joined = path.join("/");
                let value = text.trim();
                match joined.as_str() {
                    "feedback/report_metadata/org_name" => report.org_name = value.to_string(),
                    "feedback/report_metadata/report_id" => report.report_id = value.to_string(),
                    "feedback/report_metadata/date_range/begin" => {
                        report.date_begin = value.parse::<i64>().unwrap_or(0) * 1000
                    }
                    "feedback/report_metadata/date_range/end" => {
                        report.date_end = value.parse::<i64>().unwrap_or(0) * 1000
                    }
                    "feedback/policy_published/domain" => report.domain = value.to_ascii_lowercase(),
                    "feedback/policy_published/p" => report.policy = value.to_ascii_lowercase(),
                    _ => {}
                }
                if let Some(r) = record.as_mut() {
                    match joined.as_str() {
                        "feedback/record/row/source_ip" => r.source_ip = value.to_string(),
                        "feedback/record/row/count" => r.count = value.parse().unwrap_or(0),
                        "feedback/record/row/policy_evaluated/disposition" => {
                            r.disposition = value.to_ascii_lowercase()
                        }
                        "feedback/record/row/policy_evaluated/dkim" => {
                            r.dkim_result = value.to_ascii_lowercase()
                        }
                        "feedback/record/row/policy_evaluated/spf" => {
                            r.spf_result = value.to_ascii_lowercase()
                        }
                        "feedback/record/identifiers/header_from" => {
                            r.header_from = value.to_ascii_lowercase()
                        }
                        "feedback/record" => report.records.extend(record.take()),
                        _ => {}
                    }
                }
                path.pop();
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if report.org_name.is_empty() {
        return Err(DmarcError::Missing("org_name"));
    }
    if report.report_id.is_empty() {
        return Err(DmarcError::Missing("report_id"));
    }
    if report.domain.is_empty() {
        return Err(DmarcError::Missing("policy_published/domain"));
    }
    Ok(report)
}

fn inflate(raw_deflate: &[u8]) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(raw_deflate, MAX_XML_BYTES).ok()
}

/// Decompress a gzip member (RFC 1952). The CRC is not checked; the XML parser rejects
/// damaged content.
pub fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return None;
    }
    let flags = data[3];
    let mut pos = 10;
    if flags & 0x04 != 0 {
        let xlen = u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
        pos += 2 + xlen;
    }
    for bit in [0x08, 0x10] {
        if flags & bit != 0 {
            pos += data.get(pos..)?.iter().position(|b| *b == 0)? + 1;
        }
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    inflate(data.get(pos..data.len().checked_sub(8)?)?)
}

/// The first file in a ZIP archive (stored or deflated), read from its local header.
pub fn unzip_first(data: &[u8]) -> Option<Vec<u8>> {
    let u16_at = |p: usize| Some(u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize);
    let u32_at = |p: usize| {
        Some(u32::from_le_bytes([*data.get(p)?, *data.get(p + 1)?, *data.get(p + 2)?, *data.get(p + 3)?])
            as usize)
    };
    if data.get(..4)? != b"PK\x03\x04" {
        return None;
    }
    let flags = u16_at(6)?;
    let method = u16_at(8)?;
    let mut size = u32_at(18)?;
    let start = 30 + u16_at(26)? + u16_at(28)?;
    if flags & 0x08 != 0 || size == 0 {
        // Sizes are in a data descriptor after the data; use the central directory instead.
        let cd = data.windows(4).rposition(|w| w == b"PK\x01\x02")?;
        size = u32_at(cd + 20)?;
    }
    let body = data.get(start..start.checked_add(size)?)?;
    match method {
        0 => Some(body.to_vec()),
        8 => inflate(body),
        _ => None,
    }
}
