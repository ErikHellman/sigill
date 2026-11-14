//! `sigill dns-check`: verify the DNS records deliverability depends on (PTR, SPF, DKIM,
//! DMARC, MX) and report pass, warn or fail for each.

use std::net::Ipv4Addr;

use sigill_core::{Config, Stream};

use crate::dns::{DnsError, MxTarget, Resolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    /// `ptr`, `spf`, `dkim`, `dmarc` or `mx`.
    pub kind: &'static str,
    /// The DNS name (or IP) checked.
    pub name: String,
    pub detail: String,
}

impl std::fmt::Display for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}  {:<5}  {}: {}", self.status, self.kind, self.name, self.detail)
    }
}

/// Expected DKIM records for one sending domain: `(selector, TXT value)`.
pub struct ExpectedDkim {
    pub domain: String,
    pub records: Vec<(String, String)>,
}

fn check(status: Status, kind: &'static str, name: impl Into<String>, detail: impl Into<String>) -> Check {
    Check { status, kind, name: name.into(), detail: detail.into() }
}

async fn txt(resolver: &dyn Resolver, name: &str) -> Result<Vec<String>, DnsError> {
    match resolver.txt(name).await {
        Err(DnsError::NxDomain) => Ok(Vec::new()),
        other => other,
    }
}

/// The `p=` tag of a DKIM record, without whitespace.
fn dkim_key(record: &str) -> Option<String> {
    record
        .split(';')
        .map(str::trim)
        .find_map(|tag| tag.strip_prefix("p="))
        .map(|p| p.chars().filter(|c| !c.is_whitespace()).collect())
}

/// Organizational domain, approximated as the last two labels (no public suffix list).
fn org_domain(domain: &str) -> String {
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

pub async fn run(config: &Config, dkim: &[ExpectedDkim], resolver: &dyn Resolver) -> Vec<Check> {
    let mut out = Vec::new();
    let all_ips: Vec<(Stream, Ipv4Addr)> =
        Stream::ALL.iter().flat_map(|s| config.streams.get(*s).ips.iter().map(move |ip| (*s, *ip))).collect();

    // PTR and forward-confirmed reverse DNS for every source IP.
    for (stream, ip) in &all_ips {
        let helo = config.streams.get(*stream).helo_hostname.trim_end_matches('.').to_ascii_lowercase();
        out.push(match resolver.ptr(*ip).await {
            Ok(names) => {
                let names: Vec<String> =
                    names.iter().map(|n| n.trim_end_matches('.').to_ascii_lowercase()).collect();
                if !names.contains(&helo) {
                    check(
                        Status::Fail,
                        "ptr",
                        ip.to_string(),
                        format!("PTR is {names:?}, EHLO name is {helo}"),
                    )
                } else if resolver.ipv4(&helo).await.map(|a| a.contains(ip)).unwrap_or(false) {
                    check(Status::Pass, "ptr", ip.to_string(), format!("{helo} (forward-confirmed)"))
                } else {
                    check(
                        Status::Fail,
                        "ptr",
                        ip.to_string(),
                        format!("{helo} does not resolve back to {ip}"),
                    )
                }
            }
            Err(e) => check(Status::Fail, "ptr", ip.to_string(), format!("no PTR record ({e})")),
        });
    }
    if all_ips.is_empty() {
        out.push(check(Status::Warn, "ptr", "-", "no source IPs configured; PTR and SPF IPs not checked"));
    }

    for d in &config.domains {
        let domain = d.name.to_ascii_lowercase();
        let rp = d.return_path_domain.to_ascii_lowercase();
        let ips: Vec<Ipv4Addr> = config.streams.get(d.stream).ips.clone();

        // SPF on the envelope (return-path) domain, which is what SPF checks.
        out.push(match txt(resolver, &rp).await {
            Ok(records) => {
                let spf: Vec<&String> =
                    records.iter().filter(|r| r.to_ascii_lowercase().starts_with("v=spf1")).collect();
                match spf.as_slice() {
                    [] => check(Status::Fail, "spf", &rp, "no SPF record"),
                    [one] => {
                        let lower = one.to_ascii_lowercase();
                        let missing: Vec<String> = ips
                            .iter()
                            .filter(|ip| {
                                !lower
                                    .split_whitespace()
                                    .any(|t| t == format!("ip4:{ip}") || t == format!("+ip4:{ip}"))
                            })
                            .map(ToString::to_string)
                            .collect();
                        if !missing.is_empty() {
                            check(
                                Status::Fail,
                                "spf",
                                &rp,
                                format!("does not list ip4:{} ({one})", missing.join(", ip4:")),
                            )
                        } else if lower.ends_with("+all") || lower.ends_with(" ?all") {
                            check(Status::Warn, "spf", &rp, format!("permissive policy: {one}"))
                        } else {
                            check(Status::Pass, "spf", &rp, one.to_string())
                        }
                    }
                    _ => check(Status::Fail, "spf", &rp, "more than one SPF record (permerror)"),
                }
            }
            Err(e) => check(Status::Fail, "spf", &rp, format!("lookup failed ({e})")),
        });

        // DKIM: both selectors publish the key we sign with.
        for (selector, expected) in dkim.iter().filter(|e| e.domain == domain).flat_map(|e| e.records.iter())
        {
            let name = format!("{selector}._domainkey.{domain}");
            let want = dkim_key(expected);
            out.push(match txt(resolver, &name).await {
                Ok(records) if records.is_empty() => {
                    check(Status::Fail, "dkim", &name, format!("missing; publish: {expected}"))
                }
                Ok(records) => {
                    if records.iter().any(|r| dkim_key(r) == want) {
                        check(Status::Pass, "dkim", &name, "matches the signing key")
                    } else {
                        check(
                            Status::Fail,
                            "dkim",
                            &name,
                            format!("published key differs; publish: {expected}"),
                        )
                    }
                }
                Err(e) => check(Status::Fail, "dkim", &name, format!("lookup failed ({e})")),
            });
        }

        // DMARC on the domain, else its organizational domain.
        let mut found = None;
        for name in [format!("_dmarc.{domain}"), format!("_dmarc.{}", org_domain(&domain))] {
            if let Ok(records) = txt(resolver, &name).await
                && let Some(r) = records.into_iter().find(|r| r.to_ascii_lowercase().starts_with("v=dmarc1"))
            {
                found = Some((name, r));
                break;
            }
            if org_domain(&domain) == domain {
                break;
            }
        }
        out.push(match found {
            None => check(Status::Fail, "dmarc", format!("_dmarc.{domain}"), "no DMARC record"),
            Some((name, r)) => {
                let lower = r.to_ascii_lowercase().replace(' ', "");
                if lower.contains("p=none") {
                    check(Status::Warn, "dmarc", name, format!("policy is none: {r}"))
                } else if !lower.contains("rua=") {
                    check(Status::Warn, "dmarc", name, format!("no rua= for aggregate reports: {r}"))
                } else {
                    check(Status::Pass, "dmarc", name, r)
                }
            }
        });

        // MX for the bounce domain, so DSNs and reports reach the listener.
        let bounce_host = config.bounce.hostname.trim_end_matches('.').to_ascii_lowercase();
        out.push(match resolver.mx(&rp).await {
            Ok(MxTarget::Hosts(hosts)) => {
                let hosts: Vec<String> =
                    hosts.iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase()).collect();
                if hosts.contains(&bounce_host) {
                    check(Status::Pass, "mx", &rp, format!("points at {bounce_host}"))
                } else {
                    check(
                        Status::Warn,
                        "mx",
                        &rp,
                        format!("MX is {hosts:?}, bounce listener is {bounce_host}"),
                    )
                }
            }
            Ok(MxTarget::NullMx) => check(Status::Fail, "mx", &rp, "null MX: bounces cannot be received"),
            Err(e) => check(Status::Fail, "mx", &rp, format!("no MX ({e})")),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticResolver;

    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    fn config() -> Config {
        let mut c = Config {
            domains: vec![sigill_core::config::DomainConfig {
                name: "mail.example.com".into(),
                stream: Stream::Transactional,
                dkim_selector: "t1".into(),
                dkim_key_dir: "/nonexistent".into(),
                return_path_domain: "bounces.example.com".into(),
            }],
            ..Default::default()
        };
        c.streams.transactional.ips = vec![IP];
        c.streams.transactional.helo_hostname = "mta1.example.com".into();
        c.bounce.hostname = "mx.example.com".into();
        c
    }

    fn dkim() -> Vec<ExpectedDkim> {
        vec![ExpectedDkim {
            domain: "mail.example.com".into(),
            records: vec![
                ("t1r".into(), "v=DKIM1; k=rsa; p=RSAKEY".into()),
                ("t1e".into(), "v=DKIM1; k=ed25519; p=EDKEY".into()),
            ],
        }]
    }

    fn statuses(checks: &[Check]) -> Vec<(&'static str, Status)> {
        checks.iter().map(|c| (c.kind, c.status)).collect()
    }

    #[tokio::test]
    async fn all_good() {
        let r = StaticResolver::default()
            .with_ptr(IP, &["mta1.example.com."])
            .with_a("mta1.example.com", &[IP])
            .with_txt("bounces.example.com", &["v=spf1 ip4:203.0.113.10 -all"])
            .with_txt("t1r._domainkey.mail.example.com", &["v=DKIM1; k=rsa; p=RSA KEY"])
            .with_txt("t1e._domainkey.mail.example.com", &["v=DKIM1; k=ed25519; p=EDKEY"])
            .with_txt("_dmarc.example.com", &["v=DMARC1; p=quarantine; rua=mailto:dmarc@bounces.example.com"])
            .with_mx("bounces.example.com", Ok(MxTarget::Hosts(vec!["mx.example.com.".into()])));
        let checks = run(&config(), &dkim(), &r).await;
        assert!(checks.iter().all(|c| c.status == Status::Pass), "{checks:#?}");
        assert_eq!(checks.len(), 6);
    }

    #[tokio::test]
    async fn reports_problems() {
        let r = StaticResolver::default()
            .with_ptr(IP, &["static.isp.test"])
            .with_txt("bounces.example.com", &["v=spf1 include:_spf.other.test ~all"])
            .with_txt("t1r._domainkey.mail.example.com", &["v=DKIM1; k=rsa; p=OLD"])
            .with_txt("_dmarc.mail.example.com", &["v=DMARC1; p=none"])
            .with_mx("bounces.example.com", Ok(MxTarget::NullMx));
        let checks = run(&config(), &dkim(), &r).await;
        assert_eq!(
            statuses(&checks),
            vec![
                ("ptr", Status::Fail),
                ("spf", Status::Fail),
                ("dkim", Status::Fail),
                ("dkim", Status::Fail),
                ("dmarc", Status::Warn),
                ("mx", Status::Fail),
            ]
        );
        assert!(checks[3].detail.contains("missing; publish: v=DKIM1; k=ed25519"));
    }
}
