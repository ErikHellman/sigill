//! DNS lookups behind a trait, so tests can use a fixed table instead of the network.

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Mutex;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// The name does not exist (NXDOMAIN): a permanent failure.
    #[error("domain does not exist")]
    NxDomain,
    /// Lookup failed for a temporary reason (timeout, SERVFAIL, network).
    #[error("DNS lookup failed: {0}")]
    Temporary(String),
}

/// Where to deliver mail for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxTarget {
    /// MX hosts sorted by preference (lowest first).
    Hosts(Vec<String>),
    /// The domain publishes a null MX (`MX 0 .`, RFC 7505): it accepts no mail.
    NullMx,
}

pub trait Resolver: Send + Sync {
    /// MX hosts for a domain; falls back to the domain itself when it has no MX records.
    fn mx(&self, domain: &str) -> BoxFut<'_, Result<MxTarget, DnsError>>;
    fn ipv4(&self, host: &str) -> BoxFut<'_, Result<Vec<Ipv4Addr>, DnsError>>;
    fn txt(&self, name: &str) -> BoxFut<'_, Result<Vec<String>, DnsError>>;
    fn ptr(&self, ip: Ipv4Addr) -> BoxFut<'_, Result<Vec<String>, DnsError>>;
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') { name.to_string() } else { format!("{name}.") }
}

fn map_err(e: hickory_resolver::net::NetError) -> DnsError {
    if e.is_nx_domain() { DnsError::NxDomain } else { DnsError::Temporary(e.to_string()) }
}

/// The system resolver (`/etc/resolv.conf`).
pub struct HickoryResolver(TokioResolver);

impl HickoryResolver {
    pub fn from_system() -> Result<Self, DnsError> {
        let r = TokioResolver::builder_tokio()
            .map_err(|e| DnsError::Temporary(e.to_string()))?
            .build()
            .map_err(|e| DnsError::Temporary(e.to_string()))?;
        Ok(Self(r))
    }
}

impl Resolver for HickoryResolver {
    fn mx(&self, domain: &str) -> BoxFut<'_, Result<MxTarget, DnsError>> {
        let name = fqdn(domain);
        let domain = domain.to_string();
        Box::pin(async move {
            match self.0.mx_lookup(name.as_str()).await {
                Ok(lookup) => {
                    let mut mx: Vec<(u16, String)> = lookup
                        .answers()
                        .iter()
                        .filter_map(|r| match &r.data {
                            RData::MX(m) => Some((m.preference, m.exchange.to_ascii())),
                            _ => None,
                        })
                        .collect();
                    if mx.len() == 1 && (mx[0].1 == "." || mx[0].1.is_empty()) {
                        return Ok(MxTarget::NullMx);
                    }
                    mx.retain(|(_, h)| h != ".");
                    mx.sort();
                    if mx.is_empty() {
                        return Ok(MxTarget::Hosts(vec![domain]));
                    }
                    Ok(MxTarget::Hosts(
                        mx.into_iter().map(|(_, h)| h.trim_end_matches('.').to_string()).collect(),
                    ))
                }
                // No MX records but the name exists: use its A records (RFC 5321 5.1).
                Err(e) if e.is_no_records_found() && !e.is_nx_domain() => Ok(MxTarget::Hosts(vec![domain])),
                Err(e) => Err(map_err(e)),
            }
        })
    }

    fn ipv4(&self, host: &str) -> BoxFut<'_, Result<Vec<Ipv4Addr>, DnsError>> {
        let name = fqdn(host);
        Box::pin(async move {
            let lookup = self.0.ipv4_lookup(name.as_str()).await.map_err(map_err)?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect())
        })
    }

    fn txt(&self, name: &str) -> BoxFut<'_, Result<Vec<String>, DnsError>> {
        let name = fqdn(name);
        Box::pin(async move {
            match self.0.txt_lookup(name.as_str()).await {
                Ok(lookup) => Ok(lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::TXT(t) => {
                            Some(t.txt_data.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect())
                        }
                        _ => None,
                    })
                    .collect()),
                Err(e) if e.is_no_records_found() && !e.is_nx_domain() => Ok(Vec::new()),
                Err(e) => Err(map_err(e)),
            }
        })
    }

    fn ptr(&self, ip: Ipv4Addr) -> BoxFut<'_, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            let o = ip.octets();
            let name = format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]);
            let lookup = self.0.reverse_lookup(name.as_str()).await.map_err(map_err)?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::PTR(p) => Some(p.0.to_ascii().trim_end_matches('.').to_string()),
                    _ => None,
                })
                .collect())
        })
    }
}

/// A fixed table of records, for tests and `dns-check` fixtures.
#[derive(Default)]
pub struct StaticResolver {
    pub mx: Mutex<HashMap<String, Result<MxTarget, DnsError>>>,
    pub a: Mutex<HashMap<String, Vec<Ipv4Addr>>>,
    pub txt: Mutex<HashMap<String, Vec<String>>>,
    pub ptr: Mutex<HashMap<Ipv4Addr, Vec<String>>>,
}

impl StaticResolver {
    pub fn with_mx(self, domain: &str, target: Result<MxTarget, DnsError>) -> Self {
        self.mx.lock().unwrap().insert(domain.to_string(), target);
        self
    }
    pub fn with_a(self, host: &str, ips: &[Ipv4Addr]) -> Self {
        self.a.lock().unwrap().insert(host.to_string(), ips.to_vec());
        self
    }
    pub fn with_txt(self, name: &str, values: &[&str]) -> Self {
        self.txt.lock().unwrap().insert(name.to_string(), values.iter().map(|s| s.to_string()).collect());
        self
    }
    pub fn with_ptr(self, ip: Ipv4Addr, names: &[&str]) -> Self {
        self.ptr.lock().unwrap().insert(ip, names.iter().map(|s| s.to_string()).collect());
        self
    }
}

impl Resolver for StaticResolver {
    fn mx(&self, domain: &str) -> BoxFut<'_, Result<MxTarget, DnsError>> {
        let r = self.mx.lock().unwrap().get(domain).cloned().unwrap_or(Err(DnsError::NxDomain));
        Box::pin(async move { r })
    }
    fn ipv4(&self, host: &str) -> BoxFut<'_, Result<Vec<Ipv4Addr>, DnsError>> {
        let r = self.a.lock().unwrap().get(host).cloned().ok_or(DnsError::NxDomain);
        Box::pin(async move { r })
    }
    fn txt(&self, name: &str) -> BoxFut<'_, Result<Vec<String>, DnsError>> {
        let r = self.txt.lock().unwrap().get(name.trim_end_matches('.')).cloned().unwrap_or_default();
        Box::pin(async move { Ok(r) })
    }
    fn ptr(&self, ip: Ipv4Addr) -> BoxFut<'_, Result<Vec<String>, DnsError>> {
        let r = self.ptr.lock().unwrap().get(&ip).cloned().ok_or(DnsError::NxDomain);
        Box::pin(async move { r })
    }
}
