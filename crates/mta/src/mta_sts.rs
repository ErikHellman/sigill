//! MTA-STS (RFC 8461): fetch, cache and apply recipient domains' TLS policies.
//!
//! In `enforce` mode only MX hosts matching the policy are used, and only over STARTTLS
//! with a valid certificate; otherwise the delivery is deferred rather than sent in plain
//! text. `testing` and `none` policies do not change delivery.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns::{BoxFut, Resolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    pub mx: Vec<String>,
    pub max_age: u64,
}

impl Policy {
    /// Parse the policy file body.
    pub fn parse(body: &str) -> Option<Self> {
        let mut version = None;
        let mut mode = None;
        let mut mx = Vec::new();
        let mut max_age = None;
        for line in body.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let v = v.trim();
            match k.trim() {
                "version" => version = Some(v.to_string()),
                "mode" => {
                    mode = match v {
                        "enforce" => Some(Mode::Enforce),
                        "testing" => Some(Mode::Testing),
                        "none" => Some(Mode::None),
                        _ => None,
                    }
                }
                "mx" => mx.push(v.to_ascii_lowercase()),
                "max_age" => max_age = v.parse().ok(),
                _ => {}
            }
        }
        if version.as_deref() != Some("STSv1") {
            return None;
        }
        let mode = mode?;
        if mode != Mode::None && mx.is_empty() {
            return None;
        }
        Some(Self { mode, mx, max_age: max_age? })
    }

    /// Does an MX host name match one of the policy's patterns?
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.mx.iter().any(|p| match p.strip_prefix("*.") {
            // A wildcard matches exactly one leftmost label.
            Some(suffix) => {
                host.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
            }
            None => host == *p,
        })
    }
}

/// Parse the `_mta-sts` TXT record and return its `id`.
pub fn parse_txt(records: &[String]) -> Option<String> {
    let sts: Vec<&String> = records.iter().filter(|r| r.trim_start().starts_with("v=STSv1")).collect();
    if sts.len() != 1 {
        return None;
    }
    sts[0].split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == "id").then(|| v.trim().to_string())
    })
}

/// Fetches policy files over HTTPS.
pub trait PolicyFetcher: Send + Sync {
    fn fetch(&self, domain: &str) -> BoxFut<'_, Result<String, String>>;
}

pub struct HttpsFetcher(reqwest::Client);

impl HttpsFetcher {
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sigill/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self(client))
    }
}

impl PolicyFetcher for HttpsFetcher {
    fn fetch(&self, domain: &str) -> BoxFut<'_, Result<String, String>> {
        let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
        Box::pin(async move {
            let res = self.0.get(&url).send().await.map_err(|e| e.to_string())?;
            if !res.status().is_success() {
                return Err(format!("HTTP {}", res.status()));
            }
            let bytes = res.bytes().await.map_err(|e| e.to_string())?;
            if bytes.len() > 64 * 1024 {
                return Err("policy too large".into());
            }
            String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
        })
    }
}

struct Cached {
    id: String,
    policy: Policy,
    expires: Instant,
}

/// Policy lookups with an in-memory cache keyed by domain and policy id.
pub struct MtaSts {
    resolver: Arc<dyn Resolver>,
    fetcher: Arc<dyn PolicyFetcher>,
    cache: Mutex<HashMap<String, Cached>>,
}

impl MtaSts {
    pub fn new(resolver: Arc<dyn Resolver>, fetcher: Arc<dyn PolicyFetcher>) -> Self {
        Self { resolver, fetcher, cache: Mutex::new(HashMap::new()) }
    }

    /// The domain's current policy, if it has one. Fetch failures fall back to a cached
    /// policy (as RFC 8461 asks) or to no policy.
    pub async fn policy(&self, domain: &str) -> Option<Policy> {
        let txt = self.resolver.txt(&format!("_mta-sts.{domain}")).await.ok();
        let id = txt.as_deref().and_then(parse_txt);
        let now = Instant::now();
        {
            let cache = self.cache.lock().expect("mta-sts cache");
            if let Some(c) = cache.get(domain)
                && c.expires > now
                && (id.is_none() || id.as_deref() == Some(c.id.as_str()))
            {
                return Some(c.policy.clone());
            }
        }
        let id = id?;
        match self.fetcher.fetch(domain).await.ok().as_deref().and_then(Policy::parse) {
            Some(policy) => {
                let ttl = Duration::from_secs(policy.max_age.min(31_557_600));
                self.cache
                    .lock()
                    .expect("mta-sts cache")
                    .insert(domain.to_string(), Cached { id, policy: policy.clone(), expires: now + ttl });
                Some(policy)
            }
            None => {
                tracing::warn!(rcpt_domain = %domain, "MTA-STS policy fetch failed");
                self.cache.lock().expect("mta-sts cache").get(domain).map(|c| c.policy.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticResolver;

    const BODY: &str =
        "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.net\nmax_age: 86400\n";

    #[test]
    fn parses_and_matches() {
        let p = Policy::parse(BODY).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert!(p.allows("MX1.example.com."));
        assert!(p.allows("a.mail.example.net"));
        assert!(!p.allows("a.b.mail.example.net"));
        assert!(!p.allows("mail.example.net"));
        assert!(!p.allows("evil.com"));
        assert!(Policy::parse("version: STSv1\nmode: enforce\nmax_age: 1\n").is_none());
        assert!(Policy::parse("mode: enforce\nmx: a\nmax_age: 1\n").is_none());
        assert_eq!(parse_txt(&["v=STSv1; id=2024a;".into()]), Some("2024a".into()));
        assert_eq!(parse_txt(&["v=spf1 -all".into()]), None);
    }

    struct Fixed(Mutex<u32>);
    impl PolicyFetcher for Fixed {
        fn fetch(&self, _domain: &str) -> BoxFut<'_, Result<String, String>> {
            *self.0.lock().unwrap() += 1;
            Box::pin(async { Ok(BODY.to_string()) })
        }
    }

    #[tokio::test]
    async fn fetches_once_and_caches() {
        let resolver =
            Arc::new(StaticResolver::default().with_txt("_mta-sts.example.com", &["v=STSv1; id=1"]));
        let fetcher = Arc::new(Fixed(Mutex::new(0)));
        let sts = MtaSts::new(resolver, fetcher.clone());
        assert_eq!(sts.policy("example.com").await.unwrap().mode, Mode::Enforce);
        assert!(sts.policy("example.com").await.is_some());
        assert_eq!(*fetcher.0.lock().unwrap(), 1);
        assert!(sts.policy("other.com").await.is_none(), "no TXT record means no policy");
    }
}
