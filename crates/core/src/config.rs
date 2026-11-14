//! Service configuration: a TOML file plus `SIGILL_` environment overrides.
//!
//! Nested keys use a double underscore in env vars, for example
//! `SIGILL_SERVER__LISTEN=0.0.0.0:8080`. Secrets are never read from the TOML file
//! itself: they come from env vars or from files named in the config (see [`Secrets`]).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

use crate::Stream;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub secrets: SecretsConfig,
    pub domains: Vec<DomainConfig>,
    pub streams: StreamsConfig,
    pub delivery: DeliveryConfig,
    pub bounce: BounceConfig,
    pub broadcast: BroadcastConfig,
    pub webhooks: WebhookConfig,
    pub retention: RetentionConfig,
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address the HTTP API listens on. It sits behind a reverse proxy for TLS.
    pub listen: SocketAddr,
    /// Public base URL of the API, used in unsubscribe links.
    pub public_url: String,
    /// Requests per second allowed per app (burst is twice this).
    pub rate_limit_per_sec: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_url: "http://localhost:8080".into(),
            rate_limit_per_sec: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    /// Connections in the read pool.
    pub read_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { path: "sigill.db".into(), read_connections: 4 }
    }
}

/// Where secrets come from. Each value is read from the env var first, then from the file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    /// File holding the master key (at least 32 bytes of text). Env: `SIGILL_MASTER_KEY`.
    pub master_key_file: Option<PathBuf>,
    /// File holding the admin UI password. Env: `SIGILL_ADMIN_PASSWORD`.
    pub admin_password_file: Option<PathBuf>,
}

/// A domain we send from, with its DKIM keys on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// The `From` domain, for example `mail.example.com`.
    pub name: String,
    /// Which stream this domain is used for.
    pub stream: Stream,
    /// DKIM selector prefix; the RSA key uses `<selector>r` and the Ed25519 key `<selector>e`.
    pub dkim_selector: String,
    /// Directory holding `<selector>r.pem` (RSA-2048) and `<selector>e.pem` (Ed25519).
    pub dkim_key_dir: PathBuf,
    /// Domain used in the VERP return path, for example `bounces.example.com`.
    pub return_path_domain: String,
}

impl DomainConfig {
    pub fn rsa_selector(&self) -> String {
        format!("{}r", self.dkim_selector)
    }
    pub fn ed25519_selector(&self) -> String {
        format!("{}e", self.dkim_selector)
    }
    pub fn rsa_key_path(&self) -> PathBuf {
        self.dkim_key_dir.join(format!("{}.pem", self.rsa_selector()))
    }
    pub fn ed25519_key_path(&self) -> PathBuf {
        self.dkim_key_dir.join(format!("{}.pem", self.ed25519_selector()))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamsConfig {
    pub transactional: StreamConfig,
    pub broadcast: StreamConfig,
}

impl StreamsConfig {
    pub fn get(&self, stream: Stream) -> &StreamConfig {
        match stream {
            Stream::Transactional => &self.transactional,
            Stream::Broadcast => &self.broadcast,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamConfig {
    /// Default `From` address when the API call gives none.
    pub default_from: Option<String>,
    /// Source IPv4 addresses for outbound connections. Empty means the OS picks.
    pub ips: Vec<Ipv4Addr>,
    /// EHLO name; must match the PTR record of the source IPs.
    pub helo_hostname: String,
    /// Concurrent delivery workers for this stream.
    pub workers: usize,
    /// Queue priority: lower runs first.
    pub priority: i64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            default_from: None,
            ips: Vec::new(),
            helo_hostname: "localhost".into(),
            workers: 8,
            priority: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryMode {
    /// Look up MX records and deliver directly (production).
    Mx,
    /// Send everything to one host, for example Mailpit (development only).
    Smarthost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryConfig {
    pub mode: DeliveryMode,
    /// `host:port` of the smarthost when `mode = "smarthost"`.
    pub smarthost: String,
    /// Port used for MX delivery. Always 25 in production; tests point it at a fake server.
    pub mx_port: u16,
    /// Seconds between dispatcher polls when idle.
    pub poll_interval_secs: u64,
    /// Rows claimed per dispatcher round.
    pub batch_size: i64,
    /// SMTP command timeout in seconds.
    pub smtp_timeout_secs: u64,
    /// Give up after this many hours of retries.
    pub max_retry_hours: i64,
    /// Max idle seconds for pooled SMTP connections.
    pub pool_idle_secs: u64,
    /// Max messages sent over one pooled connection.
    pub pool_max_messages: u32,
    /// Fetch and enforce MTA-STS policies.
    pub mta_sts: bool,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Mx,
            smarthost: "127.0.0.1:1025".into(),
            mx_port: 25,
            poll_interval_secs: 1,
            batch_size: 100,
            smtp_timeout_secs: 60,
            max_retry_hours: 72,
            pool_idle_secs: 30,
            pool_max_messages: 100,
            mta_sts: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BounceConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Name in the SMTP greeting.
    pub hostname: String,
    pub max_message_bytes: usize,
    pub max_connections: usize,
    /// Optional TLS certificate and key (PEM) to offer STARTTLS.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Local part that accepts complaint (ARF) reports, for example `fbl@bounces.example.com`.
    pub complaint_local_part: String,
    /// Local part that accepts DMARC aggregate reports.
    pub dmarc_local_part: String,
}

impl Default for BounceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: SocketAddr::from(([0, 0, 0, 0], 25)),
            hostname: "localhost".into(),
            max_message_bytes: 10 * 1024 * 1024,
            max_connections: 50,
            tls_cert: None,
            tls_key: None,
            complaint_local_part: "fbl".into(),
            dmarc_local_part: "dmarc".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BroadcastConfig {
    /// Maximum broadcast deliveries released per hour (ramp-up limit).
    pub max_per_hour: i64,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self { max_per_hour: 1000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub max_attempts: i64,
    pub timeout_secs: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self { max_attempts: 12, timeout_secs: 10 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionConfig {
    pub message_body_days: i64,
    pub event_days: i64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self { message_body_days: 30, event_days: 395 }
    }
}

/// Health thresholds. Crossing one logs an error, which becomes a Vaka issue (and so an
/// alert through the project's alert rules).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Waiting deliveries (all streams) above this count.
    pub queue_backlog: i64,
    /// Bounced share of finished deliveries in the last hour, in percent.
    pub bounce_rate_percent: f64,
    /// Minimum finished deliveries in the hour before the bounce rate is judged.
    pub bounce_rate_min_sample: i64,
    /// Deferrals to one recipient domain in the last hour.
    pub defer_spike_per_domain: i64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            queue_backlog: 5000,
            bounce_rate_percent: 5.0,
            bounce_rate_min_sample: 100,
            defer_spike_per_domain: 200,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Load(#[from] Box<figment::Error>),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load defaults, then the TOML file (if it exists), then `SIGILL_` env vars.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            fig = fig.merge(Toml::file(p));
        }
        let fig = fig.merge(Env::prefixed("SIGILL_").split("__").ignore(&["master_key", "admin_password"]));
        let cfg: Config = fig.extract().map_err(Box::new)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for d in &self.domains {
            if d.name.is_empty() || d.return_path_domain.is_empty() || d.dkim_selector.is_empty() {
                return Err(ConfigError::Invalid(format!("domain entry {:?} is incomplete", d.name)));
            }
        }
        if self.broadcast.max_per_hour <= 0 {
            return Err(ConfigError::Invalid("broadcast.max_per_hour must be positive".into()));
        }
        Ok(())
    }

    /// The configured sending domain for a `From` domain, if any.
    pub fn domain(&self, name: &str) -> Option<&DomainConfig> {
        self.domains.iter().find(|d| d.name.eq_ignore_ascii_case(name))
    }

    /// All domains that receive bounces.
    pub fn bounce_domains(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.domains.iter().map(|d| d.return_path_domain.to_ascii_lowercase()).collect();
        v.sort();
        v.dedup();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::result_large_err)]
    fn loads_toml_with_env_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sigill.toml");
        std::fs::write(
            &path,
            r#"
[server]
public_url = "https://mail.example.com"

[[domains]]
name = "mail.example.com"
stream = "transactional"
dkim_selector = "s1"
dkim_key_dir = "/etc/sigill/dkim"
return_path_domain = "bounces.example.com"
"#,
        )
        .unwrap();
        figment::Jail::expect_with(|jail| {
            jail.set_env("SIGILL_DATABASE__PATH", "/var/lib/sigill/x.db");
            let cfg = Config::load(Some(&path)).unwrap();
            assert_eq!(cfg.server.public_url, "https://mail.example.com");
            assert_eq!(cfg.database.path, PathBuf::from("/var/lib/sigill/x.db"));
            assert_eq!(cfg.domains[0].rsa_selector(), "s1r");
            assert_eq!(cfg.bounce_domains(), vec!["bounces.example.com".to_string()]);
            assert!(cfg.domain("MAIL.example.com").is_some());
            Ok(())
        });
    }
}
