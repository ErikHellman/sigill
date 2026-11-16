//! Test helpers: a controllable fake SMTP server, DKIM keys and a ready config.
//! Tests never touch real mail servers or the internet.

pub mod fake_smtp;

use std::path::PathBuf;
use std::sync::OnceLock;

use sigill_core::config::DomainConfig;
use sigill_core::{Config, Stream};

pub use fake_smtp::{FakeSmtp, Received, Script};

/// A 32-byte master key for tests.
pub const MASTER_KEY: &str = "test-master-key-test-master-key-0123456789";

struct Keys {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

static KEYS: OnceLock<Keys> = OnceLock::new();

/// Sending domains with DKIM keys generated once per test process:
/// `mail.example.com` (transactional) and `news.example.com` (broadcast).
pub fn domains() -> Vec<DomainConfig> {
    let keys = KEYS.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        for d in make_domains(&path) {
            sigill_render::dkim::generate_keys(&d).expect("generate DKIM keys");
        }
        Keys { _dir: dir, path }
    });
    make_domains(&keys.path)
}

fn make_domains(dir: &std::path::Path) -> Vec<DomainConfig> {
    vec![
        DomainConfig {
            name: "mail.example.com".into(),
            stream: Stream::Transactional,
            dkim_selector: "t1".into(),
            dkim_key_dir: dir.to_path_buf(),
            return_path_domain: "bounces.example.com".into(),
        },
        DomainConfig {
            name: "news.example.com".into(),
            stream: Stream::Broadcast,
            dkim_selector: "b1".into(),
            dkim_key_dir: dir.to_path_buf(),
            return_path_domain: "bounces.example.com".into(),
        },
    ]
}

/// A config with both test domains and default senders.
pub fn config() -> Config {
    let mut c = Config { domains: domains(), ..Default::default() };
    c.streams.transactional.default_from = Some("noreply@mail.example.com".into());
    c.streams.broadcast.default_from = Some("news@news.example.com".into());
    c.streams.broadcast.priority = 10;
    c.server.public_url = "https://sigill.test".into();
    // Tests deliver to a fake server on loopback.
    c.delivery.allow_private_mx = true;
    c
}

pub fn secrets() -> sigill_core::secrets::Secrets {
    sigill_core::secrets::Secrets::new(MASTER_KEY.as_bytes().to_vec()).expect("valid key")
}
