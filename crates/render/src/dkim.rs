//! DKIM: every message is signed twice, with RSA-2048 (`<selector>r`) and Ed25519
//! (`<selector>e`), on the `From` domain. Private keys are PEM files on disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mail_auth::crypto::{Ed25519Key, RsaKey, Sha256};
use mail_auth::dkim::DkimSigner;
use mail_auth::dkim::generate::DkimKeyPair;
use mail_auth::headers::HeaderWriter;
use mail_auth::signer::Ready;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use sigill_core::config::DomainConfig;

#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error("cannot read DKIM key {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("invalid DKIM key {path}: {message}")]
    Key { path: PathBuf, message: String },
    #[error("DKIM signing failed: {0}")]
    Sign(String),
    #[error("no DKIM keys for domain {0}")]
    UnknownDomain(String),
    #[error("cannot write key file {path}: {source}")]
    Write { path: PathBuf, source: std::io::Error },
}

/// Headers covered by the signatures. Every name is signed even when the message does not
/// have that header, so it cannot be added afterwards. The ones a reader sees are listed
/// twice (over-signing): the second entry covers a header that is not there, so a copy of
/// the message with an extra `From` or `Subject` no longer verifies.
const SIGNED_HEADERS: [&str; 17] = [
    "From",
    "From",
    "To",
    "To",
    "Cc",
    "Subject",
    "Subject",
    "Date",
    "Date",
    "Message-ID",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
    "Reply-To",
    "Reply-To",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
];

/// Signatures stop verifying after this long (`x=`), which limits replay of old mail.
/// Longer than the 72 h retry window plus time for forwarding.
pub const SIGNATURE_LIFETIME: Duration = Duration::from_secs(14 * 24 * 3600);

/// Both signing keys of one domain.
pub struct DkimKeys {
    pub domain: String,
    rsa: DkimSigner<RsaKey<Sha256>, Ready>,
    ed: DkimSigner<Ed25519Key, Ready>,
    /// DNS TXT values for the public keys, keyed by selector.
    pub dns_records: Vec<(String, String)>,
}

impl std::fmt::Debug for DkimKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKeys").field("domain", &self.domain).finish_non_exhaustive()
    }
}

fn read_der(path: &Path) -> Result<PrivateKeyDer<'static>, DkimError> {
    let pem = std::fs::read(path).map_err(|source| DkimError::Read { path: path.into(), source })?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|e| DkimError::Key { path: path.into(), message: e.to_string() })
}

impl DkimKeys {
    /// Load both keys for a configured sending domain.
    pub fn load(cfg: &DomainConfig) -> Result<Self, DkimError> {
        let rsa_path = cfg.rsa_key_path();
        let ed_path = cfg.ed25519_key_path();
        let rsa = RsaKey::<Sha256>::from_key_der(read_der(&rsa_path)?)
            .map_err(|e| DkimError::Key { path: rsa_path.clone(), message: e.to_string() })?;
        let ed_der = read_der(&ed_path)?;
        let PrivateKeyDer::Pkcs8(ed_pkcs8) = &ed_der else {
            return Err(DkimError::Key { path: ed_path, message: "Ed25519 key must be PKCS#8".into() });
        };
        let ed = Ed25519Key::from_pkcs8_der(ed_pkcs8.secret_pkcs8_der())
            .map_err(|e| DkimError::Key { path: ed_path.clone(), message: e.to_string() })?;
        let dns_records = vec![
            (cfg.rsa_selector(), rsa_txt(&rsa.public_key())),
            (cfg.ed25519_selector(), ed25519_txt(&ed.public_key())),
        ];
        let domain = cfg.name.to_ascii_lowercase();
        let rsa = DkimSigner::from_key(rsa)
            .domain(domain.as_str())
            .selector(cfg.rsa_selector())
            .headers(SIGNED_HEADERS)
            .expiration(SIGNATURE_LIFETIME);
        let ed = DkimSigner::from_key(ed)
            .domain(domain.as_str())
            .selector(cfg.ed25519_selector())
            .headers(SIGNED_HEADERS)
            .expiration(SIGNATURE_LIFETIME);
        Ok(Self { domain, rsa, ed, dns_records })
    }

    /// Return the message with both `DKIM-Signature` headers prepended.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DkimError> {
        let ed_sig = self.ed.sign(message).map_err(|e| DkimError::Sign(e.to_string()))?;
        let rsa_sig = self.rsa.sign(message).map_err(|e| DkimError::Sign(e.to_string()))?;
        let mut out = Vec::with_capacity(message.len() + 1024);
        out.extend_from_slice(rsa_sig.to_header().as_bytes());
        out.extend_from_slice(ed_sig.to_header().as_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }
}

/// All configured domains' keys, looked up by `From` domain.
#[derive(Debug, Default)]
pub struct Signers {
    keys: HashMap<String, DkimKeys>,
}

impl Signers {
    pub fn load(domains: &[DomainConfig]) -> Result<Self, DkimError> {
        let mut keys = HashMap::new();
        for d in domains {
            keys.insert(d.name.to_ascii_lowercase(), DkimKeys::load(d)?);
        }
        Ok(Self { keys })
    }

    pub fn get(&self, domain: &str) -> Option<&DkimKeys> {
        self.keys.get(&domain.to_ascii_lowercase())
    }

    pub fn sign(&self, domain: &str, message: &[u8]) -> Result<Vec<u8>, DkimError> {
        self.get(domain).ok_or_else(|| DkimError::UnknownDomain(domain.into()))?.sign(message)
    }

    pub fn domains(&self) -> impl Iterator<Item = &DkimKeys> {
        self.keys.values()
    }
}

/// DER length bytes.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        let mut v = vec![0x80 | bytes.len() as u8];
        v.extend(bytes);
        v
    }
}

/// Wrap a PKCS#1 RSA public key in SubjectPublicKeyInfo, the form DNS records use.
pub fn rsa_spki(pkcs1: &[u8]) -> Vec<u8> {
    const ALG: [u8; 15] =
        [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    let mut bit_string = vec![0x03];
    bit_string.extend(der_len(pkcs1.len() + 1));
    bit_string.push(0);
    bit_string.extend_from_slice(pkcs1);
    let mut out = vec![0x30];
    out.extend(der_len(ALG.len() + bit_string.len()));
    out.extend_from_slice(&ALG);
    out.extend(bit_string);
    out
}

pub fn rsa_txt(pkcs1_public: &[u8]) -> String {
    format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(rsa_spki(pkcs1_public)))
}

pub fn ed25519_txt(public: &[u8]) -> String {
    format!("v=DKIM1; k=ed25519; p={}", STANDARD.encode(public))
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn write_private(path: &Path, contents: &str) -> Result<(), DkimError> {
    let err = |source| DkimError::Write { path: path.into(), source };
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path).map_err(err)?.write_all(contents.as_bytes()).map_err(err)
}

/// Generate an RSA-2048 and an Ed25519 key for `cfg` and write them (mode 0600, never
/// overwriting). Returns `(selector, TXT value)` pairs to publish.
pub fn generate_keys(cfg: &DomainConfig) -> Result<Vec<(String, String)>, DkimError> {
    std::fs::create_dir_all(&cfg.dkim_key_dir)
        .map_err(|source| DkimError::Write { path: cfg.dkim_key_dir.clone(), source })?;
    let rsa = DkimKeyPair::generate_rsa(2048).map_err(|e| DkimError::Sign(e.to_string()))?;
    let ed = DkimKeyPair::generate_ed25519().map_err(|e| DkimError::Sign(e.to_string()))?;
    write_private(&cfg.rsa_key_path(), &pem("RSA PRIVATE KEY", rsa.private_key()))?;
    write_private(&cfg.ed25519_key_path(), &pem("PRIVATE KEY", ed.private_key()))?;
    Ok(vec![
        (cfg.rsa_selector(), rsa_txt(rsa.public_key())),
        (cfg.ed25519_selector(), ed25519_txt(ed.public_key())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::dkim::DomainKey;
    use mail_auth::dns::TxtRecordParser;
    use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
    use sigill_core::Stream;

    pub fn domain_cfg(dir: &Path) -> DomainConfig {
        DomainConfig {
            name: "mail.example.com".into(),
            stream: Stream::Transactional,
            dkim_selector: "s1".into(),
            dkim_key_dir: dir.to_path_buf(),
            return_path_domain: "bounces.example.com".into(),
        }
    }

    /// Verify all DKIM signatures of `msg` against the given TXT records without DNS.
    async fn verify(msg: &[u8], records: &[(String, String)]) -> Vec<DkimResult> {
        let auth = MessageAuthenticator::new_cloudflare().unwrap();
        let caches = TestCaches::default();
        for (selector, txt) in records {
            let key = DomainKey::parse(txt.as_bytes()).unwrap();
            caches.txt.0.lock().unwrap().insert(
                format!("{selector}._domainkey.mail.example.com.").into_boxed_str(),
                mail_auth::TxtRecord::from(key),
            );
        }
        let parsed = AuthenticatedMessage::parse(msg).unwrap();
        auth.verify_dkim(mail_auth::Parameters::new(&parsed).with_cache(&caches))
            .await
            .into_iter()
            .map(|o| o.result().clone())
            .collect()
    }

    #[tokio::test]
    async fn sign_and_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = domain_cfg(dir.path());
        let records = generate_keys(&cfg).unwrap();
        assert!(generate_keys(&cfg).is_err(), "never overwrites keys");
        let keys = DkimKeys::load(&cfg).unwrap();
        assert_eq!(keys.dns_records, records);

        let msg = crate::build_mime(&crate::MimeParts {
            message_id: "m1",
            from_name: None,
            from: "noreply@mail.example.com",
            to: &["a@x.com".to_string()],
            subject: "Hello",
            html: "<p>Hello</p>",
            text: "Hello\n",
            headers: &[],
            list_unsubscribe: Some("https://x.test/u/t"),
            date: 1_700_000_000,
        })
        .unwrap();
        let signed = keys.sign(&msg).unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert_eq!(text.matches("DKIM-Signature:").count(), 2);
        assert!(text.contains("a=rsa-sha256") && text.contains("a=ed25519-sha256"));
        assert!(text.contains("list-unsubscribe-post") || text.contains("List-Unsubscribe-Post"));

        assert_eq!(verify(&signed, &records).await, vec![DkimResult::Pass, DkimResult::Pass]);

        // Relaxed canonicalisation survives line-ending changes and trailing whitespace.
        let lf = String::from_utf8(signed.clone()).unwrap().replace("\r\n", "\n");
        let crlf_again = lf.replace('\n', "\r\n");
        assert_eq!(verify(crlf_again.as_bytes(), &records).await, vec![DkimResult::Pass, DkimResult::Pass]);

        // Signatures expire, and adding a second From or Subject (or a first Reply-To)
        // breaks them, because those headers are over-signed.
        assert!(text.contains("x="), "signatures carry an expiry");
        let original = String::from_utf8(signed.clone()).unwrap();
        for extra in
            ["From: Evil <evil@other.test>\r\n", "Subject: Other\r\n", "Reply-To: evil@other.test\r\n"]
        {
            let at = original.find("Message-ID:").unwrap();
            let forged = format!("{}{extra}{}", &original[..at], &original[at..]);
            let results = verify(forged.as_bytes(), &records).await;
            assert!(results.iter().all(|r| *r != DkimResult::Pass), "{extra:?} must break the signature");
        }

        // Tampering breaks both signatures.
        let tampered = String::from_utf8(signed).unwrap().replace("Subject: Hello", "Subject: Hellp");
        let results = verify(tampered.as_bytes(), &records).await;
        assert!(results.iter().all(|r| *r != DkimResult::Pass));
    }

    #[test]
    fn spki_wrapping() {
        let spki = rsa_spki(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(spki[0], 0x30);
        assert_eq!(&spki[spki.len() - 5..], &[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(der_len(300), vec![0x82, 0x01, 0x2c]);
    }

    // Minimal DNS cache for tests (TXT only).
    struct MapCache<K, V>(std::sync::Mutex<HashMap<K, V>>);

    impl<K, V> Default for MapCache<K, V> {
        fn default() -> Self {
            Self(std::sync::Mutex::new(HashMap::new()))
        }
    }

    impl<K: std::hash::Hash + Eq, V: Clone> mail_auth::ResolverCache<K, V> for MapCache<K, V> {
        fn get<Q>(&self, name: &Q) -> Option<V>
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().get(name).cloned()
        }
        fn remove<Q>(&self, name: &Q) -> Option<V>
        where
            K: std::borrow::Borrow<Q>,
            Q: std::hash::Hash + Eq + ?Sized,
        {
            self.0.lock().unwrap().remove(name)
        }
        fn insert(&self, key: K, value: V, _valid_until: std::time::Instant) {
            self.0.lock().unwrap().insert(key, value);
        }
    }

    type Answer<T> = Result<mail_auth::RecordSet<T>, mail_auth::Negative>;

    #[derive(Default)]
    struct TestCaches {
        txt: MapCache<Box<str>, mail_auth::TxtRecord>,
        mx: MapCache<Box<str>, Answer<mail_auth::Mx>>,
        ipv4: MapCache<Box<str>, Answer<std::net::Ipv4Addr>>,
        ipv6: MapCache<Box<str>, Answer<std::net::Ipv6Addr>>,
        ptr: MapCache<std::net::IpAddr, Answer<Box<str>>>,
    }

    impl mail_auth::DnsCache for TestCaches {
        type Txt = MapCache<Box<str>, mail_auth::TxtRecord>;
        type Mx = MapCache<Box<str>, Answer<mail_auth::Mx>>;
        type Ipv4 = MapCache<Box<str>, Answer<std::net::Ipv4Addr>>;
        type Ipv6 = MapCache<Box<str>, Answer<std::net::Ipv6Addr>>;
        type Ptr = MapCache<std::net::IpAddr, Answer<Box<str>>>;
        fn txt(&self) -> Option<&Self::Txt> {
            Some(&self.txt)
        }
        fn mx(&self) -> Option<&Self::Mx> {
            Some(&self.mx)
        }
        fn ipv4(&self) -> Option<&Self::Ipv4> {
            Some(&self.ipv4)
        }
        fn ipv6(&self) -> Option<&Self::Ipv6> {
            Some(&self.ipv6)
        }
        fn ptr(&self) -> Option<&Self::Ptr> {
            Some(&self.ptr)
        }
    }
}
