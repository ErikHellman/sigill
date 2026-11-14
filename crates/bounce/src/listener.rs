//! The receive-only SMTP server for bounces, complaints and DMARC reports.
//!
//! It accepts mail only for signed VERP return paths and the complaint (and, once enabled,
//! DMARC) addresses of the bounce domains, rejects everything else at RCPT, and caps
//! message size, recipients, line length, idle time and concurrent connections.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sigill_core::config::BounceConfig;
use sigill_core::telemetry;
use sigill_core::verp;
use smtp_proto::Request;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::process::{Processor, Target};

const MAX_COMMAND_LINE: usize = 4096;
const MAX_DATA_LINE: usize = 64 * 1024;
const MAX_RECIPIENTS: usize = 50;
const MAX_ERRORS: usize = 10;

/// Listener settings, derived from [`BounceConfig`] and the configured bounce domains.
#[derive(Debug, Clone)]
pub struct Settings {
    pub hostname: String,
    pub bounce_domains: Vec<String>,
    pub complaint_local_part: String,
    pub dmarc_local_part: String,
    /// Accept mail for the DMARC address (when report ingestion is enabled).
    pub accept_dmarc: bool,
    pub max_message_bytes: usize,
    pub max_connections: usize,
    /// Idle timeout for each command or data line.
    pub timeout: Duration,
}

impl Settings {
    pub fn new(cfg: &BounceConfig, bounce_domains: Vec<String>) -> Self {
        Self {
            hostname: cfg.hostname.clone(),
            bounce_domains: bounce_domains.into_iter().map(|d| d.to_ascii_lowercase()).collect(),
            complaint_local_part: cfg.complaint_local_part.to_ascii_lowercase(),
            dmarc_local_part: cfg.dmarc_local_part.to_ascii_lowercase(),
            accept_dmarc: false,
            max_message_bytes: cfg.max_message_bytes,
            max_connections: cfg.max_connections,
            timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("reading {0}: {1}")]
    Pem(String, String),
    #[error("TLS config: {0}")]
    Config(#[from] rustls::Error),
}

/// Build a STARTTLS acceptor from PEM certificate chain and key files.
pub fn load_tls(cert: &Path, key: &Path) -> Result<TlsAcceptor, TlsError> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| TlsError::Pem(cert.display().to_string(), e.to_string()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| TlsError::Pem(key.display().to_string(), e.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Clone)]
pub struct Listener {
    settings: Arc<Settings>,
    processor: Processor,
    verp_key: [u8; 32],
    tls: Option<TlsAcceptor>,
}

impl Listener {
    pub fn new(
        settings: Settings,
        processor: Processor,
        verp_key: [u8; 32],
        tls: Option<TlsAcceptor>,
    ) -> Self {
        Self { settings: Arc::new(settings), processor, verp_key, tls }
    }

    /// Accept connections until `token` is cancelled.
    pub async fn run(self, listener: TcpListener, token: CancellationToken) {
        let slots = Arc::new(Semaphore::new(self.settings.max_connections.max(1)));
        if let Ok(addr) = listener.local_addr() {
            info!(%addr, tls = self.tls.is_some(), "bounce listener started");
        }
        loop {
            let accepted = tokio::select! {
                _ = token.cancelled() => break,
                r = listener.accept() => r,
            };
            let (mut stream, peer) = match accepted {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                let _ = stream.write_all(b"421 4.7.0 Too many connections, try again later\r\n").await;
                continue;
            };
            let this = self.clone();
            let token = token.clone();
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {
                    _ = token.cancelled() => {}
                    r = this.session(stream) => if let Err(e) = r {
                        debug!(peer = %peer.ip(), error = %e, "bounce session ended");
                    },
                }
            });
        }
        info!("bounce listener stopped");
    }

    fn target(&self, address: &str) -> Option<Target> {
        let (local, domain) = address.rsplit_once('@')?;
        if !self.settings.bounce_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
            return None;
        }
        let local = local.to_ascii_lowercase();
        if local == self.settings.complaint_local_part {
            return Some(Target::Complaint);
        }
        if self.settings.accept_dmarc && local == self.settings.dmarc_local_part {
            return Some(Target::Dmarc);
        }
        verp::decode(&self.verp_key, address).map(Target::Verp)
    }

    async fn session(&self, stream: TcpStream) -> std::io::Result<()> {
        let s = &self.settings;
        let mut io: BufReader<Box<dyn Io>> = BufReader::new(Box::new(stream));
        reply(&mut io, &format!("220 {} ESMTP\r\n", s.hostname)).await?;
        let mut tls = false;
        let mut greeted = false;
        let mut in_mail = false;
        let mut targets: Vec<Target> = Vec::new();
        let mut errors = 0usize;
        let mut line = Vec::new();
        loop {
            if errors >= MAX_ERRORS {
                reply(&mut io, "421 4.7.0 Too many errors\r\n").await?;
                return Ok(());
            }
            line.clear();
            match read_line(&mut io, &mut line, MAX_COMMAND_LINE, s.timeout).await? {
                Line::Eof => return Ok(()),
                Line::TooLong => {
                    reply(&mut io, "500 5.5.2 Line too long\r\n").await?;
                    return Ok(());
                }
                Line::Ok => {}
            }
            match Request::parse(&mut line.iter()) {
                Ok(Request::Ehlo { host }) => {
                    greeted = true;
                    in_mail = false;
                    targets.clear();
                    let mut r = format!(
                        "250-{} greets {host}\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n",
                        s.hostname
                    );
                    if self.tls.is_some() && !tls {
                        r.push_str("250-STARTTLS\r\n");
                    }
                    r.push_str(&format!("250 SIZE {}\r\n", s.max_message_bytes));
                    reply(&mut io, &r).await?;
                }
                Ok(Request::Helo { host }) => {
                    greeted = true;
                    in_mail = false;
                    targets.clear();
                    reply(&mut io, &format!("250 {} greets {host}\r\n", s.hostname)).await?;
                }
                Ok(Request::StartTls) => {
                    let Some(acceptor) = self.tls.as_ref().filter(|_| !tls) else {
                        errors += 1;
                        reply(&mut io, "502 5.5.1 STARTTLS not available\r\n").await?;
                        continue;
                    };
                    reply(&mut io, "220 2.0.0 Ready to start TLS\r\n").await?;
                    let plain = io.into_inner();
                    let stream = tokio::time::timeout(s.timeout, acceptor.accept(plain))
                        .await
                        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                    io = BufReader::new(Box::new(stream));
                    tls = true;
                    greeted = false;
                    in_mail = false;
                    targets.clear();
                }
                Ok(Request::Mail { from }) => {
                    if !greeted {
                        errors += 1;
                        reply(&mut io, "503 5.5.1 EHLO first\r\n").await?;
                    } else if from.size > s.max_message_bytes {
                        reply(&mut io, "552 5.3.4 Message too big\r\n").await?;
                    } else {
                        in_mail = true;
                        targets.clear();
                        reply(&mut io, "250 2.1.0 OK\r\n").await?;
                    }
                }
                Ok(Request::Rcpt { to }) => {
                    if !in_mail {
                        errors += 1;
                        reply(&mut io, "503 5.5.1 MAIL first\r\n").await?;
                    } else if targets.len() >= MAX_RECIPIENTS {
                        reply(&mut io, "452 4.5.3 Too many recipients\r\n").await?;
                    } else if let Some(t) = self.target(&to.address) {
                        if !targets.contains(&t) {
                            targets.push(t);
                        }
                        reply(&mut io, "250 2.1.5 OK\r\n").await?;
                    } else {
                        errors += 1;
                        reply(&mut io, "550 5.1.1 No such recipient\r\n").await?;
                    }
                }
                Ok(Request::Data) => {
                    if targets.is_empty() {
                        errors += 1;
                        reply(&mut io, "554 5.5.1 No valid recipients\r\n").await?;
                        continue;
                    }
                    reply(&mut io, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                    let data = read_data(&mut io, s.max_message_bytes, s.timeout).await?;
                    let r = match data {
                        None => "552 5.3.4 Message too big\r\n",
                        Some(raw) => match self.processor.process(&targets, &raw).await {
                            Ok(summary) => {
                                debug!(?summary, "report processed");
                                "250 2.0.0 OK\r\n"
                            }
                            Err(e) => {
                                error!(error = %e, "processing a bounce failed");
                                telemetry::capture_error(&e);
                                "451 4.3.0 Temporary failure, try again later\r\n"
                            }
                        },
                    };
                    in_mail = false;
                    targets.clear();
                    reply(&mut io, r).await?;
                }
                Ok(Request::Rset) => {
                    in_mail = false;
                    targets.clear();
                    reply(&mut io, "250 2.0.0 OK\r\n").await?;
                }
                Ok(Request::Noop { .. }) => reply(&mut io, "250 2.0.0 OK\r\n").await?,
                Ok(Request::Quit) => {
                    reply(&mut io, "221 2.0.0 Bye\r\n").await?;
                    return Ok(());
                }
                _ => {
                    errors += 1;
                    reply(&mut io, "502 5.5.2 Command not implemented\r\n").await?;
                }
            }
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

enum Line {
    Ok,
    Eof,
    TooLong,
}

async fn read_line(
    io: &mut BufReader<Box<dyn Io>>,
    buf: &mut Vec<u8>,
    max: usize,
    timeout: Duration,
) -> std::io::Result<Line> {
    let n = tokio::time::timeout(timeout, io.take(max as u64).read_until(b'\n', buf))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    Ok(if n == 0 {
        Line::Eof
    } else if buf.last() != Some(&b'\n') {
        if n >= max { Line::TooLong } else { Line::Eof }
    } else {
        Line::Ok
    })
}

async fn reply(io: &mut BufReader<Box<dyn Io>>, text: &str) -> std::io::Result<()> {
    io.get_mut().write_all(text.as_bytes()).await?;
    io.get_mut().flush().await
}

/// Read a DATA body up to the terminating `.` line, undoing dot-stuffing. Returns `None`
/// (after reading to the end) when the message is larger than `max`.
async fn read_data(
    io: &mut BufReader<Box<dyn Io>>,
    max: usize,
    timeout: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    let mut too_big = false;
    let mut line = Vec::new();
    loop {
        line.clear();
        match read_line(io, &mut line, MAX_DATA_LINE, timeout).await? {
            Line::Eof => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            // Over-long lines are kept in pieces rather than rejected.
            Line::TooLong | Line::Ok => {}
        }
        if line == b".\r\n" || line == b".\n" {
            return Ok((!too_big).then_some(data));
        }
        if too_big {
            continue;
        }
        let content = if line.starts_with(b"..") { &line[1..] } else { &line[..] };
        if data.len() + content.len() > max {
            too_big = true;
            data = Vec::new();
            continue;
        }
        data.extend_from_slice(content);
    }
}
