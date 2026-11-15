//! A small SMTP client: one connection, sequential commands, every reply kept in full.
//! Requests are written by hand; EHLO capabilities are parsed with `smtp-proto`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sigill_core::reply::Reply;
use smtp_proto::EhloResponse;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out during {0}")]
    Timeout(&'static str),
    #[error("malformed reply: {0}")]
    Protocol(String),
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("server greeting refused: {0}")]
    Greeting(Reply),
}

/// Longest reply (all lines together) accepted from a server.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// EHLO capabilities we care about.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub starttls: bool,
    pub pipelining: bool,
    pub eight_bit: bool,
    pub size: usize,
}

pub struct SmtpClient {
    io: BufReader<Box<dyn Stream>>,
    timeout: Duration,
    pub capabilities: Capabilities,
    pub tls: bool,
    /// Messages sent over this connection (for pooling limits).
    pub messages_sent: u32,
}

impl std::fmt::Debug for SmtpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpClient").field("tls", &self.tls).finish_non_exhaustive()
    }
}

async fn timed<T>(
    what: &'static str,
    d: Duration,
    f: impl std::future::Future<Output = Result<T, SmtpError>>,
) -> Result<T, SmtpError> {
    tokio::time::timeout(d, f).await.map_err(|_| SmtpError::Timeout(what))?
}

impl SmtpClient {
    /// Connect from `source` (if given) to `addr` and read the greeting.
    pub async fn connect(
        addr: SocketAddr,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> Result<Self, SmtpError> {
        let stream = timed("connect", timeout, async {
            let socket = TcpSocket::new_v4()?;
            if let Some(ip) = source {
                socket.bind(SocketAddr::from((ip, 0)))?;
            }
            Ok::<TcpStream, SmtpError>(socket.connect(addr).await?)
        })
        .await?;
        stream.set_nodelay(true)?;
        let mut c = Self {
            io: BufReader::new(Box::new(stream)),
            timeout,
            capabilities: Capabilities::default(),
            tls: false,
            messages_sent: 0,
        };
        let greeting = c.read_reply("greeting").await?.0;
        if greeting.code != 220 {
            return Err(SmtpError::Greeting(greeting));
        }
        Ok(c)
    }

    /// Read one (possibly multi-line) reply. Returns the reply and its raw bytes.
    async fn read_reply(&mut self, what: &'static str) -> Result<(Reply, Vec<u8>), SmtpError> {
        let timeout = self.timeout;
        let io = &mut self.io;
        timed(what, timeout, async move {
            let mut raw = Vec::new();
            let mut lines = Vec::new();
            let mut code: u16;
            loop {
                // Never buffer more than the reply limit, even if no newline ever comes.
                let room = (MAX_REPLY_BYTES + 1).saturating_sub(raw.len()) as u64;
                let mut line = Vec::new();
                if (&mut *io).take(room).read_until(b'\n', &mut line).await? == 0 {
                    return Err(SmtpError::Io(std::io::ErrorKind::UnexpectedEof.into()));
                }
                raw.extend_from_slice(&line);
                if raw.len() > MAX_REPLY_BYTES || line.last() != Some(&b'\n') {
                    return Err(SmtpError::Protocol("reply too long".into()));
                }
                let text = String::from_utf8_lossy(&line);
                let text = text.trim_end_matches(['\r', '\n']);
                if text.len() < 3 || !text.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
                    return Err(SmtpError::Protocol(text.chars().take(100).collect()));
                }
                code = text[..3].parse().expect("three digits");
                let sep = text.as_bytes().get(3).copied().unwrap_or(b' ');
                lines.push(text.get(4..).unwrap_or("").to_string());
                if sep != b'-' {
                    break;
                }
            }
            Ok((Reply::new(code, lines.join("\n")), raw))
        })
        .await
    }

    async fn command(&mut self, what: &'static str, line: &str) -> Result<Reply, SmtpError> {
        let timeout = self.timeout;
        let io = self.io.get_mut();
        timed(what, timeout, async move {
            io.write_all(line.as_bytes()).await?;
            io.write_all(b"\r\n").await?;
            io.flush().await?;
            Ok(())
        })
        .await?;
        Ok(self.read_reply(what).await?.0)
    }

    /// EHLO, falling back to HELO if EHLO is refused.
    pub async fn ehlo(&mut self, name: &str) -> Result<Reply, SmtpError> {
        let timeout = self.timeout;
        let io = self.io.get_mut();
        let line = format!("EHLO {name}\r\n");
        timed("EHLO", timeout, async move {
            io.write_all(line.as_bytes()).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;
        let (reply, raw) = self.read_reply("EHLO").await?;
        if reply.code == 250 {
            self.capabilities = match EhloResponse::parse(&mut raw.iter()) {
                Ok(e) => Capabilities {
                    starttls: e.capabilities & smtp_proto::EXT_START_TLS != 0,
                    pipelining: e.capabilities & smtp_proto::EXT_PIPELINING != 0,
                    eight_bit: e.capabilities & smtp_proto::EXT_8BIT_MIME != 0,
                    size: e.size,
                },
                Err(_) => Capabilities::default(),
            };
            return Ok(reply);
        }
        self.capabilities = Capabilities::default();
        self.command("HELO", &format!("HELO {name}")).await
    }

    /// STARTTLS and redo EHLO. `server_name` is checked only if the connector verifies.
    pub async fn starttls(
        mut self,
        connector: &TlsConnector,
        server_name: &str,
        ehlo_name: &str,
    ) -> Result<Self, SmtpError> {
        let reply = self.command("STARTTLS", "STARTTLS").await?;
        if reply.code != 220 {
            return Err(SmtpError::Tls(format!("STARTTLS refused: {reply}")));
        }
        let name = ServerName::try_from(server_name.trim_end_matches('.').to_string())
            .map_err(|e| SmtpError::Tls(e.to_string()))?;
        let plain = self.io.into_inner();
        let stream = timed("TLS handshake", self.timeout, async {
            connector.connect(name, plain).await.map_err(|e| SmtpError::Tls(e.to_string()))
        })
        .await?;
        self.io = BufReader::new(Box::new(stream));
        self.tls = true;
        let r = self.ehlo(ehlo_name).await?;
        if r.code != 250 {
            return Err(SmtpError::Tls(format!("EHLO after STARTTLS refused: {r}")));
        }
        Ok(self)
    }

    pub async fn mail_from(&mut self, from: &str, size: usize) -> Result<Reply, SmtpError> {
        let mut line = format!("MAIL FROM:<{from}>");
        if self.capabilities.size > 0 {
            line.push_str(&format!(" SIZE={size}"));
        }
        if self.capabilities.eight_bit {
            line.push_str(" BODY=8BITMIME");
        }
        self.command("MAIL FROM", &line).await
    }

    pub async fn rcpt_to(&mut self, to: &str) -> Result<Reply, SmtpError> {
        self.command("RCPT TO", &format!("RCPT TO:<{to}>")).await
    }

    /// DATA with the message body (dot-stuffed here). Returns the final reply, or the
    /// reply to DATA itself if it was not 354.
    pub async fn data(&mut self, message: &[u8]) -> Result<Reply, SmtpError> {
        let r = self.command("DATA", "DATA").await?;
        if r.code != 354 {
            return Ok(r);
        }
        let body = dot_stuff(message);
        let timeout = self.timeout.max(Duration::from_secs(10)) * 5;
        let io = self.io.get_mut();
        timed("DATA body", timeout, async move {
            io.write_all(&body).await?;
            io.flush().await?;
            Ok(())
        })
        .await?;
        let r = self.read_reply("end of DATA").await?.0;
        if r.code / 100 == 2 {
            self.messages_sent += 1;
        }
        Ok(r)
    }

    pub async fn rset(&mut self) -> Result<Reply, SmtpError> {
        self.command("RSET", "RSET").await
    }

    /// Say goodbye; errors are irrelevant at this point.
    pub async fn quit(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.command("QUIT", "QUIT")).await;
    }
}

/// Normalise every line ending (CRLF, bare CR, bare LF) to CRLF, escape leading dots and
/// add the terminator. Bare CR and LF must not reach the wire: a server that treats either
/// as a line ending would read `<CR>.<CR>` as the end of DATA (SMTP smuggling).
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 64);
    let mut at_line_start = true;
    let mut i = 0;
    while i < message.len() {
        let b = message[i];
        i += 1;
        match b {
            b'\r' | b'\n' => {
                if b == b'\r' && message.get(i) == Some(&b'\n') {
                    i += 1;
                }
                out.extend_from_slice(b"\r\n");
                at_line_start = true;
            }
            _ => {
                if at_line_start && b == b'.' {
                    out.push(b'.');
                }
                out.push(b);
                at_line_start = false;
            }
        }
    }
    if !at_line_start {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// TLS connectors: opportunistic (any certificate, as MTAs do without a policy) and
/// verified (WebPKI roots and host name, for MTA-STS `enforce`).
#[derive(Clone)]
pub struct TlsConnectors {
    pub opportunistic: TlsConnector,
    pub verified: TlsConnector,
}

impl TlsConnectors {
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let verified = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let opportunistic = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        Self {
            opportunistic: TlsConnector::from(Arc::new(opportunistic)),
            verified: TlsConnector::from(Arc::new(verified)),
        }
    }
}

impl Default for TlsConnectors {
    fn default() -> Self {
        Self::new()
    }
}

/// Accepts any certificate but still checks handshake signatures.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigill_testkit::{FakeSmtp, Script};

    #[test]
    fn stuffs_dots_and_line_endings() {
        assert_eq!(dot_stuff(b"a\n.b\r\n..c"), b"a\r\n..b\r\n...c\r\n.\r\n".to_vec());
        assert_eq!(dot_stuff(b".\r\n"), b"..\r\n.\r\n".to_vec());
        // Bare CR and bare LF become CRLF, so no smuggled end-of-data survives.
        assert_eq!(dot_stuff(b"a\r.\rb"), b"a\r\n..\r\nb\r\n.\r\n".to_vec());
        assert_eq!(dot_stuff(b"a\n.\nb\r"), b"a\r\n..\r\nb\r\n.\r\n".to_vec());
        assert_eq!(dot_stuff(b""), b".\r\n".to_vec());
    }

    #[tokio::test]
    async fn talks_to_fake_server_with_starttls() {
        let srv = FakeSmtp::start(Script::default()).await;
        let mut c = SmtpClient::connect(srv.addr, None, Duration::from_secs(5)).await.unwrap();
        assert_eq!(c.ehlo("mta.test").await.unwrap().code, 250);
        assert!(c.capabilities.starttls && c.capabilities.pipelining);
        let tls = TlsConnectors::new();
        let mut c = c.starttls(&tls.opportunistic, "mx.fake.test", "mta.test").await.unwrap();
        assert!(c.tls);
        assert!(!c.capabilities.starttls, "not offered again after TLS");
        assert_eq!(c.mail_from("b+x@bounces.test", 10).await.unwrap().code, 250);
        assert_eq!(c.rcpt_to("ok@x.test").await.unwrap().code, 250);
        let r = c.rcpt_to("reject@x.test").await.unwrap();
        assert_eq!(r.code, 550);
        assert!(r.text.starts_with("5.1.1"));
        assert_eq!(c.data(b"Subject: t\r\n\r\n.hidden\r\n").await.unwrap().code, 250);
        c.quit().await;
        let got = srv.received();
        assert_eq!(got.len(), 1);
        assert!(got[0].tls);
        assert_eq!(got[0].rcpt_to, vec!["ok@x.test".to_string()]);
        assert_eq!(got[0].data, b"Subject: t\r\n\r\n.hidden\r\n".to_vec());
        assert_eq!(got[0].helo, "mta.test");
    }

    #[tokio::test]
    async fn verified_tls_rejects_self_signed() {
        let srv = FakeSmtp::start(Script::default()).await;
        let mut c = SmtpClient::connect(srv.addr, None, Duration::from_secs(5)).await.unwrap();
        c.ehlo("mta.test").await.unwrap();
        let tls = TlsConnectors::new();
        assert!(matches!(
            c.starttls(&tls.verified, "mx.fake.test", "mta.test").await,
            Err(SmtpError::Tls(_))
        ));
    }

    #[tokio::test]
    async fn refused_greeting() {
        let srv = FakeSmtp::start(Script { greeting_code: 421, ..Default::default() }).await;
        let e = SmtpClient::connect(srv.addr, None, Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(e, SmtpError::Greeting(r) if r.code == 421));
    }
}
