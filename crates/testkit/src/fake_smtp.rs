//! A controllable fake SMTP server for tests, built on `smtp-proto` request parsing.
//!
//! Replies are driven by the recipient's local part, so one server can exercise every
//! outcome in a single test:
//!
//! - contains `reject` → `550 5.1.1` at RCPT (hard bounce)
//! - contains `blocked` → `554 5.7.1` at RCPT (soft, policy bounce)
//! - contains `defer` → `451 4.3.0` at RCPT
//! - contains `ratelimit` → `421 4.7.0` at RCPT (rate limited)
//! - contains `datafail` → accepted at RCPT, `554 5.6.0` after DATA
//! - contains `drop` → the connection is closed after DATA without a reply
//!
//! [`Script`] adds whole-server behaviour: no STARTTLS, or a 421 greeting.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smtp_proto::Request;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

/// Whole-server behaviour.
#[derive(Debug, Clone)]
pub struct Script {
    /// Advertise and accept STARTTLS (with a self-signed certificate).
    pub starttls: bool,
    /// Greeting code; 421 makes every connection fail at once.
    pub greeting_code: u16,
    /// Greeting/EHLO host name.
    pub hostname: String,
}

impl Default for Script {
    fn default() -> Self {
        Self { starttls: true, greeting_code: 220, hostname: "mx.fake.test".into() }
    }
}

/// One accepted message.
#[derive(Debug, Clone)]
pub struct Received {
    pub helo: String,
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub data: Vec<u8>,
    pub tls: bool,
}

#[derive(Default)]
struct Shared {
    received: Mutex<Vec<Received>>,
    connections: Mutex<usize>,
    transactions: Mutex<usize>,
    notify: Notify,
}

/// Handle to a running fake server; it stops when dropped.
pub struct FakeSmtp {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeSmtp {
    pub async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake SMTP");
        let addr = listener.local_addr().expect("local addr");
        let shared = Arc::new(Shared::default());
        let acceptor = tls_acceptor();
        let s = shared.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                *s.connections.lock().unwrap() += 1;
                let (s, script, acceptor) = (s.clone(), script.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let _ = session(stream, &script, &acceptor, &s).await;
                });
            }
        });
        Self { addr, shared, task }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn received(&self) -> Vec<Received> {
        self.shared.received.lock().unwrap().clone()
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        *self.shared.connections.lock().unwrap()
    }

    /// MAIL transactions started so far.
    pub fn transactions(&self) -> usize {
        *self.shared.transactions.lock().unwrap()
    }

    /// Wait until at least `n` messages have been received, or panic after `timeout`.
    pub async fn wait_for(&self, n: usize, timeout: Duration) -> Vec<Received> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.shared.notify.notified();
            let got = self.received();
            if got.len() >= n {
                return got;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                panic!("expected {n} messages, got {}", self.received().len());
            }
        }
    }
}

fn tls_acceptor() -> TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "mx.fake.test".to_string()])
        .expect("self-signed cert");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .expect("server TLS config");
    TlsAcceptor::from(Arc::new(config))
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn session(
    stream: TcpStream,
    script: &Script,
    acceptor: &TlsAcceptor,
    shared: &Shared,
) -> std::io::Result<()> {
    let mut io: BufReader<Box<dyn Io>> = BufReader::new(Box::new(stream));
    let host = &script.hostname;
    if script.greeting_code != 220 {
        io.get_mut()
            .write_all(format!("{} 4.3.2 {host} not accepting mail\r\n", script.greeting_code).as_bytes())
            .await?;
        return Ok(());
    }
    reply(&mut io, &format!("220 {host} ESMTP fake\r\n")).await?;
    let mut tls = false;
    let mut helo = String::new();
    let mut mail_from: Option<String> = None;
    let mut rcpts: Vec<String> = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if io.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        match Request::parse(&mut line.iter()) {
            Ok(Request::Ehlo { host: h }) | Ok(Request::Helo { host: h }) => {
                helo = h.to_string();
                mail_from = None;
                rcpts.clear();
                let mut r = format!(
                    "250-{host} greets {helo}\r\n250-PIPELINING\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n"
                );
                if script.starttls && !tls {
                    r.push_str("250-STARTTLS\r\n");
                }
                r.push_str("250 SIZE 52428800\r\n");
                reply(&mut io, &r).await?;
            }
            Ok(Request::StartTls) if script.starttls && !tls => {
                reply(&mut io, "220 2.0.0 Ready to start TLS\r\n").await?;
                let plain = io.into_inner();
                let stream = acceptor.accept(plain).await?;
                io = BufReader::new(Box::new(stream));
                tls = true;
                helo.clear();
            }
            Ok(Request::Mail { from }) => {
                *shared.transactions.lock().unwrap() += 1;
                mail_from = Some(from.address.to_string());
                rcpts.clear();
                reply(&mut io, "250 2.1.0 OK\r\n").await?;
            }
            Ok(Request::Rcpt { to }) => {
                let addr = to.address.to_string();
                let local = addr.split('@').next().unwrap_or("").to_ascii_lowercase();
                let r = if mail_from.is_none() {
                    "503 5.5.1 MAIL first\r\n"
                } else if local.contains("reject") {
                    "550 5.1.1 The email account that you tried to reach does not exist\r\n"
                } else if local.contains("blocked") {
                    "554 5.7.1 Message rejected due to local policy\r\n"
                } else if local.contains("defer") {
                    "451 4.3.0 Temporary failure, try again later\r\n"
                } else if local.contains("ratelimit") {
                    "421 4.7.0 Too many messages, rate limited\r\n"
                } else {
                    rcpts.push(addr);
                    "250 2.1.5 OK\r\n"
                };
                reply(&mut io, r).await?;
            }
            Ok(Request::Data) => {
                if rcpts.is_empty() {
                    reply(&mut io, "554 5.5.1 No valid recipients\r\n").await?;
                    continue;
                }
                reply(&mut io, "354 Go ahead\r\n").await?;
                let data = read_data(&mut io).await?;
                let lower: Vec<String> = rcpts.iter().map(|r| r.to_ascii_lowercase()).collect();
                if lower.iter().any(|r| r.contains("drop")) {
                    return Ok(());
                }
                if lower.iter().any(|r| r.contains("datafail")) {
                    reply(&mut io, "554 5.6.0 Message content rejected\r\n").await?;
                } else {
                    shared.received.lock().unwrap().push(Received {
                        helo: helo.clone(),
                        mail_from: mail_from.clone().unwrap_or_default(),
                        rcpt_to: rcpts.clone(),
                        data,
                        tls,
                    });
                    shared.notify.notify_waiters();
                    reply(&mut io, "250 2.0.0 OK queued\r\n").await?;
                }
                mail_from = None;
                rcpts.clear();
            }
            Ok(Request::Rset) => {
                mail_from = None;
                rcpts.clear();
                reply(&mut io, "250 2.0.0 OK\r\n").await?;
            }
            Ok(Request::Noop { .. }) => reply(&mut io, "250 2.0.0 OK\r\n").await?,
            Ok(Request::Quit) => {
                reply(&mut io, "221 2.0.0 Bye\r\n").await?;
                return Ok(());
            }
            _ => reply(&mut io, "502 5.5.2 Command not implemented\r\n").await?,
        }
    }
}

async fn reply(io: &mut BufReader<Box<dyn Io>>, text: &str) -> std::io::Result<()> {
    io.get_mut().write_all(text.as_bytes()).await?;
    io.get_mut().flush().await
}

/// Read a DATA body up to the terminating `.` line, undoing dot-stuffing.
async fn read_data(io: &mut BufReader<Box<dyn Io>>) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        if io.read_until(b'\n', &mut line).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if line == b".\r\n" || line == b".\n" {
            return Ok(data);
        }
        if line.starts_with(b"..") {
            data.extend_from_slice(&line[1..]);
        } else {
            data.extend_from_slice(&line);
        }
    }
}

/// Wait briefly for a condition; handy in tests that poll the database.
pub async fn eventually<F: FnMut() -> bool>(mut f: F, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}
