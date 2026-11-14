//! Reuse of open SMTP connections per (MX address, source IP, TLS policy).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::client::SmtpClient;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub addr: SocketAddr,
    pub source: Option<Ipv4Addr>,
    pub verified_tls: bool,
}

pub struct Pool {
    idle: Mutex<HashMap<PoolKey, Vec<(SmtpClient, Instant)>>>,
    max_idle: Duration,
    max_messages: u32,
}

impl Pool {
    pub fn new(max_idle: Duration, max_messages: u32) -> Self {
        Self { idle: Mutex::new(HashMap::new()), max_idle, max_messages }
    }

    /// An idle connection for `key`, if one is fresh enough.
    pub fn take(&self, key: &PoolKey) -> Option<SmtpClient> {
        let mut idle = self.idle.lock().expect("pool lock");
        let list = idle.get_mut(key)?;
        while let Some((c, since)) = list.pop() {
            if since.elapsed() < self.max_idle {
                return Some(c);
            }
        }
        None
    }

    /// Return a healthy connection after a finished transaction. Returns it back to the
    /// caller (to QUIT) when it has carried enough messages.
    pub fn put(&self, key: PoolKey, client: SmtpClient) -> Option<SmtpClient> {
        if client.messages_sent >= self.max_messages {
            return Some(client);
        }
        self.idle.lock().expect("pool lock").entry(key).or_default().push((client, Instant::now()));
        None
    }

    /// Remove connections idle for too long; the caller sends QUIT on them.
    pub fn expired(&self) -> Vec<SmtpClient> {
        let mut out = Vec::new();
        let mut idle = self.idle.lock().expect("pool lock");
        for list in idle.values_mut() {
            let (old, fresh): (Vec<_>, Vec<_>) =
                list.drain(..).partition(|(_, t)| t.elapsed() >= self.max_idle);
            *list = fresh;
            out.extend(old.into_iter().map(|(c, _)| c));
        }
        idle.retain(|_, l| !l.is_empty());
        out
    }

    /// Everything, for shutdown.
    pub fn drain(&self) -> Vec<SmtpClient> {
        self.idle
            .lock()
            .expect("pool lock")
            .drain()
            .flat_map(|(_, l)| l.into_iter().map(|(c, _)| c))
            .collect()
    }

    pub fn idle_count(&self) -> usize {
        self.idle.lock().expect("pool lock").values().map(Vec::len).sum()
    }
}
