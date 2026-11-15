//! Limits on failed admin logins. Basic auth has no sessions, so every request carries a
//! password guess; without a limit the password could be tried at network speed.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::request::Parts;

/// Failures allowed per client in one window before it is blocked for the rest of it.
pub const MAX_FAILURES_PER_CLIENT: u32 = 10;
/// Failures allowed from all clients together in one window.
pub const MAX_FAILURES_TOTAL: u32 = 200;
pub const WINDOW: Duration = Duration::from_secs(15 * 60);

const TOTAL_KEY: &str = "";

#[derive(Default)]
pub struct LoginThrottle {
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginThrottle {
    fn count(&self, key: &str, now: Instant) -> u32 {
        let m = self.failures.lock().expect("login throttle lock");
        match m.get(key) {
            Some((n, since)) if now.saturating_duration_since(*since) < WINDOW => *n,
            _ => 0,
        }
    }

    /// Has this client, or everyone together, used up the failures for this window?
    pub fn blocked(&self, client: &str) -> bool {
        self.blocked_at(client, Instant::now())
    }

    fn blocked_at(&self, client: &str, now: Instant) -> bool {
        self.count(client, now) >= MAX_FAILURES_PER_CLIENT || self.count(TOTAL_KEY, now) >= MAX_FAILURES_TOTAL
    }

    pub fn record_failure(&self, client: &str) {
        self.record_failure_at(client, Instant::now());
    }

    fn record_failure_at(&self, client: &str, now: Instant) {
        let mut m = self.failures.lock().expect("login throttle lock");
        if m.len() > 10_000 {
            m.retain(|_, (_, since)| now.saturating_duration_since(*since) < WINDOW);
        }
        for key in [client, TOTAL_KEY] {
            let e = m.entry(key.to_string()).or_insert((0, now));
            if now.saturating_duration_since(e.1) >= WINDOW {
                *e = (0, now);
            }
            e.0 += 1;
        }
    }
}

/// Who is asking: the address the reverse proxy saw (the last `X-Forwarded-For` entry,
/// which the proxy itself appends), or one shared key for direct connections.
pub fn client_key(parts: &Parts) -> String {
    parts
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|s| !s.is_empty())
        .filter(|s| s.len() <= 64)
        .unwrap_or("direct")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_too_many_failures_and_recovers() {
        let t = LoginThrottle::default();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES_PER_CLIENT {
            assert!(!t.blocked_at("1.2.3.4", t0));
            t.record_failure_at("1.2.3.4", t0);
        }
        assert!(t.blocked_at("1.2.3.4", t0));
        assert!(!t.blocked_at("5.6.7.8", t0), "other clients are unaffected");
        assert!(!t.blocked_at("1.2.3.4", t0 + WINDOW), "the block ends with the window");
    }

    #[test]
    fn total_limit_covers_many_clients() {
        let t = LoginThrottle::default();
        let t0 = Instant::now();
        for i in 0..MAX_FAILURES_TOTAL {
            t.record_failure_at(&format!("10.0.{}.{}", i / 250, i % 250), t0);
        }
        assert!(t.blocked_at("192.0.2.1", t0));
    }
}
