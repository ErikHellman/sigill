//! Per-domain throttling: a cap on concurrent connections and on deliveries per minute.
//! Limits come from the `domain_throttle` table; backoff after rate-limit replies is
//! stored there too, so the dispatcher skips the domain until it expires.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Limits for domains without their own row.
pub const DEFAULT_MAX_CONNS: i64 = 10;
pub const DEFAULT_MAX_PER_MINUTE: i64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_conns: i64,
    pub max_per_minute: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_conns: DEFAULT_MAX_CONNS, max_per_minute: DEFAULT_MAX_PER_MINUTE }
    }
}

struct DomainState {
    conns: Arc<Semaphore>,
    max_conns: i64,
    window_start: Instant,
    sent_in_window: i64,
}

#[derive(Default)]
pub struct Throttle {
    limits: Mutex<HashMap<String, Limits>>,
    state: Mutex<HashMap<String, DomainState>>,
}

/// Result of asking to send `n` deliveries to a domain now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    Granted,
    /// Over the per-minute limit; try again after this long.
    RetryIn(Duration),
}

impl Throttle {
    pub fn set_limits(&self, limits: HashMap<String, Limits>) {
        *self.limits.lock().expect("throttle lock") = limits;
    }

    fn limits_for(&self, domain: &str) -> Limits {
        self.limits.lock().expect("throttle lock").get(domain).copied().unwrap_or_default()
    }

    fn with_state<T>(&self, domain: &str, now: Instant, f: impl FnOnce(&mut DomainState) -> T) -> T {
        let limits = self.limits_for(domain);
        let mut state = self.state.lock().expect("throttle lock");
        let s = state.entry(domain.to_string()).or_insert_with(|| DomainState {
            conns: Arc::new(Semaphore::new(limits.max_conns.max(1) as usize)),
            max_conns: limits.max_conns,
            window_start: now,
            sent_in_window: 0,
        });
        if s.max_conns != limits.max_conns {
            // Limits changed: new connections use the new cap.
            s.conns = Arc::new(Semaphore::new(limits.max_conns.max(1) as usize));
            s.max_conns = limits.max_conns;
        }
        f(s)
    }

    /// Reserve `n` sends in the current one-minute window. A batch larger than the limit
    /// is granted when the window is empty, so it can never starve.
    pub fn reserve(&self, domain: &str, n: i64) -> Reservation {
        self.reserve_at(domain, n, Instant::now())
    }

    pub fn reserve_at(&self, domain: &str, n: i64, now: Instant) -> Reservation {
        let max = self.limits_for(domain).max_per_minute.max(1);
        self.with_state(domain, now, |s| {
            if now.duration_since(s.window_start) >= Duration::from_secs(60) {
                s.window_start = now;
                s.sent_in_window = 0;
            }
            if s.sent_in_window == 0 || s.sent_in_window + n <= max {
                s.sent_in_window += n;
                Reservation::Granted
            } else {
                Reservation::RetryIn(
                    Duration::from_secs(60).saturating_sub(now.duration_since(s.window_start)),
                )
            }
        })
    }

    /// Wait for a connection slot to the domain.
    pub async fn connection(&self, domain: &str) -> OwnedSemaphorePermit {
        let sem = self.with_state(domain, Instant::now(), |s| s.conns.clone());
        sem.acquire_owned().await.expect("semaphore never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_minute_window() {
        let t = Throttle::default();
        t.set_limits(HashMap::from([("gmail.com".to_string(), Limits { max_conns: 2, max_per_minute: 3 })]));
        let t0 = Instant::now();
        assert_eq!(t.reserve_at("gmail.com", 2, t0), Reservation::Granted);
        assert_eq!(t.reserve_at("gmail.com", 1, t0), Reservation::Granted);
        assert!(
            matches!(t.reserve_at("gmail.com", 1, t0 + Duration::from_secs(10)), Reservation::RetryIn(d) if d == Duration::from_secs(50))
        );
        assert_eq!(t.reserve_at("gmail.com", 1, t0 + Duration::from_secs(61)), Reservation::Granted);
        // A batch bigger than the limit goes through on an empty window.
        assert_eq!(t.reserve_at("big.test", 1000, t0), Reservation::Granted);
    }

    #[tokio::test]
    async fn connection_cap() {
        let t = Throttle::default();
        t.set_limits(HashMap::from([("x.test".to_string(), Limits { max_conns: 1, max_per_minute: 10 })]));
        let p1 = t.connection("x.test").await;
        let waiting = tokio::time::timeout(Duration::from_millis(50), t.connection("x.test")).await;
        assert!(waiting.is_err(), "second connection waits");
        drop(p1);
        let _p2 = tokio::time::timeout(Duration::from_millis(50), t.connection("x.test")).await.unwrap();
    }
}
