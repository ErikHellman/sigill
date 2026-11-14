//! Per-app token bucket.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    /// `rate` requests per second with a burst of twice that.
    pub fn new(rate: u32) -> Self {
        let rate = f64::from(rate.max(1));
        Self { rate, burst: rate * 2.0, buckets: Mutex::new(HashMap::new()) }
    }

    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        let (tokens, last) = buckets.entry(key.to_string()).or_insert((self.burst, now));
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.rate).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_refills() {
        let rl = RateLimiter::new(2);
        let t0 = Instant::now();
        assert!((0..4).all(|_| rl.allow_at("a", t0)));
        assert!(!rl.allow_at("a", t0));
        assert!(rl.allow_at("b", t0), "buckets are per key");
        assert!(rl.allow_at("a", t0 + Duration::from_millis(500)));
        assert!(!rl.allow_at("a", t0 + Duration::from_millis(500)));
    }
}
