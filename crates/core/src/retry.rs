//! Retry schedule for temporary failures (4xx replies and connection errors).
//!
//! 5 min, 15 min, 30 min, 1 h, 2 h, 4 h, then every 4 h until the retry window (72 h by
//! default) runs out; after that the delivery fails for good.

const MINUTE: i64 = 60_000;
const HOUR: i64 = 60 * MINUTE;
const SCHEDULE_MS: [i64; 6] = [5 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 2 * HOUR, 4 * HOUR];

/// Delay before the next try after `attempts` failed attempts (1-based).
pub fn delay_after(attempts: i64) -> i64 {
    let idx = (attempts.max(1) - 1) as usize;
    SCHEDULE_MS.get(idx).copied().unwrap_or(4 * HOUR)
}

/// What to do after a temporary failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Try again at this time (unix ms).
    RetryAt(i64),
    /// The retry window is over.
    GiveUp,
}

/// Decide the next step for a delivery first queued at `created_at_ms`, which has now
/// failed `attempts` times, at time `now_ms`.
pub fn next_attempt(created_at_ms: i64, attempts: i64, now_ms: i64, max_retry_hours: i64) -> RetryDecision {
    let deadline = created_at_ms + max_retry_hours * HOUR;
    if now_ms >= deadline {
        return RetryDecision::GiveUp;
    }
    let next = now_ms + delay_after(attempts);
    if next > deadline {
        // One last try right at the end of the window.
        RetryDecision::RetryAt(deadline)
    } else {
        RetryDecision::RetryAt(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_schedule() {
        assert_eq!(delay_after(1), 5 * MINUTE);
        assert_eq!(delay_after(2), 15 * MINUTE);
        assert_eq!(delay_after(3), 30 * MINUTE);
        assert_eq!(delay_after(4), HOUR);
        assert_eq!(delay_after(5), 2 * HOUR);
        assert_eq!(delay_after(6), 4 * HOUR);
        assert_eq!(delay_after(20), 4 * HOUR);
        assert_eq!(delay_after(0), 5 * MINUTE);
    }

    #[test]
    fn gives_up_after_window() {
        let created = 1_000_000;
        assert_eq!(next_attempt(created, 1, created, 72), RetryDecision::RetryAt(created + 5 * MINUTE));
        assert_eq!(next_attempt(created, 9, created + 72 * HOUR, 72), RetryDecision::GiveUp);
        assert_eq!(
            next_attempt(created, 9, created + 70 * HOUR, 72),
            RetryDecision::RetryAt(created + 72 * HOUR)
        );
    }

    #[test]
    fn total_attempts_within_72h() {
        let created = 0;
        let mut now = 0;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match next_attempt(created, attempts, now, 72) {
                RetryDecision::RetryAt(t) => now = t,
                RetryDecision::GiveUp => break,
            }
        }
        // 6 scheduled steps (7h45m) plus 4-hourly tries to 72h, plus the final one.
        assert!((20..=25).contains(&attempts), "{attempts}");
    }
}
