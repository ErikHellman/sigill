//! Domain types, configuration and logic shared by every Sigill crate.

pub mod address;
pub mod config;
pub mod reply;
pub mod retry;
pub mod secrets;
pub mod telemetry;
pub mod types;
pub mod verp;

pub use config::Config;
pub use types::*;

/// New UUIDv7 id as hyphenated text, the form stored in SQLite.
pub fn new_id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

/// Current time in unix milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub const MINUTE_MS: i64 = 60_000;
pub const HOUR_MS: i64 = 60 * MINUTE_MS;
pub const DAY_MS: i64 = 24 * HOUR_MS;
