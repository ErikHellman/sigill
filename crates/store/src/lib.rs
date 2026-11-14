//! SQLite storage for Sigill: connection setup, embedded migrations and every query.
//!
//! One writer pool with a single connection serialises all writes; a separate read pool
//! serves queries. Both use WAL mode, so reads never wait for the writer.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};

pub mod admin;
pub mod apps;
pub mod broadcasts;
pub mod contacts;
pub mod dmarc;
pub mod events;
pub mod feedback;
pub mod health;
pub mod messages;
pub mod queue;
pub mod retention;
pub mod setup;
pub mod suppressions;
pub mod templates;
pub mod throttle;
pub mod webhooks;

pub use sqlx;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid stored value: {0}")]
    Invalid(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Parse a text column into one of the core enums.
pub(crate) fn parse<T: FromStr>(s: &str) -> Result<T> {
    s.parse().map_err(|_| Error::Invalid(s.to_string()))
}

/// Handles to the writer and reader pools.
#[derive(Clone, Debug)]
pub struct Store {
    pub write: SqlitePool,
    pub read: SqlitePool,
}

fn options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5000))
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
}

impl Store {
    /// Open (creating if needed) the database file and run pending migrations.
    pub async fn open(path: &Path, read_connections: u32) -> Result<Self> {
        let write = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect_with(options(path))
            .await?;
        MIGRATOR.run(&write).await?;
        let read = SqlitePoolOptions::new()
            .max_connections(read_connections.max(1))
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(path)
                    .read_only(true)
                    .busy_timeout(Duration::from_millis(5000))
                    .foreign_keys(true),
            )
            .await?;
        Ok(Self { write, read })
    }

    /// Run pending migrations only (used by `sigill migrate`).
    pub async fn migrate(path: &Path) -> Result<()> {
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options(path)).await?;
        MIGRATOR.run(&pool).await?;
        pool.close().await;
        Ok(())
    }

    pub async fn close(&self) {
        self.write.close().await;
        self.read.close().await;
    }

    /// Check that the database answers (used by `/healthz`).
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.read).await?;
        Ok(())
    }
}

/// Helpers for tests in this and other crates: a fresh temp-file database per test.
pub mod testing {
    use super::*;

    pub struct TestDb {
        pub store: Store,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for TestDb {
        type Target = Store;
        fn deref(&self) -> &Store {
            &self.store
        }
    }

    pub async fn test_db() -> TestDb {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("test.db"), 2).await.expect("open db");
        TestDb { store, _dir: dir }
    }
}
