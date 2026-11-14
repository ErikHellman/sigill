//! Bounce and complaint handling: a receive-only SMTP listener for the bounce domains,
//! DSN and ARF parsing, DMARC aggregate report ingestion, and the store updates that follow (suppressions, events, webhooks).

pub mod dmarc;
pub mod listener;
pub mod parse;
pub mod process;

pub use listener::{Listener, Settings, load_tls};
pub use process::{Processor, Summary, Target};
