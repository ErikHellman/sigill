//! The outbound MTA: dispatcher, delivery workers, SMTP client, DNS, MTA-STS and
//! per-domain throttling.

pub mod client;
pub mod deliver;
pub mod dispatcher;
pub mod dns;
pub mod mta_sts;
pub mod pool;
pub mod throttle;

pub use deliver::{Job, Mta};
pub use dispatcher::Dispatcher;
