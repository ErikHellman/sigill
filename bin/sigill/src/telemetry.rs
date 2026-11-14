//! Vaka error reporting and JSON logging.
//!
//! Never put recipient addresses, subjects or bodies into log fields: every `tracing`
//! event also becomes a Vaka breadcrumb. Use message/delivery ids and recipient domains.

use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

/// Start Vaka (key, endpoint and environment from `VAKA_*` env vars; a no-op without a key).
pub fn init_vaka() -> vaka_sdk::Guard {
    vaka_sdk::init(vaka_sdk::Config {
        release: Some(env!("CARGO_PKG_VERSION").into()),
        debug: std::env::var_os("VAKA_DEBUG").is_some(),
        ..Default::default()
    })
}

/// JSON logs to stdout plus the Vaka layer. Filter with `SIGILL_LOG` (default `info`),
/// using `tracing` target syntax such as `info,sigill_mta=debug`.
pub fn init_tracing() {
    let filter: Targets = std::env::var("SIGILL_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "info".parse().expect("valid default filter"));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json().with_current_span(true).with_span_list(false))
        .with(vaka_sdk::tracing_layer::VakaLayer::default())
        .with(filter)
        .init();
}
