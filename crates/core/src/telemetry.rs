//! Analytics and error hooks. Library crates call these; the binary installs Vaka behind
//! them, so only the binary depends on the SDK. Never pass recipient addresses, subjects
//! or bodies: use ids, streams and recipient domains.

use std::sync::OnceLock;

type TrackFn = fn(&str, &[(&str, &str)]);
type ErrorFn = fn(&(dyn std::error::Error + 'static));

static TRACK: OnceLock<TrackFn> = OnceLock::new();
static CAPTURE: OnceLock<ErrorFn> = OnceLock::new();

/// Install the analytics and error hooks (once, at startup).
pub fn install(track: TrackFn, capture: ErrorFn) {
    let _ = TRACK.set(track);
    let _ = CAPTURE.set(capture);
}

/// Record an analytics event.
pub fn track(name: &str, props: &[(&str, &str)]) {
    if let Some(f) = TRACK.get() {
        f(name, props);
    }
}

/// Report a handled error.
pub fn capture_error(err: &(dyn std::error::Error + 'static)) {
    if let Some(f) = CAPTURE.get() {
        f(err);
    }
}
