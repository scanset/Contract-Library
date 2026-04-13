//! HTTP Probe command executor.
//!
//! Uses curl for HTTP requests. Cross-platform.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions (cross-platform)
///
/// pub mod http;
//  pub use http::create_curl_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for curl (HTTP probing).
pub fn create_curl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(15));
    executor.allow_commands(&[
        "curl",
        "/usr/bin/curl",
        "/usr/local/bin/curl",
    ]);
    executor
}
