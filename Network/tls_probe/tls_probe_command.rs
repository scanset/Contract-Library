//! TLS Probe command executor.
//!
//! Uses openssl s_client + sh for pipe handling.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions (cross-platform)
///
/// pub mod tls;
//  pub use tls::create_tls_probe_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for TLS probing.
/// Needs sh (for pipe) and openssl s_client.
pub fn create_tls_probe_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "sh",
        "/bin/sh",
        "/usr/bin/sh",
        "openssl",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
    ]);
    executor
}
