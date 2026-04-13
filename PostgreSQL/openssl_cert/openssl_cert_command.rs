//! OpenSSL command executor for certificate inspection.
//!
//! Cross-platform: openssl is available on Linux, macOS, and Windows.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions (add to commands/mod.rs)
///
/// pub mod openssl;
//  pub use openssl::create_openssl_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for openssl
pub fn create_openssl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "openssl",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
    ]);
    executor
}
