//! Apache httpd command executor.
//!
//! Allows httpd and apachectl for module listing and config checks.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod apache;
//  pub use apache::create_httpd_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for httpd/apachectl.
pub fn create_httpd_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "httpd",
        "/usr/sbin/httpd",
        "apachectl",
        "/usr/sbin/apachectl",
        "/usr/bin/apachectl",
    ]);
    executor
}
