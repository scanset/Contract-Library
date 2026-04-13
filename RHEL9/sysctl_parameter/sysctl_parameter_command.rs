//! Sysctl Parameter Command Module
//!
//! Extracted from commands/r9.rs — contains only the executor factory
//! needed by the sysctl_parameter collector: create_sysctl_executor.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod r9;
//  pub use r9::{
//      create_crypto_policy_executor, create_fips_executor,
//      create_rpm_executor, create_sysctl_executor, create_systemctl_executor,
//  };
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for sysctl
pub fn create_sysctl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));
    executor.allow_commands(&["sysctl", "/usr/sbin/sysctl", "/sbin/sysctl"]);
    executor
}
