//! Mount Point command executor.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions (add to commands/r9.rs)
///
/// pub use r9::create_findmnt_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for findmnt
pub fn create_findmnt_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));
    executor.allow_commands(&["findmnt", "/usr/bin/findmnt", "/bin/findmnt"]);
    executor
}
