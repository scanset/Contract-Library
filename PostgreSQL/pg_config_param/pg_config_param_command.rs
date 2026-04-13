//! PostgreSQL command executors for compliance scanning.
//!
//! Provides whitelisted command executors for PostgreSQL checks.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod pg;
//  pub use pg::create_psql_executor;
//
//////////////////////////////////////////////////////
//! Cross-platform: psql paths for RHEL, Debian, and generic PATH.
//!
//! Authentication:
//!   - Default: peer auth via `-U postgres` (no password needed)
//!   - Optional: set ESP_PG_PASS in the agent's environment. On each
//!     psql call, the executor reads it and injects it as PGPASSWORD
//!     into the spawned process. Supports credential rotation without
//!     agent restart. The value never appears in policy files or evidence.

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for psql
///
/// Maps ESP_PG_PASS -> PGPASSWORD via dynamic env resolution.
/// On each execute(), reads ESP_PG_PASS from the agent's current
/// environment and passes it as PGPASSWORD to the child psql process.
/// If ESP_PG_PASS is not set, the mapping is skipped and psql falls
/// back to pg_hba.conf peer auth.
pub fn create_psql_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "psql",
        // RHEL / Rocky / CentOS
        "/usr/pgsql-16/bin/psql",
        "/usr/pgsql-15/bin/psql",
        "/usr/pgsql-14/bin/psql",
        // Debian / Ubuntu
        "/usr/lib/postgresql/16/bin/psql",
        "/usr/lib/postgresql/15/bin/psql",
        "/usr/lib/postgresql/14/bin/psql",
        // Common alternative
        "/usr/bin/psql",
    ]);

    // Extend PATH to include common PostgreSQL bin directories.
    // The base executor sets PATH=/usr/bin:/bin:/usr/sbin:/sbin which
    // doesn't include vendor-specific PG paths like /usr/pgsql-16/bin/.
    executor.set_env(
        "PATH",
        concat!(
            "/usr/pgsql-16/bin:/usr/pgsql-15/bin:/usr/pgsql-14/bin:",
            "/usr/lib/postgresql/16/bin:/usr/lib/postgresql/15/bin:/usr/lib/postgresql/14/bin:",
            "/usr/bin:/bin:/usr/sbin:/sbin"
        ),
    );

    // Dynamic mapping: resolve ESP_PG_PASS -> PGPASSWORD on each call
    executor.set_env_from("PGPASSWORD", "ESP_PG_PASS");

    executor
}
