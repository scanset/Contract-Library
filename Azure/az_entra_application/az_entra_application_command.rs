//! Azure Entra Application Command Module
//!
//! Extracted from commands/az.rs — contains the AzClient and AzError types
//! needed by the az_entra_application collector.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod az;
//  pub use az::AzClient;
//  pub use az::AzError;
//
//////////////////////////////////////////////////////

use serde_json::Value;
use std::process::Command;

// =============================================================================
// Error type
// =============================================================================

#[derive(Debug)]
pub enum AzError {
    /// The resource was not found (non-fatal — results in found=false).
    NotFound,
    /// The az command exited non-zero for a non-404 reason.
    CommandFailed(String),
    /// The command stdout could not be parsed as JSON.
    JsonParse(String),
}

impl std::fmt::Display for AzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AzError::NotFound => write!(f, "resource not found"),
            AzError::CommandFailed(s) => write!(f, "az command failed: {}", s),
            AzError::JsonParse(s) => write!(f, "JSON parse error: {}", s),
        }
    }
}

impl std::error::Error for AzError {}

// =============================================================================
// Client
// =============================================================================

pub struct AzClient;

impl AzClient {
    pub fn new() -> Self {
        Self
    }

    /// Execute an `az` command with the given arguments.
    ///
    /// `--output json` is appended automatically unless already present.
    ///
    /// Returns the parsed JSON response on success, or an `AzError` on failure.
    pub fn execute(&self, args: &[&str]) -> Result<Value, AzError> {
        let mut cmd = Command::new("az");
        cmd.args(args);

        // Ensure JSON output unless caller already specified --output or -o
        if !args.contains(&"--output") && !args.contains(&"-o") {
            cmd.args(["--output", "json"]);
        }

        let output = cmd
            .output()
            .map_err(|e| AzError::CommandFailed(format!("failed to spawn az: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if Self::is_not_found_stderr(&stderr) {
                return Err(AzError::NotFound);
            }
            return Err(AzError::CommandFailed(stderr.trim().to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Empty stdout is valid for some delete operations — return empty object
        if stdout.trim().is_empty() {
            return Ok(Value::Object(serde_json::Map::new()));
        }

        serde_json::from_str(&stdout)
            .map_err(|e| AzError::JsonParse(format!("{}: raw={}", e, stdout.trim())))
    }

    /// Returns true when stderr indicates the resource was not found.
    fn is_not_found_stderr(stderr: &str) -> bool {
        stderr.contains("does not exist")
            || stderr.contains("Not Found")
            || stderr.contains("Resource 'microsoft.graph")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("(NotFound)")
            || stderr.contains("404")
    }
}

impl Default for AzClient {
    fn default() -> Self {
        Self::new()
    }
}
