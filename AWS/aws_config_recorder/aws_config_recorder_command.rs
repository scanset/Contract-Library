//! AWS aws_config_recorder Command Module
//!
//! Extracted from commands/aws.rs — AwsClient base used by the aws_config_recorder collector.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws;
//  pub use aws::{AwsClient, AwsError, AwsResult};
//
//////////////////////////////////////////////////////

use serde::Deserialize;
use serde_json::Value;
use std::process::Command;
use std::time::Duration;

/// Default timeout for AWS CLI commands (30 seconds)
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// AWS CLI client for executing commands
#[derive(Debug, Clone)]
pub struct AwsClient {
    region: Option<String>,
    #[allow(dead_code)]
    timeout: Duration,
}

impl Default for AwsClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl AwsClient {
    pub fn new(region: Option<String>) -> Self {
        Self {
            region,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    #[allow(dead_code)]
    pub fn with_timeout(region: Option<String>, timeout: Duration) -> Self {
        Self { region, timeout }
    }

    pub fn execute(&self, service: &str, operation: &str, args: &[&str]) -> AwsResult<Value> {
        #[allow(clippy::disallowed_methods)]
        let mut cmd = Command::new("aws");

        cmd.arg(service).arg(operation);

        if let Some(ref region) = self.region {
            cmd.arg("--region").arg(region);
        }

        cmd.arg("--output").arg("json");

        for arg in args {
            cmd.arg(arg);
        }

        let output = cmd.output().map_err(|e| {
            AwsError::CommandFailed(format!("Failed to execute aws command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if stderr.contains("AccessDenied") || stderr.contains("UnauthorizedAccess") {
                return Err(AwsError::AccessDenied(stderr.to_string()));
            }
            if stderr.contains("InvalidParameterValue") || stderr.contains("ValidationError") {
                return Err(AwsError::InvalidParameter(stderr.to_string()));
            }
            if stderr.contains("does not exist") || stderr.contains("not found") {
                return Err(AwsError::ResourceNotFound(stderr.to_string()));
            }

            return Err(AwsError::CommandFailed(format!(
                "AWS CLI command failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.trim().is_empty() {
            return Ok(Value::Object(serde_json::Map::new()));
        }

        serde_json::from_str(&stdout)
            .map_err(|e| AwsError::ParseError(format!("Failed to parse AWS response: {}", e)))
    }

    #[allow(dead_code)]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// AWS resource tag
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Tag {
    pub key: String,
    pub value: String,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug)]
pub enum AwsError {
    CommandFailed(String),
    AccessDenied(String),
    InvalidParameter(String),
    ResourceNotFound(String),
    ParseError(String),
}

impl std::fmt::Display for AwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(msg) => write!(f, "AWS command failed: {}", msg),
            Self::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            Self::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Self::ResourceNotFound(msg) => write!(f, "Resource not found: {}", msg),
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for AwsError {}

pub type AwsResult<T> = Result<T, AwsError>;
