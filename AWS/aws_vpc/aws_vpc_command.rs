//! AWS VPC Command Module
//!
//! Extracted from commands/aws.rs — contains only the types and methods
//! needed by the aws_vpc collector: AwsClient core, describe_vpcs,
//! describe_vpc_attribute, VpcDescription, Tag, AwsError, AwsResult,
//! and parse_tag_filter.

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
// EC2 — VPC Operations
// ============================================================================

impl AwsClient {
    /// Describe VPCs by ID or tag filter
    pub fn describe_vpcs(
        &self,
        vpc_id: Option<&str>,
        filters: Option<&[(&str, &str)]>,
    ) -> AwsResult<Vec<VpcDescription>> {
        let mut args = Vec::new();

        if let Some(id) = vpc_id {
            args.push("--vpc-ids");
            args.push(id);
        }

        let filter_strings: Vec<String>;
        if let Some(f) = filters {
            filter_strings = f
                .iter()
                .map(|(k, v)| format!("Name={},Values={}", k, v))
                .collect();
            for fs in &filter_strings {
                args.push("--filters");
                args.push(fs);
            }
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let response = self.execute("ec2", "describe-vpcs", &args_refs)?;

        let vpcs = response
            .get("Vpcs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        Ok(vpcs)
    }

    /// Describe a VPC attribute (enableDnsSupport, enableDnsHostnames)
    pub fn describe_vpc_attribute(&self, vpc_id: &str, attribute: &str) -> AwsResult<bool> {
        let args = vec!["--vpc-id", vpc_id, "--attribute", attribute];

        let response = self.execute("ec2", "describe-vpc-attribute", &args)?;

        let attr_key = match attribute {
            "enableDnsSupport" => "EnableDnsSupport",
            "enableDnsHostnames" => "EnableDnsHostnames",
            _ => attribute,
        };

        let value = response
            .get(attr_key)
            .and_then(|v| v.get("Value"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(value)
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// VPC description from AWS API
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VpcDescription {
    pub vpc_id: String,
    pub cidr_block: String,
    pub state: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub enable_dns_support: Option<bool>,
    #[serde(default)]
    pub enable_dns_hostnames: Option<bool>,
    #[serde(default)]
    pub tags: Vec<Tag>,
}

impl VpcDescription {
    pub fn name(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.key == "Name")
            .map(|t| t.value.as_str())
    }
}

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

// ============================================================================
// Utility Functions
// ============================================================================

/// Parse a tag filter string (e.g., "Name=my-vpc" or "Environment=prod")
pub fn parse_tag_filter(filter: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = filter.splitn(2, '=').collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}
