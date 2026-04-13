//! Azure CLI Client
//!
//! Thin wrapper around `Command::new("az")` mirroring the AwsClient pattern.
//! Authentication is via environment (az login already done via SPN).
//!
//! Usage:
//!   let client = AzClient::new();
//!   let resp = client.execute(&["ad", "app", "show", "--id", "c79bed94-..."])?;

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod az_entra_application;
//  pub use az_entra_application::AzEntraApplicationCollector;
//
//////////////////////////////////////////////////////

use serde_json::Value;
use std::process::Command;

#[derive(Debug)]
pub enum AzError {
    CommandFailed(String),
    JsonParse(String),
    NotFound,
}

impl std::fmt::Display for AzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AzError::CommandFailed(s) => write!(f, "az command failed: {}", s),
            AzError::JsonParse(s) => write!(f, "JSON parse error: {}", s),
            AzError::NotFound => write!(f, "resource not found"),
        }
    }
}

pub struct AzClient;

impl AzClient {
    pub fn new() -> Self {
        Self
    }

    /// Execute an `az` command with the given args.
    /// Always appends `--output json` unless already present.
    pub fn execute(&self, args: &[&str]) -> Result<Value, AzError> {
        let mut cmd = Command::new("az");
        cmd.args(args);

        // Ensure JSON output
        if !args.contains(&"--output") && !args.contains(&"-o") {
            cmd.args(["--output", "json"]);
        }

        let output = cmd
            .output()
            .map_err(|e| AzError::CommandFailed(format!("failed to spawn az: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if stderr.contains("does not exist")
                || stderr.contains("Not Found")
                || stderr.contains("Resource 'microsoft.graph")
            {
                return Err(AzError::NotFound);
            }
            return Err(AzError::CommandFailed(stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&stdout).map_err(|e| AzError::JsonParse(format!("{}: {}", e, stdout)))
    }
}

impl Default for AzClient {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// az_entra_application collector
// =============================================================================
//
// Azure Entra ID Application Registration Collector
//
// Lookup by display_name: az ad app list --display-name <n>  → takes first result
// Lookup by client_id:    az ad app show --id <client_id>
//
// Tags are a flat string array — not [{Key,Value}] like AWS.
//   ["esp-daemon","fedramp","example-org"]
//   Access via record check: field tags.* string = `fedramp` at_least_one
//
// ## RecordData Field Paths
//
// ```text
// appId                                    → "d4e5f6a7-b8c9-0123-4567-890abcdef012"
// id                                       → "e5f6a7b8-c901-2345-6789-0abcdef01234"
// displayName                              → "example-org-esp-daemon"
// signInAudience                           → "AzureADMyOrg"
// publisherDomain                          → "binarysparklabs.com"
// tags.0                                   → "esp-daemon"
// tags.1                                   → "fedramp"
// tags.*                                   → (all tags via wildcard)
// passwordCredentials.0.displayName        → "esp-daemon-secret"
// passwordCredentials.0.endDateTime        → "2027-01-01T00:00:00Z"
// requiredResourceAccess.0.resourceAppId   → "00000003-0000-0000-c000-000000000000"
// ```

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

pub struct AzEntraApplicationCollector {
    id: String,
}

impl AzEntraApplicationCollector {
    pub fn new() -> Self {
        Self {
            id: "az_entra_application_collector".to_string(),
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }
}

impl Default for AzEntraApplicationCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AzEntraApplicationCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let display_name = self.extract_string_field(object, "display_name");
        let client_id = self.extract_string_field(object, "client_id");

        if display_name.is_none() && client_id.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'display_name' or 'client_id' is required for az_entra_application".to_string(),
            });
        }

        let client = AzClient::new();

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_application".to_string(),
            self.id.clone(),
        );

        let target = client_id
            .as_ref()
            .map(|id| format!("entra-app:{}", id))
            .or_else(|| {
                display_name
                    .as_ref()
                    .map(|n| format!("entra-app:name:{}", n))
            })
            .unwrap();

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Entra ID app registration via Azure CLI")
            .target(&target)
            .command("az ad app");
        if let Some(ref n) = display_name {
            method_builder = method_builder.input("display_name", n);
        }
        if let Some(ref id) = client_id {
            method_builder = method_builder.input("client_id", id);
        }
        data.set_method(method_builder.build());

        // Execute lookup
        let app_result = if let Some(ref id) = client_id {
            client.execute(&["ad", "app", "show", "--id", id.as_str()])
        } else {
            let name = display_name.as_ref().unwrap();
            match client.execute(&["ad", "app", "list", "--display-name", name.as_str()]) {
                Ok(arr) => {
                    // list returns an array — take first element
                    if let Some(first) = arr.as_array().and_then(|a| a.first()).cloned() {
                        Ok(first)
                    } else {
                        Err(AzError::NotFound)
                    }
                }
                Err(e) => Err(e),
            }
        };

        match app_result {
            Err(AzError::NotFound) | Err(AzError::CommandFailed(_))
                if { matches!(app_result, Err(AzError::NotFound)) } =>
            {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Azure CLI error (az ad app): {}", e),
                });
            }
            Ok(app) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = app
                    .get("appId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("app_id".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = app.get("id").and_then(|v: &serde_json::Value| v.as_str()) {
                    data.add_field(
                        "object_id".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = app
                    .get("displayName")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "display_name".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = app
                    .get("signInAudience")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "sign_in_audience".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = app
                    .get("publisherDomain")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "publisher_domain".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }

                // Password credentials
                let pwd_count = app
                    .get("passwordCredentials")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .map(|a| a.len() as i64)
                    .unwrap_or(0);
                data.add_field(
                    "password_credential_count".to_string(),
                    ResolvedValue::Integer(pwd_count),
                );
                data.add_field(
                    "has_password_credentials".to_string(),
                    ResolvedValue::Boolean(pwd_count > 0),
                );

                let record_data = RecordData::from_json_value(app.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_entra_application".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_entra_application" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_entra_application', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }
    fn supports_batch_collection(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_id() {
        assert_eq!(
            AzEntraApplicationCollector::new().collector_id(),
            "az_entra_application_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AzEntraApplicationCollector::new().supported_ctn_types(),
            vec!["az_entra_application"]
        );
    }
}
