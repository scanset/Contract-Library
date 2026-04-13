//! AWS KMS Key Collector
//!
//! Three API calls:
//! 1. kms describe-key             → key metadata
//! 2. kms get-key-rotation-status  → rotation enabled, period
//! 3. kms get-key-policy           → key policy (JSON string → parsed)
//!
//! key_id must be key ID or ARN — NOT alias.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! KeyMetadata.KeyId                    → "aaaaaaaa-bbbb-..."
//! KeyMetadata.Enabled                  → true
//! KeyMetadata.KeyState                 → "Enabled"
//! KeyMetadata.KeyUsage                 → "ENCRYPT_DECRYPT"
//! KeyMetadata.KeyManager               → "CUSTOMER"
//! RotationStatus.KeyRotationEnabled    → true
//! RotationStatus.RotationPeriodInDays  → 90
//! KeyPolicy.Statement.0.Sid            → "RootAccountFullAccess"
//! KeyPolicy.Statement.0.Effect         → "Allow"
//! KeyPolicy.Statement.1.Sid            → "SecretsManagerAccess"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_kms_key;
//  pub use aws_kms_key::AwsKmsKeyCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsKmsKeyCollector {
    id: String,
}

impl AwsKmsKeyCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_kms_key_collector".to_string(),
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

    fn is_not_found_error(err_str: &str) -> bool {
        err_str.contains("NotFoundException") || err_str.contains("KeyNotFound")
    }
}

impl Default for AwsKmsKeyCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsKmsKeyCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let key_id = self.extract_string_field(object, "key_id").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'key_id' is required for aws_kms_key (must be key ID or ARN, not alias)"
                    .to_string(),
            }
        })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_kms_key".to_string(),
            self.id.clone(),
        );

        let target = format!("kms:{}", key_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query KMS key configuration, rotation status, and key policy via AWS CLI")
            .target(&target)
            .command("aws kms describe-key + get-key-rotation-status + get-key-policy")
            .input("key_id", &key_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let key_args = ["--key-id", key_id.as_str()];

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut key_metadata_val = serde_json::json!({});
        let mut rotation_status_val = serde_json::json!({});
        let mut key_policy_val = serde_json::json!({});

        // ====================================================================
        // Command 1: describe-key
        // ====================================================================
        match client.execute("kms", "describe-key", &key_args) {
            Ok(resp) => {
                let metadata = resp
                    .get("KeyMetadata")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));
                key_metadata_val = metadata.clone();

                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = metadata
                    .get("KeyId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("key_id".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = metadata
                    .get("Arn")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("key_arn".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = metadata
                    .get("Enabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("enabled".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = metadata
                    .get("KeyState")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "key_state".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = metadata
                    .get("KeyUsage")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "key_usage".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = metadata
                    .get("KeySpec")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("key_spec".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = metadata
                    .get("KeyManager")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "key_manager".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = metadata
                    .get("Origin")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("origin".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = metadata
                    .get("MultiRegion")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("multi_region".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = metadata
                    .get("Description")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "description".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_found_error(&err_str) {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                    let empty = RecordData::from_json_value(serde_json::json!({}));
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(empty)),
                    );
                    return Ok(data);
                }
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-key): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: get-key-rotation-status
        // ====================================================================
        match client.execute("kms", "get-key-rotation-status", &key_args) {
            Ok(resp) => {
                rotation_status_val = resp.clone();

                if let Some(v) = resp
                    .get("KeyRotationEnabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("rotation_enabled".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = resp
                    .get("RotationPeriodInDays")
                    .and_then(|v: &serde_json::Value| v.as_i64())
                {
                    data.add_field(
                        "rotation_period_in_days".to_string(),
                        ResolvedValue::Integer(v),
                    );
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-key-rotation-status): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 3: get-key-policy
        // ====================================================================
        let policy_args = ["--key-id", key_id.as_str(), "--policy-name", "default"];
        match client.execute("kms", "get-key-policy", &policy_args) {
            Ok(resp) => {
                if let Some(policy_str) = resp
                    .get("Policy")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(policy_str) {
                        key_policy_val = parsed;
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-key-policy): {}", e),
                });
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "KeyMetadata": key_metadata_val,
            "RotationStatus": rotation_status_val,
            "KeyPolicy": key_policy_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_kms_key".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_kms_key" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_kms_key', got '{}'",
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
            AwsKmsKeyCollector::new().collector_id(),
            "aws_kms_key_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsKmsKeyCollector::new().supported_ctn_types(),
            vec!["aws_kms_key"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsKmsKeyCollector::is_not_found_error("NotFoundException"));
        assert!(!AwsKmsKeyCollector::is_not_found_error("AccessDenied"));
    }
}
