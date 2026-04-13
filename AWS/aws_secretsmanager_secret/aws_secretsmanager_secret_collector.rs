//! AWS Secrets Manager Secret Collector
//!
//! Single API call: secretsmanager describe-secret --secret-id <secret_id>
//!
//! secret_id can be secret name or ARN.
//! Tags are [{Key, Value}] → flattened to tag_key:<Key> scalars.
//! has_current_version: true when any VersionIdsToStages value contains "AWSCURRENT".
//! rotation_enabled: true only when RotationEnabled field is present and true.
//! RecoveryWindowInDays is NOT returned by describe-secret (creation parameter only).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_secretsmanager_secret;
//  pub use aws_secretsmanager_secret::AwsSecretsmanagerSecretCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsSecretsmanagerSecretCollector {
    id: String,
}

impl AwsSecretsmanagerSecretCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_secretsmanager_secret_collector".to_string(),
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
        err_str.contains("ResourceNotFoundException") || err_str.contains("SecretNotFound")
    }
}

impl Default for AwsSecretsmanagerSecretCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSecretsmanagerSecretCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let secret_id = self
            .extract_string_field(object, "secret_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'secret_id' is required for aws_secretsmanager_secret".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_secretsmanager_secret".to_string(),
            self.id.clone(),
        );

        let target = format!("secretsmanager:{}", secret_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Secrets Manager secret metadata via AWS CLI")
            .target(&target)
            .command("aws secretsmanager describe-secret")
            .input("secret_id", &secret_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--secret-id", secret_id.as_str()];

        match client.execute("secretsmanager", "describe-secret", &args) {
            Ok(resp) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = resp
                    .get("Name")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "secret_name".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp.get("ARN").and_then(|v: &serde_json::Value| v.as_str()) {
                    data.add_field(
                        "secret_arn".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("KmsKeyId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "kms_key_id".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("Description")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "description".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }

                // rotation_enabled — absent means false
                let rotation_enabled = resp
                    .get("RotationEnabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                    .unwrap_or(false);
                data.add_field(
                    "rotation_enabled".to_string(),
                    ResolvedValue::Boolean(rotation_enabled),
                );

                // has_current_version — any version with AWSCURRENT stage
                let has_current = resp
                    .get("VersionIdsToStages")
                    .and_then(|v: &serde_json::Value| v.as_object())
                    .map(|versions| {
                        versions.values().any(|stages| {
                            stages
                                .as_array()
                                .map(|arr| arr.iter().any(|s| s.as_str() == Some("AWSCURRENT")))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                data.add_field(
                    "has_current_version".to_string(),
                    ResolvedValue::Boolean(has_current),
                );

                // Tags flat map
                if let Some(tags) = resp
                    .get("Tags")
                    .and_then(|v: &serde_json::Value| v.as_array())
                {
                    for tag in tags {
                        let key = tag
                            .get("Key")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("");
                        let val = tag
                            .get("Value")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("");
                        if !key.is_empty() {
                            data.add_field(
                                format!("tag_key:{}", key),
                                ResolvedValue::String(val.to_string()),
                            );
                        }
                    }
                }

                let record_data = RecordData::from_json_value(resp.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
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
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (describe-secret): {}", e),
                    });
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_secretsmanager_secret".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_secretsmanager_secret" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_secretsmanager_secret', got '{}'",
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
            AwsSecretsmanagerSecretCollector::new().collector_id(),
            "aws_secretsmanager_secret_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsSecretsmanagerSecretCollector::new().supported_ctn_types(),
            vec!["aws_secretsmanager_secret"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsSecretsmanagerSecretCollector::is_not_found_error(
            "ResourceNotFoundException"
        ));
        assert!(AwsSecretsmanagerSecretCollector::is_not_found_error(
            "SecretNotFound"
        ));
        assert!(!AwsSecretsmanagerSecretCollector::is_not_found_error(
            "AccessDenied"
        ));
    }
}
