//! AWS IAM User Collector
//!
//! Three API calls (Commands 2 and 3 skipped if user not found):
//! 1. iam get-user --user-name <n>                    → user metadata
//! 2. iam list-user-policies --user-name <n>          → inline policy names
//! 3. iam list-attached-user-policies --user-name <n> → managed policy attachments
//!
//! RecordData merge (mirrors aws_iam_role pattern):
//!   User object (from get-user response["User"])
//!   + InlinePolicyNames (from list-user-policies response["PolicyNames"])
//!   + AttachedPolicies  (from list-attached-user-policies response["AttachedPolicies"])
//!
//! Tags are flattened: [{Key, Value}] → tag_key:<Key> scalars.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! UserName                         → "example-org-esp-scanner"
//! Arn                              → "arn:aws:iam::123456789012:user/esp/..."
//! Path                             → "/esp/"
//! UserId                           → "AIDAXCKLYU6GDIZA6BTVK"
//! Tags.0.Key                       → "Purpose"
//! Tags.0.Value                     → "ESP AWS daemon dev container identity"
//! InlinePolicyNames.0              → "example-org-esp-scanner-policy"
//! AttachedPolicies.0.PolicyName    → (managed policy name if any)
//! AttachedPolicies.0.PolicyArn     → (managed policy ARN if any)
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_iam_user;
//  pub use aws_iam_user::AwsIamUserCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsIamUserCollector {
    id: String,
}

impl AwsIamUserCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_iam_user_collector".to_string(),
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
        err_str.contains("NoSuchEntity") || err_str.contains("not found")
    }
}

impl Default for AwsIamUserCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsIamUserCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let user_name = self
            .extract_string_field(object, "user_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'user_name' is required for aws_iam_user".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_iam_user".to_string(),
            self.id.clone(),
        );

        let target = format!("iam-user:{}", user_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query IAM user configuration via AWS CLI (get-user + list-user-policies + list-attached-user-policies)")
            .target(&target)
            .command("aws iam get-user")
            .input("user_name", &user_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let user_args = ["--user-name", user_name.as_str()];

        // ====================================================================
        // Command 1: get-user
        // ====================================================================
        let user_obj = match client.execute("iam", "get-user", &user_args) {
            Ok(resp) => {
                let user = resp.get("User").cloned().unwrap_or(serde_json::json!({}));

                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = user
                    .get("UserName")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "user_name".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = user.get("Arn").and_then(|v: &serde_json::Value| v.as_str()) {
                    data.add_field("user_arn".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = user
                    .get("Path")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("path".to_string(), ResolvedValue::String(v.to_string()));
                }

                // Tags flat map
                if let Some(tags) = user
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

                user
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
                    reason: format!("AWS API error (get-user): {}", e),
                });
            }
        };

        // ====================================================================
        // Command 2: list-user-policies (inline)
        // ====================================================================
        let inline_policy_names = match client.execute("iam", "list-user-policies", &user_args) {
            Ok(resp) => {
                let names = resp
                    .get("PolicyNames")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let count = names.len() as i64;
                data.add_field(
                    "inline_policy_count".to_string(),
                    ResolvedValue::Integer(count),
                );
                serde_json::Value::Array(names)
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-user-policies): {}", e),
                });
            }
        };

        // ====================================================================
        // Command 3: list-attached-user-policies (managed)
        // ====================================================================
        let attached_policies =
            match client.execute("iam", "list-attached-user-policies", &user_args) {
                Ok(resp) => {
                    let policies = resp
                        .get("AttachedPolicies")
                        .and_then(|v: &serde_json::Value| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let count = policies.len() as i64;
                    data.add_field(
                        "attached_policy_count".to_string(),
                        ResolvedValue::Integer(count),
                    );
                    serde_json::Value::Array(policies)
                }
                Err(e) => {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (list-attached-user-policies): {}", e),
                    });
                }
            };

        // ====================================================================
        // Build merged RecordData (mirrors aws_iam_role pattern)
        // ====================================================================
        let mut merged = user_obj.clone();
        merged["InlinePolicyNames"] = inline_policy_names;
        merged["AttachedPolicies"] = attached_policies;

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_iam_user".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_iam_user" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_iam_user', got '{}'",
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
            AwsIamUserCollector::new().collector_id(),
            "aws_iam_user_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsIamUserCollector::new().supported_ctn_types(),
            vec!["aws_iam_user"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsIamUserCollector::is_not_found_error("NoSuchEntity"));
        assert!(!AwsIamUserCollector::is_not_found_error("AccessDenied"));
    }
}
