//! AWS IAM Role Collector
//!
//! Collects IAM Role configuration from AWS CLI via three API calls:
//! 1. `iam get-role` — role config, trust policy, metadata
//! 2. `iam list-attached-role-policies` — managed policy attachments
//! 3. `iam list-role-policies` — inline policy names
//!
//! The RecordData merges all three: role fields at top level, plus
//! `AttachedPolicies` array and `InlinePolicyNames` array.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! RoleName                                                    → "example-node-role"
//! Arn                                                         → "arn:aws:iam::123456789012:role/example-node-role"
//! AssumeRolePolicyDocument.Statement.0.Principal.Service      → "ec2.amazonaws.com"
//! AssumeRolePolicyDocument.Statement.0.Action                 → "sts:AssumeRole"
//! AttachedPolicies.0.PolicyName                               → "AmazonEKS_CNI_Policy"
//! AttachedPolicies.0.PolicyArn                                → "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
//! AttachedPolicies.*.PolicyName                               → all managed policy names
//! InlinePolicyNames                                           → [] (empty array)
//! MaxSessionDuration                                          → 3600
//! Tags.0.Key                                                  → "Project"
//! Tags.0.Value                                                → "scanset"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_iam_role;
//  pub use aws_iam_role::AwsIamRoleCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS IAM Role information
pub struct AwsIamRoleCollector {
    id: String,
}

impl AwsIamRoleCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_iam_role_collector".to_string(),
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

impl Default for AwsIamRoleCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsIamRoleCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let role_name = self
            .extract_string_field(object, "role_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'role_name' is required for aws_iam_role".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_iam_role".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = format!("iam-role:{}", role_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query IAM role configuration via AWS CLI (get-role + list-attached-role-policies + list-role-policies)")
            .target(&target)
            .command("aws iam get-role")
            .input("role_name", &role_name);

        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        // Step 1: get-role
        let get_role_args = vec!["--role-name", role_name.as_str()];
        let get_role_response = client.execute("iam", "get-role", &get_role_args);

        let role = match get_role_response {
            Ok(response) => response.get("Role").cloned(),
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("NoSuchEntity") {
                    None
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (get-role): {}", e),
                    });
                }
            }
        };

        if let Some(role) = role {
            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Scalar fields from get-role
            if let Some(name) = role
                .get("RoleName")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "role_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }

            if let Some(arn) = role.get("Arn").and_then(|v: &serde_json::Value| v.as_str()) {
                data.add_field(
                    "role_arn".to_string(),
                    ResolvedValue::String(arn.to_string()),
                );
            }

            if let Some(path) = role
                .get("Path")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field("path".to_string(), ResolvedValue::String(path.to_string()));
            }

            if let Some(msd) = role
                .get("MaxSessionDuration")
                .and_then(|v: &serde_json::Value| v.as_i64())
            {
                data.add_field(
                    "max_session_duration".to_string(),
                    ResolvedValue::Integer(msd),
                );
            }

            // Step 2: list-attached-role-policies
            let attached_args = vec!["--role-name", role_name.as_str()];
            let attached_response = client
                .execute("iam", "list-attached-role-policies", &attached_args)
                .map_err(|e| CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-attached-role-policies): {}", e),
                })?;

            let attached_policies = attached_response
                .get("AttachedPolicies")
                .cloned()
                .unwrap_or(serde_json::json!([]));

            let attached_count = attached_policies
                .as_array()
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);

            data.add_field(
                "attached_policy_count".to_string(),
                ResolvedValue::Integer(attached_count),
            );

            // Step 3: list-role-policies (inline)
            let inline_args = vec!["--role-name", role_name.as_str()];
            let inline_response = client
                .execute("iam", "list-role-policies", &inline_args)
                .map_err(|e| CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-role-policies): {}", e),
                })?;

            let inline_policy_names = inline_response
                .get("PolicyNames")
                .cloned()
                .unwrap_or(serde_json::json!([]));

            let inline_count = inline_policy_names
                .as_array()
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);

            data.add_field(
                "inline_policy_count".to_string(),
                ResolvedValue::Integer(inline_count),
            );

            // Build merged RecordData: role fields + AttachedPolicies + InlinePolicyNames
            let mut merged = role.clone();
            if let serde_json::Value::Object(ref mut map) = merged {
                map.insert("AttachedPolicies".to_string(), attached_policies);
                map.insert("InlinePolicyNames".to_string(), inline_policy_names);
            }

            let record_data = RecordData::from_json_value(merged);
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );
        } else {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_iam_role".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_iam_role" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_iam_role', got '{}'",
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
        let collector = AwsIamRoleCollector::new();
        assert_eq!(collector.collector_id(), "aws_iam_role_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsIamRoleCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_iam_role"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsIamRoleCollector::default();
        assert_eq!(collector.collector_id(), "aws_iam_role_collector");
    }
}
