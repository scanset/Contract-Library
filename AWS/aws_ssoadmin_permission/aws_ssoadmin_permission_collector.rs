//! AWS SSO Admin Permission Set Collector
//!
//! Four API calls:
//! 1. sso-admin list-permission-sets --instance-arn <arn>
//!    → paginate until finding ARN where describe returns matching Name
//! 2. sso-admin describe-permission-set --instance-arn <arn> --permission-set-arn <ps-arn>
//!    → name, description, session_duration
//! 3. sso-admin list-managed-policies-in-permission-set
//!    → AttachedManagedPolicies array
//! 4. sso-admin get-inline-policy-for-permission-set
//!    → InlinePolicy (JSON string, empty string when not present)
//!
//! ## RecordData Field Paths
//!
//! ```text
//! PermissionSet.Name                        → "ExampleOrgAdmin"
//! PermissionSet.PermissionSetArn            → "arn:aws:sso:::permissionSet/..."
//! PermissionSet.Description                 → "Full admin access..."
//! PermissionSet.SessionDuration             → "PT4H"
//! AttachedManagedPolicies.0.Name            → "AdministratorAccess"
//! AttachedManagedPolicies.0.Arn             → "arn:aws:iam::aws:policy/AdministratorAccess"
//! AttachedManagedPolicies.*.Name            → (all managed policy names)
//! InlinePolicy.Statement.0.Sid              → "EC2ReadOnly"
//! InlinePolicy.Statement.0.Effect           → "Allow"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ssoadmin_permission;
//  pub use aws_ssoadmin_permission::AwsSsoadminPermissionSetCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsSsoadminPermissionSetCollector {
    id: String,
}

impl AwsSsoadminPermissionSetCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_ssoadmin_permission_set_collector".to_string(),
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

    /// Finds the permission set ARN by listing all permission sets and describing each
    /// until one with a matching Name is found.
    fn find_permission_set_arn(
        &self,
        client: &AwsClient,
        instance_arn: &str,
        target_name: &str,
        object_id: &str,
    ) -> Result<Option<String>, CollectionError> {
        let list_args = ["--instance-arn", instance_arn];
        let ps_list = match client.execute("sso-admin", "list-permission-sets", &list_args) {
            Ok(resp) => resp
                .get("PermissionSets")
                .and_then(|v: &serde_json::Value| v.as_array())
                .cloned()
                .unwrap_or_default(),
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object_id.to_string(),
                    reason: format!("AWS API error (list-permission-sets): {}", e),
                });
            }
        };

        for ps_val in &ps_list {
            let ps_arn = match ps_val.as_str() {
                Some(s) => s,
                None => continue,
            };

            let desc_args = [
                "--instance-arn",
                instance_arn,
                "--permission-set-arn",
                ps_arn,
            ];
            if let Ok(resp) = client.execute("sso-admin", "describe-permission-set", &desc_args) {
                let name = resp
                    .get("PermissionSet")
                    .and_then(|v: &serde_json::Value| v.get("Name"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                    .unwrap_or("");
                if name == target_name {
                    return Ok(Some(ps_arn.to_string()));
                }
            }
        }

        Ok(None)
    }
}

impl Default for AwsSsoadminPermissionSetCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSsoadminPermissionSetCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let permission_set_name = self
            .extract_string_field(object, "permission_set_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'permission_set_name' is required for aws_ssoadmin_permission_set"
                    .to_string(),
            })?;

        let instance_arn = self
            .extract_string_field(object, "instance_arn")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'instance_arn' is required for aws_ssoadmin_permission_set".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_ssoadmin_permission_set".to_string(),
            self.id.clone(),
        );

        let target = format!("permission-set:{}", permission_set_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query IAM Identity Center permission set via AWS CLI")
            .target(&target)
            .command("aws sso-admin list-permission-sets + describe-permission-set + list-managed-policies-in-permission-set + get-inline-policy-for-permission-set")
            .input("permission_set_name", &permission_set_name)
            .input("instance_arn", &instance_arn);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // ====================================================================
        // Find ARN by name
        // ====================================================================
        let ps_arn = match self.find_permission_set_arn(
            &client,
            &instance_arn,
            &permission_set_name,
            &object.identifier,
        )? {
            Some(arn) => arn,
            None => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
                return Ok(data);
            }
        };

        let ps_args = [
            "--instance-arn",
            instance_arn.as_str(),
            "--permission-set-arn",
            ps_arn.as_str(),
        ];

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "permission_set_arn".to_string(),
            ResolvedValue::String(ps_arn.clone()),
        );

        // ====================================================================
        // Command 2: describe-permission-set
        // ====================================================================
        let mut ps_metadata_val = serde_json::json!({});
        match client.execute("sso-admin", "describe-permission-set", &ps_args) {
            Ok(resp) => {
                if let Some(ps) = resp.get("PermissionSet") {
                    ps_metadata_val = ps.clone();

                    if let Some(v) = ps.get("Name").and_then(|v: &serde_json::Value| v.as_str()) {
                        data.add_field(
                            "permission_set_name".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                    if let Some(v) = ps
                        .get("Description")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "description".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                    if let Some(v) = ps
                        .get("SessionDuration")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "session_duration".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-permission-set): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 3: list-managed-policies-in-permission-set
        // ====================================================================
        let mut managed_policies_val = serde_json::json!([]);
        match client.execute(
            "sso-admin",
            "list-managed-policies-in-permission-set",
            &ps_args,
        ) {
            Ok(resp) => {
                let policies = resp
                    .get("AttachedManagedPolicies")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let count = policies.len() as i64;
                data.add_field(
                    "managed_policy_count".to_string(),
                    ResolvedValue::Integer(count),
                );
                managed_policies_val = serde_json::Value::Array(policies);
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "AWS API error (list-managed-policies-in-permission-set): {}",
                        e
                    ),
                });
            }
        }

        // ====================================================================
        // Command 4: get-inline-policy-for-permission-set
        // ====================================================================
        let mut inline_policy_val = serde_json::json!({});
        match client.execute(
            "sso-admin",
            "get-inline-policy-for-permission-set",
            &ps_args,
        ) {
            Ok(resp) => {
                let policy_str = resp
                    .get("InlinePolicy")
                    .and_then(|v: &serde_json::Value| v.as_str())
                    .unwrap_or("");

                if policy_str.is_empty() {
                    data.add_field(
                        "has_inline_policy".to_string(),
                        ResolvedValue::Boolean(false),
                    );
                } else {
                    data.add_field(
                        "has_inline_policy".to_string(),
                        ResolvedValue::Boolean(true),
                    );
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(policy_str) {
                        inline_policy_val = parsed;
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "AWS API error (get-inline-policy-for-permission-set): {}",
                        e
                    ),
                });
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "PermissionSet": ps_metadata_val,
            "AttachedManagedPolicies": managed_policies_val,
            "InlinePolicy": inline_policy_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_ssoadmin_permission_set".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_ssoadmin_permission_set" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_ssoadmin_permission_set', got '{}'",
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
            AwsSsoadminPermissionSetCollector::new().collector_id(),
            "aws_ssoadmin_permission_set_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsSsoadminPermissionSetCollector::new().supported_ctn_types(),
            vec!["aws_ssoadmin_permission_set"]
        );
    }
}
