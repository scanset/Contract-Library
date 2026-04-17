//! Azure Role Assignment Collector
//!
//! Single API call: az role assignment list --assignee <principal_id>
//! Optionally filtered by role_name and scope.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzRoleAssignmentCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzRoleAssignmentCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
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

    fn is_not_found(stderr: &str) -> bool {
        stderr.contains("Cannot find user or service principal in graph database")
            || stderr.contains("does not exist")
            || stderr.contains("Not Found")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("(NotFound)")
            || stderr.contains("404")
    }
}

impl CtnDataCollector for AzRoleAssignmentCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let principal_id = self
            .extract_string_field(object, "principal_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'principal_id' is required for az_role_assignment".to_string(),
            })?;

        let role_name = self.extract_string_field(object, "role_name");
        let scope = self.extract_string_field(object, "scope");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_role_assignment".to_string(),
            self.id.clone(),
        );

        // Build args
        let mut args: Vec<String> = vec![
            "role".to_string(),
            "assignment".to_string(),
            "list".to_string(),
            "--assignee".to_string(),
            principal_id.clone(),
        ];
        if let Some(ref s) = scope {
            args.push("--scope".to_string());
            args.push(s.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());
        let command_str = format!("az {}", args.join(" "));

        let target = format!("az-role-assignment:{}", principal_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure RBAC role assignments via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("principal_id", &principal_id);
        if let Some(ref r) = role_name {
            method_builder = method_builder.input("role_name", r);
        }
        if let Some(ref s) = scope {
            method_builder = method_builder.input("scope", s);
        }
        data.set_method(method_builder.build());

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self
            .executor
            .execute("az", &arg_refs, Some(Duration::from_secs(30)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute az: {}", e),
            })?;

        if output.exit_code != 0 {
            if Self::is_not_found(&output.stderr) {
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
                reason: format!(
                    "az role assignment list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let arr: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az role assignment list JSON: {}", e),
            }
        })?;

        let assignments = arr.as_array().cloned().unwrap_or_default();

        // Find matching assignment
        let assignment = if let Some(ref rn) = role_name {
            assignments
                .iter()
                .find(|a| {
                    a.get("roleDefinitionName").and_then(|v| v.as_str()) == Some(rn.as_str())
                })
                .cloned()
        } else {
            assignments.into_iter().next()
        };

        match assignment {
            None => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
            }
            Some(a) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                let str_fields = [
                    ("roleDefinitionName", "role_definition_name"),
                    ("scope", "scope"),
                    ("principalId", "principal_id"),
                    ("principalType", "principal_type"),
                    ("id", "assignment_id"),
                ];
                for (json_key, field_name) in &str_fields {
                    if let Some(v) = a.get(*json_key).and_then(|v| v.as_str()) {
                        data.add_field(
                            field_name.to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                }

                let record_data = RecordData::from_json_value(a);
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_role_assignment".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_role_assignment" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_role_assignment', got '{}'",
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
