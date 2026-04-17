//! Azure Activity Log Alert Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_activity_log_alert;
//  pub use az_activity_log_alert::AzActivityLogAlertCollector;
//
///////////////////////////////////////////////////////

//! Single `az monitor activity-log alert show --name <name>
//! --resource-group <rg> [--subscription <id>] --output json` call.
//! Returns enabled state, description, scope/condition/action counts,
//! and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzActivityLogAlertCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzActivityLogAlertCollector {
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
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("activitylogalerts") {
                return true;
            }
        }
        false
    }

    fn count_array(value: &serde_json::Value, path: &[&str]) -> i64 {
        let mut current = value;
        for key in path {
            match current.get(*key) {
                Some(v) => current = v,
                None => return 0,
            }
        }
        current.as_array().map(|a| a.len() as i64).unwrap_or(0)
    }

    /// Extract the first operationName condition value from condition.allOf
    fn extract_operation_name(value: &serde_json::Value) -> Option<String> {
        let all_of = value
            .get("condition")
            .and_then(|v| v.get("allOf"))
            .and_then(|v| v.as_array())?;
        for cond in all_of {
            if let Some(field) = cond.get("field").and_then(|v| v.as_str()) {
                if field == "operationName" {
                    if let Some(eq) = cond.get("equals").and_then(|v| v.as_str()) {
                        return Some(eq.to_string());
                    }
                }
            }
        }
        None
    }

    /// Extract the category condition value from condition.allOf
    fn extract_category(value: &serde_json::Value) -> Option<String> {
        let all_of = value
            .get("condition")
            .and_then(|v| v.get("allOf"))
            .and_then(|v| v.as_array())?;
        for cond in all_of {
            if let Some(field) = cond.get("field").and_then(|v| v.as_str()) {
                if field == "category" {
                    if let Some(eq) = cond.get("equals").and_then(|v| v.as_str()) {
                        return Some(eq.to_string());
                    }
                }
            }
        }
        None
    }
}

impl CtnDataCollector for AzActivityLogAlertCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let name = self.extract_string_field(object, "name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'name' is required for az_activity_log_alert".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_activity_log_alert".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_activity_log_alert".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "monitor".to_string(),
            "activity-log".to_string(),
            "alert".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
            "--resource-group".to_string(),
            resource_group.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("activity-log-alert:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Activity Log Alert via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name)
            .input("resource_group", &resource_group);
        if let Some(ref sub) = subscription {
            method_builder = method_builder.input("subscription", sub);
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
                    "az monitor activity-log alert show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|e| {
                CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Failed to parse activity-log alert show JSON: {}", e),
                }
            })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
            ("description", "description"),
            ("resourceGroup", "resource_group"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // enabled (boolean)
        let enabled = resp
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field("enabled".to_string(), ResolvedValue::Boolean(enabled));

        // Array counts
        let scope_count = Self::count_array(&resp, &["scopes"]);
        data.add_field(
            "scope_count".to_string(),
            ResolvedValue::Integer(scope_count),
        );

        let condition_count = Self::count_array(&resp, &["condition", "allOf"]);
        data.add_field(
            "condition_count".to_string(),
            ResolvedValue::Integer(condition_count),
        );

        let action_group_count = Self::count_array(&resp, &["actions", "actionGroups"]);
        data.add_field(
            "action_group_count".to_string(),
            ResolvedValue::Integer(action_group_count),
        );
        data.add_field(
            "has_action_groups".to_string(),
            ResolvedValue::Boolean(action_group_count > 0),
        );

        // Extracted condition fields for easy assertion
        if let Some(op_name) = Self::extract_operation_name(&resp) {
            data.add_field(
                "operation_name".to_string(),
                ResolvedValue::String(op_name),
            );
        }
        if let Some(category) = Self::extract_category(&resp) {
            data.add_field(
                "category".to_string(),
                ResolvedValue::String(category),
            );
        }

        // RecordData
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_activity_log_alert".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_activity_log_alert" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_activity_log_alert', got '{}'",
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
    fn not_found_matches_resource_not_found() {
        let stderr = "ERROR: (ResourceNotFound) The Resource \
                     'Microsoft.Insights/activityLogAlerts/alert-missing' was not found.";
        assert!(AzActivityLogAlertCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_scoped_to_alert() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Insights/activityLogAlerts/x'";
        assert!(AzActivityLogAlertCollector::is_not_found(stderr));
    }

    #[test]
    fn unrelated_authz_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/d1'";
        assert!(!AzActivityLogAlertCollector::is_not_found(stderr));
    }

    #[test]
    fn extract_operation_name_from_json() {
        let json: serde_json::Value = serde_json::json!({
            "condition": {
                "allOf": [
                    { "field": "category", "equals": "Administrative" },
                    { "field": "operationName", "equals": "Microsoft.Authorization/policyAssignments/write" }
                ]
            }
        });
        assert_eq!(
            AzActivityLogAlertCollector::extract_operation_name(&json),
            Some("Microsoft.Authorization/policyAssignments/write".to_string())
        );
    }

    #[test]
    fn extract_category_from_json() {
        let json: serde_json::Value = serde_json::json!({
            "condition": {
                "allOf": [
                    { "field": "category", "equals": "Administrative" },
                    { "field": "operationName", "equals": "Something/write" }
                ]
            }
        });
        assert_eq!(
            AzActivityLogAlertCollector::extract_category(&json),
            Some("Administrative".to_string())
        );
    }
}
