//! Azure Policy Assignment List Collector
//!
//! Single `az policy assignment list -o json [--subscription <id>]`.
//! Projects each record into snake_case, hoists `systemData.createdBy` /
//! `createdAt` to top-level `created_by` / `created_at` for ergonomic
//! field access.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzPolicyAssignmentListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzPolicyAssignmentListCollector {
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

    fn project_record(item: &serde_json::Value) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        for (json_key, out_key) in &[
            ("id", "id"),
            ("name", "name"),
            ("type", "type"),
            ("displayName", "display_name"),
            ("description", "description"),
            ("enforcementMode", "enforcement_mode"),
            ("policyDefinitionId", "policy_definition_id"),
            ("scope", "scope"),
            ("definitionVersion", "definition_version"),
        ] {
            if let Some(v) = item.get(*json_key).and_then(|v| v.as_str()) {
                if !v.is_empty() {
                    out.insert(
                        (*out_key).to_string(),
                        serde_json::Value::String(v.to_string()),
                    );
                }
            }
        }

        if let Some(sd) = item.get("systemData") {
            if let Some(v) = sd.get("createdAt").and_then(|v| v.as_str()) {
                out.insert(
                    "created_at".to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
            if let Some(v) = sd.get("createdBy").and_then(|v| v.as_str()) {
                out.insert(
                    "created_by".to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
            if let Some(v) = sd.get("createdByType").and_then(|v| v.as_str()) {
                out.insert(
                    "created_by_type".to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzPolicyAssignmentListCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let scope = self
            .extract_string_field(object, "scope")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `scope`".to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_policy_assignment_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "policy".to_string(),
            "assignment".to_string(),
            "list".to_string(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("policy-assignment-list:{}", scope);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure policy assignments via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("scope", &scope);
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
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az policy assignment list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az policy assignment list JSON: {}", e),
            }
        })?;

        let raw_array = resp
            .as_array()
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "az policy assignment list did not return a JSON array".to_string(),
            })?;

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "assignment_count".to_string(),
            ResolvedValue::Integer(count),
        );

        let assignments_record =
            RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "assignments".to_string(),
            ResolvedValue::RecordData(Box::new(assignments_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_policy_assignment_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_policy_assignment_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_policy_assignment_list', got '{}'",
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
