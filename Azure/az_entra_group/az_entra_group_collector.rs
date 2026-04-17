//! Azure Entra ID Group Collector
//!
//! Single API call: az ad group show --group <display_name>

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzEntraGroupCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzEntraGroupCollector {
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
        stderr.contains("does not exist")
            || stderr.contains("Not Found")
            || stderr.contains("No group matches the name")
            || stderr.contains("Resource 'microsoft.graph")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("(NotFound)")
            || stderr.contains("404")
    }
}

impl CtnDataCollector for AzEntraGroupCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let display_name = self
            .extract_string_field(object, "display_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'display_name' is required for az_entra_group".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_group".to_string(),
            self.id.clone(),
        );

        let args: Vec<String> = vec![
            "ad".to_string(),
            "group".to_string(),
            "show".to_string(),
            "--group".to_string(),
            display_name.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        let command_str = format!("az {}", args.join(" "));

        let target = format!("entra-group:{}", display_name);
        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::ApiCall)
                .description("Query Entra ID group via Azure CLI")
                .target(&target)
                .command(&command_str)
                .input("display_name", &display_name)
                .build(),
        );

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
                    "az ad group show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let group: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|e| {
                CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Failed to parse az ad group show JSON: {}", e),
                }
            })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = group.get("id").and_then(|v| v.as_str()) {
            data.add_field("group_id".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = group.get("displayName").and_then(|v| v.as_str()) {
            data.add_field(
                "display_name".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = group.get("description").and_then(|v| v.as_str()) {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = group.get("securityEnabled").and_then(|v| v.as_bool()) {
            data.add_field("security_enabled".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = group.get("mailEnabled").and_then(|v| v.as_bool()) {
            data.add_field("mail_enabled".to_string(), ResolvedValue::Boolean(v));
        }

        let record_data = RecordData::from_json_value(group);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_entra_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_entra_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_entra_group', got '{}'",
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
