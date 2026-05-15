//! Azure Diagnostic Setting List Collector
//!
//! Wraps `az monitor diagnostic-settings list --resource <id> -o json`.
//! Hoists `workspaceId` + computes enabled-category counts so the
//! envelope record is self-describing without nested traversal.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzDiagnosticSettingListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzDiagnosticSettingListCollector {
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
            ("resourceGroup", "resource_group"),
            ("workspaceId", "workspace_id"),
            ("storageAccountId", "storage_account_id"),
            ("eventHubAuthorizationRuleId", "event_hub_authorization_rule_id"),
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

        // Logs / metrics — surface counts and the enabled category lists.
        let mut log_count = 0i64;
        let mut enabled_log_categories: Vec<serde_json::Value> = Vec::new();
        if let Some(arr) = item.get("logs").and_then(|v| v.as_array()) {
            log_count = arr.len() as i64;
            for log in arr {
                let enabled = log
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled {
                    if let Some(cat) = log.get("category").and_then(|v| v.as_str()) {
                        enabled_log_categories.push(serde_json::Value::String(cat.to_string()));
                    }
                }
            }
        }
        out.insert(
            "log_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(log_count)),
        );
        if !enabled_log_categories.is_empty() {
            out.insert(
                "enabled_log_categories".to_string(),
                serde_json::Value::Array(enabled_log_categories),
            );
        }

        let mut metric_count = 0i64;
        let mut enabled_metric_categories: Vec<serde_json::Value> = Vec::new();
        if let Some(arr) = item.get("metrics").and_then(|v| v.as_array()) {
            metric_count = arr.len() as i64;
            for metric in arr {
                let enabled = metric
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled {
                    if let Some(cat) = metric.get("category").and_then(|v| v.as_str()) {
                        enabled_metric_categories
                            .push(serde_json::Value::String(cat.to_string()));
                    }
                }
            }
        }
        out.insert(
            "metric_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(metric_count)),
        );
        if !enabled_metric_categories.is_empty() {
            out.insert(
                "enabled_metric_categories".to_string(),
                serde_json::Value::Array(enabled_metric_categories),
            );
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzDiagnosticSettingListCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let resource_id = self
            .extract_string_field(object, "resource_id")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `resource_id`".to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_diagnostic_setting_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "monitor".to_string(),
            "diagnostic-settings".to_string(),
            "list".to_string(),
            "--resource".to_string(),
            resource_id.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("diag-setting-list:{}", resource_id);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure diagnostic settings via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("resource_id", &resource_id);
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
                    "az monitor diagnostic-settings list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        // Azure returns one of:
        //   []                          (no diagnostic settings configured)
        //   [{...}, {...}]              (one or more settings)
        //   { "value": [{...}, ...] }   (older API responses)
        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az diag-settings list JSON: {}", e),
            }
        })?;

        let raw_array: Vec<serde_json::Value> = if let Some(arr) = resp.as_array() {
            arr.clone()
        } else if let Some(arr) = resp.get("value").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            Vec::new()
        };

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("setting_count".to_string(), ResolvedValue::Integer(count));

        let settings_record = RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "settings".to_string(),
            ResolvedValue::RecordData(Box::new(settings_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_diagnostic_setting_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_diagnostic_setting_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_diagnostic_setting_list', got '{}'",
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
