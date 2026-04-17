//! Azure Diagnostic Setting Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_diagnostic_setting;
//  pub use az_diagnostic_setting::AzDiagnosticSettingCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzDiagnosticSettingCollector::new(
//          "az-diagnostic-setting-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzDiagnosticSettingExecutor::new(
//          contracts::create_az_diagnostic_setting_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az monitor diagnostic-settings show --name <setting>
//! --resource <target ARM ID> [--subscription <id>] --output json` call.
//! Returns scalar fields plus the full response as RecordData for
//! per-category record_checks on logs[] and metrics[].
//!
//! ## NotFound handling
//!
//! Three distinct stderr patterns all map to `found=false`:
//!
//! 1. **Setting doesn't exist on real resource** - exit 3, stderr contains
//!    `(ResourceNotFound)` with message "The diagnostic setting 'X' doesn't
//!    exist."
//! 2. **Target resource doesn't exist** - exit 3, stderr contains
//!    `(ResourceNotFound)` with "under resource group ... was not found"
//!    wording
//! 3. **Target resource inaccessible (fake RG / no permission)** - exit 1,
//!    stderr contains `(AuthorizationFailed)` with action scoped to
//!    `Microsoft.Insights/diagnosticSettings/read`
//! 4. **Malformed provider namespace in resource ID** - exit 3, stderr
//!    contains `(InvalidResourceNamespace)` - the CTN treats this as
//!    "resource does not exist" (found=false) rather than a collection
//!    error because the net effect on policy is identical.
//!
//! All other non-zero exits bubble up as `CollectionError::CollectionFailed`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzDiagnosticSettingCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzDiagnosticSettingCollector {
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

    /// Returns true when Azure's error shape matches a genuine NotFound,
    /// where "genuine" includes: the setting missing, the target resource
    /// missing, the RG missing/forbidden, or the namespace malformed. Any
    /// of those four mean "policy can't assert on a non-present config",
    /// which the executor renders as a clean found=false fail.
    ///
    /// - `(ResourceNotFound)` covers missing settings AND missing target
    ///   resources (two different wording paths, same error code).
    /// - `(AuthorizationFailed)` gated on the diagnostic-settings scope
    ///   substring so unrelated RBAC failures still surface as errors.
    /// - `(InvalidResourceNamespace)` covers typos in the provider segment
    ///   of the resource ID - Azure can't look up "does the target exist"
    ///   without a valid namespace, so it's semantically equivalent to
    ///   NotFound for our purposes.
    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(InvalidResourceNamespace)")
            || stderr.contains("Code: InvalidResourceNamespace")
        {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/diagnosticsettings") || lower.contains("microsoft.insights") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzDiagnosticSettingCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let resource_id = self.extract_string_field(object, "resource_id").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'resource_id' is required for az_diagnostic_setting (full ARM ID of the \
                        target resource)"
                    .to_string(),
            }
        })?;
        let setting_name = self.extract_string_field(object, "setting_name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'setting_name' is required for az_diagnostic_setting".to_string(),
            }
        })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_diagnostic_setting".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "monitor".to_string(),
            "diagnostic-settings".to_string(),
            "show".to_string(),
            "--name".to_string(),
            setting_name.clone(),
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

        let target = format!("diag-setting:{}@{}", setting_name, resource_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Diagnostic Setting via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("setting_name", &setting_name)
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
                    "az monitor diagnostic-settings show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az monitor diagnostic-settings show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings (required)
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("resourceGroup", "target_resource_group"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // optional destination strings - default to empty string when absent
        let optional_strings = [
            ("workspaceId", "workspace_id"),
            ("eventHubName", "event_hub_name"),
            ("eventHubAuthorizationRuleId", "event_hub_authorization_rule_id"),
            ("storageAccountId", "storage_account_id"),
            ("marketplacePartnerId", "marketplace_partner_id"),
            ("serviceBusRuleId", "service_bus_rule_id"),
            ("logAnalyticsDestinationType", "log_analytics_destination_type"),
        ];
        for (json_key, field_name) in &optional_strings {
            let val = resp
                .get(*json_key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            data.add_field(field_name.to_string(), ResolvedValue::String(val));
        }

        // derived destination booleans - based on the optional strings being non-empty
        let workspace = resp.get("workspaceId").and_then(|v| v.as_str()).unwrap_or("");
        let event_hub_auth = resp
            .get("eventHubAuthorizationRuleId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let storage = resp
            .get("storageAccountId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let marketplace = resp
            .get("marketplacePartnerId")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let has_ws = !workspace.is_empty();
        let has_eh = !event_hub_auth.is_empty();
        let has_sa = !storage.is_empty();
        let has_mp = !marketplace.is_empty();

        data.add_field(
            "has_workspace_destination".to_string(),
            ResolvedValue::Boolean(has_ws),
        );
        data.add_field(
            "has_event_hub_destination".to_string(),
            ResolvedValue::Boolean(has_eh),
        );
        data.add_field(
            "has_storage_destination".to_string(),
            ResolvedValue::Boolean(has_sa),
        );
        data.add_field(
            "has_marketplace_destination".to_string(),
            ResolvedValue::Boolean(has_mp),
        );

        let destination_count = (has_ws as i64) + (has_eh as i64) + (has_sa as i64) + (has_mp as i64);
        data.add_field(
            "destination_count".to_string(),
            ResolvedValue::Integer(destination_count),
        );

        // logs[] and metrics[]
        let empty_arr = serde_json::Value::Array(Vec::new());
        let logs = resp.get("logs").unwrap_or(&empty_arr);
        let metrics = resp.get("metrics").unwrap_or(&empty_arr);

        let log_count = logs.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        let metric_count = metrics.as_array().map(|a| a.len()).unwrap_or(0) as i64;

        let log_enabled = logs
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|e| e.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
                    .count() as i64
            })
            .unwrap_or(0);
        let metric_enabled = metrics
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|e| e.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
                    .count() as i64
            })
            .unwrap_or(0);

        data.add_field(
            "log_category_count".to_string(),
            ResolvedValue::Integer(log_count),
        );
        data.add_field(
            "metric_category_count".to_string(),
            ResolvedValue::Integer(metric_count),
        );
        data.add_field(
            "log_categories_enabled_count".to_string(),
            ResolvedValue::Integer(log_enabled),
        );
        data.add_field(
            "metric_categories_enabled_count".to_string(),
            ResolvedValue::Integer(metric_enabled),
        );
        // all_*_enabled - vacuously true when the array is empty
        data.add_field(
            "all_log_categories_enabled".to_string(),
            ResolvedValue::Boolean(log_enabled == log_count),
        );
        data.add_field(
            "all_metric_categories_enabled".to_string(),
            ResolvedValue::Boolean(metric_enabled == metric_count),
        );

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_diagnostic_setting".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_diagnostic_setting" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_diagnostic_setting', got '{}'",
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
    fn not_found_matches_setting_missing() {
        let stderr = "ERROR: (ResourceNotFound) The diagnostic setting 'missing' doesn't exist.";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_target_resource_missing() {
        let stderr = "ERROR: (ResourceNotFound) The Resource \
                     'Microsoft.Network/networkSecurityGroups/nsg-gone' under resource group \
                     'rg-real' was not found.";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found_code_line() {
        let stderr = "ERROR: something\nCode: ResourceNotFound\nMessage: whatever";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_invalid_namespace() {
        let stderr = "ERROR: (InvalidResourceNamespace) The resource namespace 'Bogus.Provider' \
                     is invalid.";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_invalid_namespace_code_line() {
        let stderr = "ERROR: something\nCode: InvalidResourceNamespace\n...";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_diag_settings() {
        let stderr = "ERROR: (AuthorizationFailed) The client 'x' does not have authorization \
                     to perform action 'Microsoft.Insights/diagnosticSettings/read' over scope \
                     '/subscriptions/abc/resourceGroups/rg-gone/providers/Microsoft.Network/\
                     networkSecurityGroups/nsg/providers/Microsoft.Insights' or the scope is invalid.";
        assert!(AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'";
        assert!(!AzDiagnosticSettingCollector::is_not_found(stderr));
    }

    #[test]
    fn forbidden_is_not_not_found() {
        let stderr = "ERROR: (Forbidden) Caller is not authorized to perform action on resource.";
        assert!(!AzDiagnosticSettingCollector::is_not_found(stderr));
    }
}
