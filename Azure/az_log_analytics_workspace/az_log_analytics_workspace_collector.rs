//! Azure Log Analytics Workspace (LAW) Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_log_analytics_workspace;
//  pub use az_log_analytics_workspace::AzLogAnalyticsWorkspaceCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzLogAnalyticsWorkspaceCollector::new(
//          "az-log-analytics-workspace-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzLogAnalyticsWorkspaceExecutor::new(
//          contracts::create_az_log_analytics_workspace_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az monitor log-analytics workspace show --workspace-name <name>
//! --resource-group <rg> [--subscription <id>] --output json` call. Returns
//! scalar fields for SKU, retention, access control, public network access,
//! daily quota cap, and local auth settings, plus the full response as
//! RecordData for tag-based record_checks.
//!
//! ## NotFound handling
//!
//! Same dual-pattern as other Azure CTNs:
//! - `(ResourceNotFound)` - real RG with missing/malformed workspace name
//! - `(AuthorizationFailed)` scoped to `/workspaces/` - inaccessible RG

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzLogAnalyticsWorkspaceCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzLogAnalyticsWorkspaceCollector {
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

    /// Returns true when Azure's error shape matches a genuine NotFound.
    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/workspaces/") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzLogAnalyticsWorkspaceCollector {
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
                reason: "'name' is required for az_log_analytics_workspace".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_log_analytics_workspace"
                        .to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_log_analytics_workspace".to_string(),
            self.id.clone(),
        );

        // Build argv -- note: az monitor log-analytics workspace show uses
        // --workspace-name, not --name
        let mut args: Vec<String> = vec![
            "monitor".to_string(),
            "log-analytics".to_string(),
            "workspace".to_string(),
            "show".to_string(),
            "--workspace-name".to_string(),
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

        let target = format!("law:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Log Analytics Workspace via Azure CLI")
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
                    "az monitor log-analytics workspace show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse az monitor log-analytics workspace show JSON: {}",
                    e
                ),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("customerId", "customer_id"),
            ("createdDate", "created_date"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // SKU
        if let Some(sku_name) = resp
            .get("sku")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "sku_name".to_string(),
                ResolvedValue::String(sku_name.to_string()),
            );
        }

        // Retention
        if let Some(retention) = resp.get("retentionInDays").and_then(|v| v.as_i64()) {
            data.add_field(
                "retention_in_days".to_string(),
                ResolvedValue::Integer(retention),
            );
        }

        // Public network access
        for (json_key, field_name) in &[
            (
                "publicNetworkAccessForIngestion",
                "public_network_access_ingestion",
            ),
            ("publicNetworkAccessForQuery", "public_network_access_query"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // Features
        if let Some(features) = resp.get("features") {
            // disableLocalAuth
            let disable_local_auth = features
                .get("disableLocalAuth")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            data.add_field(
                "local_auth_disabled".to_string(),
                ResolvedValue::Boolean(disable_local_auth),
            );

            // enableLogAccessUsingOnlyResourcePermissions
            let resource_permissions = features
                .get("enableLogAccessUsingOnlyResourcePermissions")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            data.add_field(
                "resource_permissions_enabled".to_string(),
                ResolvedValue::Boolean(resource_permissions),
            );
        }

        // Workspace capping
        if let Some(capping) = resp.get("workspaceCapping") {
            if let Some(quota) = capping.get("dailyQuotaGb").and_then(|v| v.as_f64()) {
                // -1.0 means unlimited; store as integer for ESP (truncate)
                // For -1 (unlimited), store as-is; for positive values, store as int
                let quota_int = quota as i64;
                data.add_field(
                    "daily_quota_gb".to_string(),
                    ResolvedValue::Integer(quota_int),
                );
                data.add_field(
                    "has_daily_cap".to_string(),
                    ResolvedValue::Boolean(quota > 0.0),
                );
            }
            if let Some(status) = capping
                .get("dataIngestionStatus")
                .and_then(|v| v.as_str())
            {
                data.add_field(
                    "data_ingestion_status".to_string(),
                    ResolvedValue::String(status.to_string()),
                );
            }
        }

        // Derived: retention meets common compliance thresholds
        if let Some(retention) = resp.get("retentionInDays").and_then(|v| v.as_i64()) {
            data.add_field(
                "retention_meets_90_days".to_string(),
                ResolvedValue::Boolean(retention >= 90),
            );
            data.add_field(
                "retention_meets_365_days".to_string(),
                ResolvedValue::Boolean(retention >= 365),
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
        vec!["az_log_analytics_workspace".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_log_analytics_workspace" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_log_analytics_workspace', got '{}'",
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
                     'Microsoft.OperationalInsights/workspaces/law-missing' was not found.";
        assert!(AzLogAnalyticsWorkspaceCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_workspace() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-x'";
        assert!(AzLogAnalyticsWorkspaceCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'";
        assert!(!AzLogAnalyticsWorkspaceCollector::is_not_found(stderr));
    }
}
