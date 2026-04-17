//! Azure Recovery Services Vault Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_recovery_services_vault;
//  pub use az_recovery_services_vault::AzRecoveryServicesVaultCollector;
//
///////////////////////////////////////////////////////

//! Single `az backup vault show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! SKU, storage redundancy, soft delete, immutability, MUA, secure score,
//! identity, and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzRecoveryServicesVaultCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzRecoveryServicesVaultCollector {
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
            if lower.contains("/vaults/") && lower.contains("recoveryservices") {
                return true;
            }
        }
        false
    }

    /// Helper to navigate nested JSON paths like "properties.securitySettings.softDeleteSettings.softDeleteState"
    fn get_nested_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
        let mut current = value;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_str()
    }

    fn get_nested_i64(value: &serde_json::Value, path: &[&str]) -> Option<i64> {
        let mut current = value;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_i64()
    }
}

impl CtnDataCollector for AzRecoveryServicesVaultCollector {
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
                reason: "'name' is required for az_recovery_services_vault".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_recovery_services_vault"
                        .to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_recovery_services_vault".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "backup".to_string(),
            "vault".to_string(),
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
        let target = format!("rsv:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Recovery Services Vault via Azure CLI")
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
                    "az backup vault show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse backup vault show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // Resource group (may be cased differently in response)
        if let Some(rg) = resp.get("resourceGroup").and_then(|v| v.as_str()) {
            data.add_field(
                "resource_group".to_string(),
                ResolvedValue::String(rg.to_string()),
            );
        }

        // SKU name
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

        // Identity type
        if let Some(id_type) = resp
            .get("identity")
            .and_then(|v| v.get("type"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "identity_type".to_string(),
                ResolvedValue::String(id_type.to_string()),
            );
        }

        // Properties - provisioning state
        if let Some(v) = Self::get_nested_str(&resp, &["properties", "provisioningState"]) {
            data.add_field(
                "provisioning_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Properties - public network access
        if let Some(v) = Self::get_nested_str(&resp, &["properties", "publicNetworkAccess"]) {
            data.add_field(
                "public_network_access".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Properties - secure score
        if let Some(v) = Self::get_nested_str(&resp, &["properties", "secureScore"]) {
            data.add_field(
                "secure_score".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Properties - BCDR security level
        if let Some(v) = Self::get_nested_str(&resp, &["properties", "bcdrSecurityLevel"]) {
            data.add_field(
                "bcdr_security_level".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Redundancy settings
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "redundancySettings", "standardTierStorageRedundancy"],
        ) {
            data.add_field(
                "storage_redundancy".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "redundancySettings", "crossRegionRestore"],
        ) {
            data.add_field(
                "cross_region_restore".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Security settings - soft delete
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "securitySettings", "softDeleteSettings", "softDeleteState"],
        ) {
            data.add_field(
                "soft_delete_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = Self::get_nested_i64(
            &resp,
            &["properties", "securitySettings", "softDeleteSettings", "softDeleteRetentionPeriodInDays"],
        ) {
            data.add_field(
                "soft_delete_retention_days".to_string(),
                ResolvedValue::Integer(v),
            );
        }
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "securitySettings", "softDeleteSettings", "enhancedSecurityState"],
        ) {
            data.add_field(
                "enhanced_security_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Security settings - immutability
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "securitySettings", "immutabilitySettings", "state"],
        ) {
            data.add_field(
                "immutability_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Security settings - MUA
        if let Some(v) = Self::get_nested_str(
            &resp,
            &["properties", "securitySettings", "multiUserAuthorization"],
        ) {
            data.add_field(
                "multi_user_authorization".to_string(),
                ResolvedValue::String(v.to_string()),
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
        vec!["az_recovery_services_vault".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_recovery_services_vault" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_recovery_services_vault', got '{}'",
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
                     'Microsoft.RecoveryServices/vaults/rsv-missing' was not found.";
        assert!(AzRecoveryServicesVaultCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_rsv() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv-x'";
        assert!(AzRecoveryServicesVaultCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/disk1'";
        assert!(!AzRecoveryServicesVaultCollector::is_not_found(stderr));
    }
}
