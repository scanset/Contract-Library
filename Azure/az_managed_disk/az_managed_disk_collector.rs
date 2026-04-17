//! Azure Managed Disk Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_managed_disk;
//  pub use az_managed_disk::AzManagedDiskCollector;
//
///////////////////////////////////////////////////////

//! Single `az disk show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! SKU, disk size, state, encryption type, network access policy, OS type,
//! zone, performance tier, IOPS/throughput, and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzManagedDiskCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzManagedDiskCollector {
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
            if lower.contains("/disks/") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzManagedDiskCollector {
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
                reason: "'name' is required for az_managed_disk".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_managed_disk".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_managed_disk".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "disk".to_string(),
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
        let target = format!("disk:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Managed Disk via Azure CLI")
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
                    "az disk show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse disk show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("diskState", "disk_state"),
            ("networkAccessPolicy", "network_access_policy"),
            ("publicNetworkAccess", "public_network_access"),
            ("osType", "os_type"),
            ("hyperVGeneration", "hyper_v_generation"),
            ("tier", "performance_tier"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // Creation option
        if let Some(create_option) = resp
            .get("creationData")
            .and_then(|v| v.get("createOption"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "create_option".to_string(),
                ResolvedValue::String(create_option.to_string()),
            );
        }

        // SKU name and tier
        if let Some(sku) = resp.get("sku") {
            if let Some(sku_name) = sku.get("name").and_then(|v| v.as_str()) {
                data.add_field(
                    "sku_name".to_string(),
                    ResolvedValue::String(sku_name.to_string()),
                );
            }
            if let Some(sku_tier) = sku.get("tier").and_then(|v| v.as_str()) {
                data.add_field(
                    "sku_tier".to_string(),
                    ResolvedValue::String(sku_tier.to_string()),
                );
            }
        }

        // Encryption type and DES presence
        if let Some(enc) = resp.get("encryption") {
            if let Some(enc_type) = enc.get("type").and_then(|v| v.as_str()) {
                data.add_field(
                    "encryption_type".to_string(),
                    ResolvedValue::String(enc_type.to_string()),
                );
            }
            let has_des = enc.get("diskEncryptionSetId").is_some();
            data.add_field(
                "has_disk_encryption_set".to_string(),
                ResolvedValue::Boolean(has_des),
            );
        } else {
            data.add_field(
                "has_disk_encryption_set".to_string(),
                ResolvedValue::Boolean(false),
            );
        }

        // Integers
        if let Some(size) = resp.get("diskSizeGB").and_then(|v| v.as_i64()) {
            data.add_field(
                "disk_size_gb".to_string(),
                ResolvedValue::Integer(size),
            );
        }
        if let Some(iops) = resp.get("diskIOPSReadWrite").and_then(|v| v.as_i64()) {
            data.add_field(
                "disk_iops_read_write".to_string(),
                ResolvedValue::Integer(iops),
            );
        }
        if let Some(mbps) = resp.get("diskMBpsReadWrite").and_then(|v| v.as_i64()) {
            data.add_field(
                "disk_mbps_read_write".to_string(),
                ResolvedValue::Integer(mbps),
            );
        }

        // Derived: is_attached
        let is_attached = resp.get("managedBy").is_some();
        data.add_field(
            "is_attached".to_string(),
            ResolvedValue::Boolean(is_attached),
        );

        // Zone count
        let zone_count = resp
            .get("zones")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "zone_count".to_string(),
            ResolvedValue::Integer(zone_count),
        );

        // RecordData
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_managed_disk".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_managed_disk" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_managed_disk', got '{}'",
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
                     'Microsoft.Compute/disks/disk-missing' was not found.";
        assert!(AzManagedDiskCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_disk() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/disk-x'";
        assert!(AzManagedDiskCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb1'";
        assert!(!AzManagedDiskCollector::is_not_found(stderr));
    }
}
