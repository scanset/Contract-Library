//! Azure Disk Encryption Set Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_disk_encryption_set;
//  pub use az_disk_encryption_set::AzDiskEncryptionSetCollector;
//
///////////////////////////////////////////////////////

//! Single `az disk-encryption-set show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! encryption type, identity, key rotation, active key URL, and the full
//! response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzDiskEncryptionSetCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzDiskEncryptionSetCollector {
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
            if lower.contains("/diskencryptionsets/") {
                return true;
            }
        }
        false
    }

    /// Parse key URL to extract vault name, key name, and key version.
    /// Format: https://<vault>.vault.azure.net/keys/<key-name>/<version>
    fn parse_key_url(url: &str) -> (Option<String>, Option<String>, Option<String>) {
        // Extract vault name from host
        let vault_name = url
            .strip_prefix("https://")
            .and_then(|s| s.split('.').next())
            .map(|s| s.to_string());

        // Extract key name and version from path
        let parts: Vec<&str> = url.split("/keys/").collect();
        let (key_name, key_version) = if parts.len() == 2 {
            let key_parts: Vec<&str> = parts[1].splitn(2, '/').collect();
            let name = Some(key_parts[0].to_string());
            let version = key_parts.get(1).map(|s| s.to_string());
            (name, version)
        } else {
            (None, None)
        };

        (vault_name, key_name, key_version)
    }
}

impl CtnDataCollector for AzDiskEncryptionSetCollector {
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
                reason: "'name' is required for az_disk_encryption_set".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_disk_encryption_set".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_disk_encryption_set".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "disk-encryption-set".to_string(),
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
        let target = format!("des:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Disk Encryption Set via Azure CLI")
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
                    "az disk-encryption-set show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse disk-encryption-set show JSON: {}", e),
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
            ("encryptionType", "encryption_type"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
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

        // Auto key rotation
        let rotation_enabled = resp
            .get("rotationToLatestKeyVersionEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "auto_key_rotation_enabled".to_string(),
            ResolvedValue::Boolean(rotation_enabled),
        );

        // Active key URL and parsed components
        if let Some(key_url) = resp
            .get("activeKey")
            .and_then(|v| v.get("keyUrl"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "active_key_url".to_string(),
                ResolvedValue::String(key_url.to_string()),
            );
            let (vault_name, key_name, key_version) = Self::parse_key_url(key_url);
            if let Some(v) = vault_name {
                data.add_field(
                    "key_vault_name".to_string(),
                    ResolvedValue::String(v),
                );
            }
            if let Some(k) = key_name {
                data.add_field(
                    "key_name".to_string(),
                    ResolvedValue::String(k),
                );
            }
            if let Some(ver) = key_version {
                data.add_field(
                    "key_version".to_string(),
                    ResolvedValue::String(ver),
                );
            }
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
        vec!["az_disk_encryption_set".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_disk_encryption_set" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_disk_encryption_set', got '{}'",
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
                     'Microsoft.Compute/diskEncryptionSets/des-missing' was not found.";
        assert!(AzDiskEncryptionSetCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_des() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des-x'";
        assert!(AzDiskEncryptionSetCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/disk1'";
        assert!(!AzDiskEncryptionSetCollector::is_not_found(stderr));
    }

    #[test]
    fn parse_key_url_extracts_components() {
        let url = "https://kv-example.vault.azure.net/keys/my-cmk/abc123def456";
        let (vault, key, version) = AzDiskEncryptionSetCollector::parse_key_url(url);
        assert_eq!(vault.unwrap(), "kv-example");
        assert_eq!(key.unwrap(), "my-cmk");
        assert_eq!(version.unwrap(), "abc123def456");
    }
}
