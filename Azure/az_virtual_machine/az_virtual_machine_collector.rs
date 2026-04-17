//! Azure Virtual Machine (VM) Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_virtual_machine;
//  pub use az_virtual_machine::AzVirtualMachineCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzVirtualMachineCollector::new(
//          "az-virtual-machine-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzVirtualMachineExecutor::new(
//          contracts::create_az_virtual_machine_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az vm show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! VM size, OS type, security profile, storage profile, identity,
//! boot diagnostics, extensions, and encryption, plus the full response
//! as RecordData for tag-based record_checks.
//!
//! ## NotFound handling
//!
//! Same dual-pattern as other Azure CTNs:
//! - `(ResourceNotFound)` - real RG with missing/malformed VM name
//! - `(AuthorizationFailed)` scoped to `/virtualMachines/` - inaccessible RG

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzVirtualMachineCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzVirtualMachineCollector {
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
            if lower.contains("/virtualmachines/") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzVirtualMachineCollector {
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
                reason: "'name' is required for az_virtual_machine".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_virtual_machine".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_virtual_machine".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "vm".to_string(),
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

        let target = format!("vm:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Virtual Machine via Azure CLI")
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
                    "az vm show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az vm show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("vmId", "vm_id"),
            ("priority", "priority"),
            ("timeCreated", "time_created"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // VM size
        if let Some(vm_size) = resp
            .get("hardwareProfile")
            .and_then(|v| v.get("vmSize"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "vm_size".to_string(),
                ResolvedValue::String(vm_size.to_string()),
            );
        }

        // Zone
        if let Some(zone) = resp
            .get("zones")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "availability_zone".to_string(),
                ResolvedValue::String(zone.to_string()),
            );
        }
        let has_zone = resp
            .get("zones")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        data.add_field(
            "has_availability_zone".to_string(),
            ResolvedValue::Boolean(has_zone),
        );

        // OS type from storage profile
        if let Some(os_type) = resp
            .get("storageProfile")
            .and_then(|v| v.get("osDisk"))
            .and_then(|v| v.get("osType"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "os_type".to_string(),
                ResolvedValue::String(os_type.to_string()),
            );
        }

        // OS disk fields
        if let Some(os_disk) = resp
            .get("storageProfile")
            .and_then(|v| v.get("osDisk"))
        {
            if let Some(size) = os_disk.get("diskSizeGB").and_then(|v| v.as_i64()) {
                data.add_field(
                    "os_disk_size_gb".to_string(),
                    ResolvedValue::Integer(size),
                );
            }
            if let Some(storage_type) = os_disk
                .get("managedDisk")
                .and_then(|v| v.get("storageAccountType"))
                .and_then(|v| v.as_str())
            {
                data.add_field(
                    "os_disk_storage_type".to_string(),
                    ResolvedValue::String(storage_type.to_string()),
                );
            }
            let has_des = os_disk
                .get("managedDisk")
                .and_then(|v| v.get("diskEncryptionSet"))
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            data.add_field(
                "os_disk_encrypted_with_cmk".to_string(),
                ResolvedValue::Boolean(has_des),
            );
        }

        // Data disks
        let data_disk_count = resp
            .get("storageProfile")
            .and_then(|v| v.get("dataDisks"))
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "data_disk_count".to_string(),
            ResolvedValue::Integer(data_disk_count),
        );

        // Disk controller type
        if let Some(dc_type) = resp
            .get("storageProfile")
            .and_then(|v| v.get("diskControllerType"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "disk_controller_type".to_string(),
                ResolvedValue::String(dc_type.to_string()),
            );
        }

        // Image reference
        if let Some(image_ref) = resp
            .get("storageProfile")
            .and_then(|v| v.get("imageReference"))
        {
            for (json_key, field_name) in &[
                ("publisher", "image_publisher"),
                ("offer", "image_offer"),
                ("sku", "image_sku"),
                ("exactVersion", "image_version"),
            ] {
                if let Some(v) = image_ref.get(*json_key).and_then(|v| v.as_str()) {
                    data.add_field(
                        field_name.to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
            }
        }

        // OS profile
        if let Some(os_profile) = resp.get("osProfile") {
            if let Some(admin) = os_profile.get("adminUsername").and_then(|v| v.as_str()) {
                data.add_field(
                    "admin_username".to_string(),
                    ResolvedValue::String(admin.to_string()),
                );
            }
            let allow_ext = os_profile
                .get("allowExtensionOperations")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            data.add_field(
                "allow_extension_operations".to_string(),
                ResolvedValue::Boolean(allow_ext),
            );

            // Linux-specific
            if let Some(linux_config) = os_profile.get("linuxConfiguration") {
                let disable_pw = linux_config
                    .get("disablePasswordAuthentication")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                data.add_field(
                    "password_auth_disabled".to_string(),
                    ResolvedValue::Boolean(disable_pw),
                );
                let provision_agent = linux_config
                    .get("provisionVMAgent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                data.add_field(
                    "vm_agent_provisioned".to_string(),
                    ResolvedValue::Boolean(provision_agent),
                );
                if let Some(patch_mode) = linux_config
                    .get("patchSettings")
                    .and_then(|v| v.get("patchMode"))
                    .and_then(|v| v.as_str())
                {
                    data.add_field(
                        "patch_mode".to_string(),
                        ResolvedValue::String(patch_mode.to_string()),
                    );
                }
            }

            // Windows-specific
            if let Some(win_config) = os_profile.get("windowsConfiguration") {
                let provision_agent = win_config
                    .get("provisionVMAgent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                data.add_field(
                    "vm_agent_provisioned".to_string(),
                    ResolvedValue::Boolean(provision_agent),
                );
                if let Some(patch_mode) = win_config
                    .get("patchSettings")
                    .and_then(|v| v.get("patchMode"))
                    .and_then(|v| v.as_str())
                {
                    data.add_field(
                        "patch_mode".to_string(),
                        ResolvedValue::String(patch_mode.to_string()),
                    );
                }
            }
        }

        // Boot diagnostics
        let boot_diag_enabled = resp
            .get("diagnosticsProfile")
            .and_then(|v| v.get("bootDiagnostics"))
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "boot_diagnostics_enabled".to_string(),
            ResolvedValue::Boolean(boot_diag_enabled),
        );

        // Identity
        if let Some(identity) = resp.get("identity") {
            if let Some(id_type) = identity.get("type").and_then(|v| v.as_str()) {
                data.add_field(
                    "identity_type".to_string(),
                    ResolvedValue::String(id_type.to_string()),
                );
            }
            data.add_field(
                "has_managed_identity".to_string(),
                ResolvedValue::Boolean(true),
            );
        } else {
            data.add_field(
                "has_managed_identity".to_string(),
                ResolvedValue::Boolean(false),
            );
        }

        // Security profile (may be absent)
        let security_profile = resp.get("securityProfile");
        let secure_boot = security_profile
            .and_then(|v| v.get("uefiSettings"))
            .and_then(|v| v.get("secureBootEnabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let vtpm = security_profile
            .and_then(|v| v.get("uefiSettings"))
            .and_then(|v| v.get("vTpmEnabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let encryption_at_host = security_profile
            .and_then(|v| v.get("encryptionAtHost"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "secure_boot_enabled".to_string(),
            ResolvedValue::Boolean(secure_boot),
        );
        data.add_field(
            "vtpm_enabled".to_string(),
            ResolvedValue::Boolean(vtpm),
        );
        data.add_field(
            "encryption_at_host".to_string(),
            ResolvedValue::Boolean(encryption_at_host),
        );

        if let Some(sec_type) = security_profile
            .and_then(|v| v.get("securityType"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "security_type".to_string(),
                ResolvedValue::String(sec_type.to_string()),
            );
        }

        // Extensions (resources array)
        let extensions = resp
            .get("resources")
            .and_then(|v| v.as_array());
        let extension_count = extensions.map(|a| a.len() as i64).unwrap_or(0);
        data.add_field(
            "extension_count".to_string(),
            ResolvedValue::Integer(extension_count),
        );

        // Check for MDE extension
        let has_mde = extensions
            .map(|exts| {
                exts.iter().any(|ext| {
                    ext.get("name")
                        .and_then(|v| v.as_str())
                        .map(|n| n.starts_with("MDE."))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        data.add_field(
            "mde_extension_installed".to_string(),
            ResolvedValue::Boolean(has_mde),
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
        vec!["az_virtual_machine".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_virtual_machine" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_virtual_machine', got '{}'",
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
                     'Microsoft.Compute/virtualMachines/vm-missing' was not found.";
        assert!(AzVirtualMachineCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_vm() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-x'";
        assert!(AzVirtualMachineCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1'";
        assert!(!AzVirtualMachineCollector::is_not_found(stderr));
    }
}
