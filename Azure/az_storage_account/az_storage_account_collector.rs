//! Azure Storage Account Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_storage_account;
//  pub use az_storage_account::AzStorageAccountCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzStorageAccountCollector::new(
//          "az-storage-account-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzStorageAccountExecutor::new(
//          contracts::create_az_storage_account_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az storage account show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields plus the
//! full response as RecordData for tag / nested-field record_checks.
//!
//! ## NotFound handling
//!
//! Azure returns TWO distinct error shapes for a non-existent account,
//! with TWO different exit codes:
//!
//! 1. **Real RG + missing/malformed name** - exit 3, stderr contains
//!    `(ResourceNotFound)`.
//! 2. **Missing or inaccessible RG** - exit 1, stderr contains
//!    `(AuthorizationFailed)` because RBAC scoping hides the distinction
//!    between "RG does not exist" and "caller has no access to RG".
//!
//! The collector matches on stderr content (not exit code) and treats both
//! as `found=false`. All other non-zero exits bubble up as
//! `CollectionError::CollectionFailed`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzStorageAccountCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzStorageAccountCollector {
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

    /// Extract blob-service-properties fields from the
    /// `az storage account blob-service-properties show` response.
    ///
    /// Azure response shape (abbreviated):
    /// ```json
    /// {
    ///   "deleteRetentionPolicy": { "enabled": true, "days": 7 },
    ///   "containerDeleteRetentionPolicy": { "enabled": true, "days": 7 },
    ///   "isVersioningEnabled": true,
    ///   "changeFeed": { "enabled": true },
    ///   "lastAccessTimeTrackingPolicy": { "enable": true }
    /// }
    /// ```
    fn extract_blob_service_properties(resp: &serde_json::Value, data: &mut CollectedData) {
        // deleteRetentionPolicy (blob soft delete)
        if let Some(drp) = resp.get("deleteRetentionPolicy") {
            let enabled = drp.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            data.add_field(
                "blob_soft_delete_enabled".to_string(),
                ResolvedValue::Boolean(enabled),
            );
            if let Some(days) = drp.get("days").and_then(|v| v.as_i64()) {
                data.add_field(
                    "blob_soft_delete_days".to_string(),
                    ResolvedValue::Integer(days),
                );
            }
        }

        // containerDeleteRetentionPolicy
        if let Some(cdrp) = resp.get("containerDeleteRetentionPolicy") {
            let enabled = cdrp.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            data.add_field(
                "container_soft_delete_enabled".to_string(),
                ResolvedValue::Boolean(enabled),
            );
            if let Some(days) = cdrp.get("days").and_then(|v| v.as_i64()) {
                data.add_field(
                    "container_soft_delete_days".to_string(),
                    ResolvedValue::Integer(days),
                );
            }
        }

        // isVersioningEnabled
        let versioning = resp
            .get("isVersioningEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "versioning_enabled".to_string(),
            ResolvedValue::Boolean(versioning),
        );

        // changeFeed.enabled
        let change_feed = resp
            .get("changeFeed")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "change_feed_enabled".to_string(),
            ResolvedValue::Boolean(change_feed),
        );

        // lastAccessTimeTrackingPolicy.enable (note: "enable" not "enabled")
        let last_access = resp
            .get("lastAccessTimeTrackingPolicy")
            .and_then(|v| v.get("enable"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "last_access_time_enabled".to_string(),
            ResolvedValue::Boolean(last_access),
        );
    }

    /// Returns true when Azure's error shape matches a genuine NotFound.
    ///
    /// Matches two distinct patterns:
    /// - `(ResourceNotFound)` - real RG with missing/malformed account name
    /// - `(AuthorizationFailed)` scoped to `/storageAccounts/` - fake or
    ///   inaccessible RG (Azure RBAC hides "forbidden" vs "missing")
    ///
    /// The AuthorizationFailed branch is additionally gated on the storage
    /// accounts scope substring to avoid silently swallowing unrelated RBAC
    /// failures elsewhere in the request pipeline.
    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/storageaccounts/") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzStorageAccountCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let name = self.extract_string_field(object, "name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'name' is required for az_storage_account".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_storage_account (az storage \
                            account show requires -g)"
                        .to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_storage_account".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "storage".to_string(),
            "account".to_string(),
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

        let target = format!("storage-account:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Storage Account via Azure CLI")
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
                    "az storage account show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az storage account show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("kind", "kind"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("accessTier", "access_tier"),
            ("provisioningState", "provisioning_state"),
            ("statusOfPrimary", "status_of_primary"),
            ("primaryLocation", "primary_location"),
            ("secondaryLocation", "secondary_location"),
            ("minimumTlsVersion", "minimum_tls_version"),
            ("publicNetworkAccess", "public_network_access"),
            ("dnsEndpointType", "dns_endpoint_type"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // top-level booleans
        for (json_key, field_name) in &[
            ("enableHttpsTrafficOnly", "enable_https_traffic_only"),
            ("allowBlobPublicAccess", "allow_blob_public_access"),
            ("allowSharedKeyAccess", "allow_shared_key_access"),
            ("allowCrossTenantReplication", "allow_cross_tenant_replication"),
            ("defaultToOAuthAuthentication", "default_to_oauth_authentication"),
            ("isHnsEnabled", "is_hns_enabled"),
            ("isSftpEnabled", "is_sftp_enabled"),
            ("isLocalUserEnabled", "is_local_user_enabled"),
            ("enableNfsV3", "enable_nfs_v3"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_bool()) {
                data.add_field(field_name.to_string(), ResolvedValue::Boolean(v));
            }
        }

        // sku.{name, tier}
        if let Some(sku) = resp.get("sku") {
            if let Some(v) = sku.get("name").and_then(|v| v.as_str()) {
                data.add_field("sku_name".to_string(), ResolvedValue::String(v.to_string()));
            }
            if let Some(v) = sku.get("tier").and_then(|v| v.as_str()) {
                data.add_field("sku_tier".to_string(), ResolvedValue::String(v.to_string()));
            }
        }

        // encryption.*
        if let Some(enc) = resp.get("encryption") {
            if let Some(v) = enc.get("keySource").and_then(|v| v.as_str()) {
                data.add_field(
                    "encryption_key_source".to_string(),
                    ResolvedValue::String(v.to_string()),
                );
                data.add_field(
                    "cmk_enabled".to_string(),
                    ResolvedValue::Boolean(v == "Microsoft.Keyvault"),
                );
            }
            // requireInfrastructureEncryption: null -> false (safe default)
            let require_infra = enc
                .get("requireInfrastructureEncryption")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            data.add_field(
                "require_infrastructure_encryption".to_string(),
                ResolvedValue::Boolean(require_infra),
            );

            if let Some(svcs) = enc.get("services") {
                for (json_key, field_name) in &[
                    ("blob", "blob_encryption_enabled"),
                    ("file", "file_encryption_enabled"),
                    ("queue", "queue_encryption_enabled"),
                    ("table", "table_encryption_enabled"),
                ] {
                    if let Some(svc) = svcs.get(*json_key) {
                        if !svc.is_null() {
                            if let Some(en) = svc.get("enabled").and_then(|v| v.as_bool()) {
                                data.add_field(
                                    field_name.to_string(),
                                    ResolvedValue::Boolean(en),
                                );
                            }
                        }
                    }
                }
            }
        }

        // keyCreationTime.{key1, key2}
        if let Some(kct) = resp.get("keyCreationTime") {
            for (json_key, field_name) in &[
                ("key1", "key_creation_time_key1"),
                ("key2", "key_creation_time_key2"),
            ] {
                if let Some(v) = kct.get(*json_key).and_then(|v| v.as_str()) {
                    data.add_field(
                        field_name.to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
            }
        }

        // immutableStorageWithVersioning.enabled
        let immutable_storage = resp
            .get("immutableStorageWithVersioning")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "immutable_storage_enabled".to_string(),
            ResolvedValue::Boolean(immutable_storage),
        );

        // largeFileSharesState — null or string
        if let Some(v) = resp.get("largeFileSharesState").and_then(|v| v.as_str()) {
            data.add_field(
                "large_file_shares_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // networkRuleSet.*
        if let Some(nrs) = resp.get("networkRuleSet") {
            if let Some(v) = nrs.get("defaultAction").and_then(|v| v.as_str()) {
                data.add_field(
                    "network_default_action".to_string(),
                    ResolvedValue::String(v.to_string()),
                );
                data.add_field(
                    "has_network_acls".to_string(),
                    ResolvedValue::Boolean(v == "Deny"),
                );
            }
            if let Some(v) = nrs.get("bypass").and_then(|v| v.as_str()) {
                data.add_field(
                    "network_bypass".to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
            let ip_count = nrs
                .get("ipRules")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0);
            data.add_field("ip_rule_count".to_string(), ResolvedValue::Integer(ip_count));
            let vnet_count = nrs
                .get("virtualNetworkRules")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "vnet_rule_count".to_string(),
                ResolvedValue::Integer(vnet_count),
            );
        }

        // privateEndpointConnections
        let pe_count = resp
            .get("privateEndpointConnections")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "private_endpoint_count".to_string(),
            ResolvedValue::Integer(pe_count),
        );
        data.add_field(
            "has_private_endpoints".to_string(),
            ResolvedValue::Boolean(pe_count > 0),
        );

        // identity.*
        if let Some(id_obj) = resp.get("identity") {
            let identity_type = id_obj
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("None")
                .to_string();
            data.add_field(
                "has_managed_identity".to_string(),
                ResolvedValue::Boolean(identity_type != "None"),
            );
            data.add_field(
                "identity_type".to_string(),
                ResolvedValue::String(identity_type),
            );
        } else {
            data.add_field(
                "has_managed_identity".to_string(),
                ResolvedValue::Boolean(false),
            );
            data.add_field(
                "identity_type".to_string(),
                ResolvedValue::String("None".to_string()),
            );
        }

        // -- Behavior-gated: blob-service-properties ----------------------
        //
        // `behavior include_blob_properties true` in the ESP policy triggers a
        // second API call: `az storage account blob-service-properties show`.
        // This surfaces soft delete, container delete retention, versioning,
        // change feed, and last-access-time tracking — all high-value
        // compliance fields that live outside the base `az storage account show`
        // response.
        let include_blob_props = hints
            .get_parameter_as_bool("include_blob_properties")
            .unwrap_or(false);
        if include_blob_props {
            let mut blob_args: Vec<String> = vec![
                "storage".to_string(),
                "account".to_string(),
                "blob-service-properties".to_string(),
                "show".to_string(),
                "--account-name".to_string(),
                name.clone(),
                "--resource-group".to_string(),
                resource_group.clone(),
            ];
            if let Some(ref sub) = subscription {
                blob_args.push("--subscription".to_string());
                blob_args.push(sub.clone());
            }
            blob_args.push("--output".to_string());
            blob_args.push("json".to_string());

            let blob_arg_refs: Vec<&str> = blob_args.iter().map(|s| s.as_str()).collect();
            match self
                .executor
                .execute("az", &blob_arg_refs, Some(Duration::from_secs(30)))
            {
                Ok(blob_output) if blob_output.exit_code == 0 => {
                    if let Ok(blob_resp) =
                        serde_json::from_str::<serde_json::Value>(blob_output.stdout.trim())
                    {
                        Self::extract_blob_service_properties(&blob_resp, &mut data);
                    }
                }
                _ => {
                    // Non-fatal: blob-service-properties is optional enrichment.
                    // Fields simply stay absent from collected data; STATE checks
                    // against them will produce Error (field missing), not silent
                    // false passes.
                }
            }
        }

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_storage_account".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_storage_account" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_storage_account', got '{}'",
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
                     'Microsoft.Storage/storageAccounts/stmissing' under resource group \
                     'rg-real' was not found.";
        assert!(AzStorageAccountCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found_code_line() {
        let stderr = "ERROR: something\nCode: ResourceNotFound\nMessage: whatever";
        assert!(AzStorageAccountCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_storage_account() {
        let stderr = "ERROR: (AuthorizationFailed) The client 'x' does not have authorization \
                     to perform action 'Microsoft.Storage/storageAccounts/read' over scope \
                     '/subscriptions/abc/resourceGroups/rg-gone/providers/Microsoft.Storage/storageAccounts/stx' \
                     or the scope is invalid.";
        assert!(AzStorageAccountCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'";
        assert!(!AzStorageAccountCollector::is_not_found(stderr));
    }

    #[test]
    fn forbidden_is_not_not_found() {
        let stderr = "ERROR: (Forbidden) Caller is not authorized to perform action on resource.";
        assert!(!AzStorageAccountCollector::is_not_found(stderr));
    }

    #[test]
    fn blob_service_properties_full_shape() {
        let resp = serde_json::json!({
            "deleteRetentionPolicy": { "enabled": true, "days": 14 },
            "containerDeleteRetentionPolicy": { "enabled": true, "days": 7 },
            "isVersioningEnabled": true,
            "changeFeed": { "enabled": true },
            "lastAccessTimeTrackingPolicy": { "enable": true }
        });
        let mut data = CollectedData::new("test".to_string(), "az_storage_account".to_string(), "t".to_string());
        AzStorageAccountCollector::extract_blob_service_properties(&resp, &mut data);

        assert_eq!(data.fields.get("blob_soft_delete_enabled"), Some(&ResolvedValue::Boolean(true)));
        assert_eq!(data.fields.get("blob_soft_delete_days"), Some(&ResolvedValue::Integer(14)));
        assert_eq!(data.fields.get("container_soft_delete_enabled"), Some(&ResolvedValue::Boolean(true)));
        assert_eq!(data.fields.get("container_soft_delete_days"), Some(&ResolvedValue::Integer(7)));
        assert_eq!(data.fields.get("versioning_enabled"), Some(&ResolvedValue::Boolean(true)));
        assert_eq!(data.fields.get("change_feed_enabled"), Some(&ResolvedValue::Boolean(true)));
        assert_eq!(data.fields.get("last_access_time_enabled"), Some(&ResolvedValue::Boolean(true)));
    }

    #[test]
    fn blob_service_properties_all_disabled() {
        let resp = serde_json::json!({
            "deleteRetentionPolicy": { "enabled": false },
            "containerDeleteRetentionPolicy": { "enabled": false },
            "isVersioningEnabled": false,
            "changeFeed": { "enabled": false },
            "lastAccessTimeTrackingPolicy": { "enable": false }
        });
        let mut data = CollectedData::new("test".to_string(), "az_storage_account".to_string(), "t".to_string());
        AzStorageAccountCollector::extract_blob_service_properties(&resp, &mut data);

        assert_eq!(data.fields.get("blob_soft_delete_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert!(data.fields.get("blob_soft_delete_days").is_none()); // days absent when disabled
        assert_eq!(data.fields.get("container_soft_delete_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert_eq!(data.fields.get("versioning_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert_eq!(data.fields.get("change_feed_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert_eq!(data.fields.get("last_access_time_enabled"), Some(&ResolvedValue::Boolean(false)));
    }

    #[test]
    fn blob_service_properties_empty_response() {
        let resp = serde_json::json!({});
        let mut data = CollectedData::new("test".to_string(), "az_storage_account".to_string(), "t".to_string());
        AzStorageAccountCollector::extract_blob_service_properties(&resp, &mut data);

        // Booleans default to false, days absent
        assert_eq!(data.fields.get("versioning_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert_eq!(data.fields.get("change_feed_enabled"), Some(&ResolvedValue::Boolean(false)));
        assert_eq!(data.fields.get("last_access_time_enabled"), Some(&ResolvedValue::Boolean(false)));
    }
}
