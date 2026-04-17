//! Azure Key Vault Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_key_vault;
//  pub use az_key_vault::AzKeyVaultCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzKeyVaultCollector::new(
//          "az-key-vault-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzKeyVaultExecutor::new(
//          contracts::create_az_key_vault_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az keyvault show --name <name> [--resource-group <rg>]
//! [--subscription <id>] --output json` call. Returns scalar fields plus the
//! full response as RecordData for tag / nested-field record_checks.
//!
//! ## NotFound handling
//!
//! `az keyvault show` on a nonexistent vault exits 1 with stderr:
//!
//!     ERROR: The Vault 'X' not found within subscription.
//!
//! This also covers malformed inputs (e.g. `--name x` — Azure returns
//! NotFound, not a validation error). Single substring match
//! `"not found within subscription"` covers both. All other non-zero exits
//! bubble up as `CollectionError::CollectionFailed`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzKeyVaultCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzKeyVaultCollector {
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
        stderr.contains("not found within subscription")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("(NotFound)")
    }

    /// Extract the five networkAcls-derived scalars from the `properties`
    /// object. Returns (default_action, bypass, ip_rule_count,
    /// vnet_rule_count, denies_by_default). When `networkAcls` is absent
    /// the two strings are empty, the two counts are 0, and
    /// denies_by_default is false.
    ///
    /// Azure-observed casing is capitalized (`"Deny"`, `"Allow"`,
    /// `"AzureServices"`, `"None"`); stored as-emitted so ESP policy
    /// authors match the API spelling. `denies_by_default` does a
    /// case-insensitive comparison to survive any future API drift in
    /// casing.
    fn extract_network_acl_fields(
        properties: &serde_json::Value,
    ) -> (String, String, i64, i64, bool) {
        let acls = properties.get("networkAcls");
        let acls = match acls {
            Some(v) if !v.is_null() => v,
            _ => return (String::new(), String::new(), 0, 0, false),
        };
        let default_action = acls
            .get("defaultAction")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let bypass = acls
            .get("bypass")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ip_rule_count = acls
            .get("ipRules")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let vnet_rule_count = acls
            .get("virtualNetworkRules")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let denies_by_default = default_action.eq_ignore_ascii_case("Deny");
        (
            default_action,
            bypass,
            ip_rule_count,
            vnet_rule_count,
            denies_by_default,
        )
    }
}

impl CtnDataCollector for AzKeyVaultCollector {
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
                reason: "'name' is required for az_key_vault".to_string(),
            }
        })?;
        let resource_group = self.extract_string_field(object, "resource_group");
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_key_vault".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "keyvault".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
        ];
        if let Some(ref rg) = resource_group {
            args.push("--resource-group".to_string());
            args.push(rg.clone());
        }
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));

        let target = format!("key-vault:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Key Vault via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name);
        if let Some(ref rg) = resource_group {
            method_builder = method_builder.input("resource_group", rg);
        }
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
                    "az keyvault show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az keyvault show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("type", "type"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        let props = resp.get("properties");

        // properties.* strings
        if let Some(p) = props {
            for (json_key, field_name) in &[
                ("vaultUri", "vault_uri"),
                ("tenantId", "tenant_id"),
                ("provisioningState", "provisioning_state"),
                ("publicNetworkAccess", "public_network_access"),
            ] {
                if let Some(v) = p.get(*json_key).and_then(|v| v.as_str()) {
                    data.add_field(
                        field_name.to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
            }

            // sku.{family, name}
            if let Some(sku) = p.get("sku") {
                if let Some(v) = sku.get("family").and_then(|v| v.as_str()) {
                    data.add_field("sku_family".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = sku.get("name").and_then(|v| v.as_str()) {
                    data.add_field("sku_name".to_string(), ResolvedValue::String(v.to_string()));
                }
            }

            // booleans
            for (json_key, field_name) in &[
                ("enableRbacAuthorization", "enable_rbac_authorization"),
                ("enablePurgeProtection", "enable_purge_protection"),
                ("enableSoftDelete", "enable_soft_delete"),
                ("enabledForDeployment", "enabled_for_deployment"),
                ("enabledForDiskEncryption", "enabled_for_disk_encryption"),
                ("enabledForTemplateDeployment", "enabled_for_template_deployment"),
            ] {
                if let Some(v) = p.get(*json_key).and_then(|v| v.as_bool()) {
                    data.add_field(field_name.to_string(), ResolvedValue::Boolean(v));
                }
            }

            // softDeleteRetentionInDays — nullable; omit when null
            if let Some(n) = p.get("softDeleteRetentionInDays").and_then(|v| v.as_i64()) {
                data.add_field(
                    "soft_delete_retention_days".to_string(),
                    ResolvedValue::Integer(n),
                );
            }

            // derived: has_network_acls = networkAcls is not null
            let has_acls = p
                .get("networkAcls")
                .map(|v| !v.is_null())
                .unwrap_or(false);
            data.add_field(
                "has_network_acls".to_string(),
                ResolvedValue::Boolean(has_acls),
            );

            // networkAcls detail: default_action, bypass, ip/vnet counts,
            // and the derived denies_by_default boolean. All come from
            // the same `az keyvault show` response - zero extra API calls.
            let (acl_default_action, acl_bypass, acl_ip_count, acl_vnet_count, acl_denies) =
                Self::extract_network_acl_fields(p);
            data.add_field(
                "network_acl_default_action".to_string(),
                ResolvedValue::String(acl_default_action),
            );
            data.add_field(
                "network_acl_bypass".to_string(),
                ResolvedValue::String(acl_bypass),
            );
            data.add_field(
                "network_acl_ip_rule_count".to_string(),
                ResolvedValue::Integer(acl_ip_count),
            );
            data.add_field(
                "network_acl_vnet_rule_count".to_string(),
                ResolvedValue::Integer(acl_vnet_count),
            );
            data.add_field(
                "network_acl_denies_by_default".to_string(),
                ResolvedValue::Boolean(acl_denies),
            );

            // derived: access_policy_count
            let ap_count = p
                .get("accessPolicies")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "access_policy_count".to_string(),
                ResolvedValue::Integer(ap_count),
            );

            // derived: private_endpoint_count — null or array
            let pe_count = p
                .get("privateEndpointConnections")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "private_endpoint_count".to_string(),
                ResolvedValue::Integer(pe_count),
            );
        }

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_key_vault".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_key_vault" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_key_vault', got '{}'",
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
    fn not_found_matches_vault_not_found_in_subscription() {
        let stderr = "ERROR: The Vault 'kv-esp-test-nonexistent-xyz' not found within subscription.";
        assert!(AzKeyVaultCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_malformed_short_name() {
        let stderr = "ERROR: The Vault 'x' not found within subscription.";
        assert!(AzKeyVaultCollector::is_not_found(stderr));
    }

    #[test]
    fn forbidden_is_not_not_found() {
        let stderr = "ERROR: (Forbidden) Caller is not authorized to perform action on resource.";
        assert!(!AzKeyVaultCollector::is_not_found(stderr));
    }

    #[test]
    fn network_acls_absent_yields_empty_zero_false() {
        let props = serde_json::json!({
            "provisioningState": "Succeeded"
        });
        let (da, bp, ip, vn, dn) = AzKeyVaultCollector::extract_network_acl_fields(&props);
        assert_eq!(da, "");
        assert_eq!(bp, "");
        assert_eq!(ip, 0);
        assert_eq!(vn, 0);
        assert!(!dn);
    }

    #[test]
    fn network_acls_null_yields_empty_zero_false() {
        let props = serde_json::json!({ "networkAcls": null });
        let (da, bp, ip, vn, dn) = AzKeyVaultCollector::extract_network_acl_fields(&props);
        assert_eq!(da, "");
        assert_eq!(bp, "");
        assert_eq!(ip, 0);
        assert_eq!(vn, 0);
        assert!(!dn);
    }

    #[test]
    fn network_acls_deny_with_rules_parses_all_five() {
        let props = serde_json::json!({
            "networkAcls": {
                "defaultAction": "Deny",
                "bypass": "AzureServices",
                "ipRules": [
                    {"value": "203.0.113.0/24"},
                    {"value": "198.51.100.7/32"}
                ],
                "virtualNetworkRules": [
                    {"id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/sn"}
                ]
            }
        });
        let (da, bp, ip, vn, dn) = AzKeyVaultCollector::extract_network_acl_fields(&props);
        assert_eq!(da, "Deny");
        assert_eq!(bp, "AzureServices");
        assert_eq!(ip, 2);
        assert_eq!(vn, 1);
        assert!(dn);
    }

    #[test]
    fn network_acls_allow_default_denies_by_default_false() {
        let props = serde_json::json!({
            "networkAcls": {
                "defaultAction": "Allow",
                "bypass": "None",
                "ipRules": [],
                "virtualNetworkRules": []
            }
        });
        let (da, bp, ip, vn, dn) = AzKeyVaultCollector::extract_network_acl_fields(&props);
        assert_eq!(da, "Allow");
        assert_eq!(bp, "None");
        assert_eq!(ip, 0);
        assert_eq!(vn, 0);
        assert!(!dn);
    }

    #[test]
    fn network_acls_lowercase_deny_still_denies_by_default() {
        // Defensive: survives any future casing drift from the API.
        let props = serde_json::json!({
            "networkAcls": {
                "defaultAction": "deny",
                "bypass": "AzureServices"
            }
        });
        let (da, _, _, _, dn) = AzKeyVaultCollector::extract_network_acl_fields(&props);
        assert_eq!(da, "deny");
        assert!(dn);
    }
}
