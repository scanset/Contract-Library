//! Azure Public IP Address Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_public_ip;
//  pub use az_public_ip::AzPublicIpCollector;
//
///////////////////////////////////////////////////////

//! Single `az network public-ip show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! allocation method, IP version, SKU, DDoS protection mode, idle timeout,
//! zone count, association status, and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzPublicIpCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzPublicIpCollector {
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
            if lower.contains("/publicipaddresses/") {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzPublicIpCollector {
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
                reason: "'name' is required for az_public_ip".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_public_ip".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_public_ip".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "network".to_string(),
            "public-ip".to_string(),
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
        let target = format!("public-ip:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Public IP via Azure CLI")
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
                    "az network public-ip show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse public-ip show JSON: {}", e),
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
            ("ipAddress", "ip_address"),
            ("publicIPAllocationMethod", "allocation_method"),
            ("publicIPAddressVersion", "ip_version"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
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

        // DDoS protection mode
        if let Some(ddos_mode) = resp
            .get("ddosSettings")
            .and_then(|v| v.get("protectionMode"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "ddos_protection_mode".to_string(),
                ResolvedValue::String(ddos_mode.to_string()),
            );
        }

        // Idle timeout
        if let Some(timeout) = resp.get("idleTimeoutInMinutes").and_then(|v| v.as_i64()) {
            data.add_field(
                "idle_timeout_minutes".to_string(),
                ResolvedValue::Integer(timeout),
            );
        }

        // Zone count and zone_redundant derived boolean
        let zone_count = resp
            .get("zones")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "zone_count".to_string(),
            ResolvedValue::Integer(zone_count),
        );
        data.add_field(
            "zone_redundant".to_string(),
            ResolvedValue::Boolean(zone_count > 1),
        );

        // Association: is the PIP attached to something?
        let is_associated = resp.get("ipConfiguration").is_some()
            || resp.get("natGateway").is_some();
        data.add_field(
            "is_associated".to_string(),
            ResolvedValue::Boolean(is_associated),
        );

        // DNS FQDN (if dnsSettings present)
        if let Some(fqdn) = resp
            .get("dnsSettings")
            .and_then(|v| v.get("fqdn"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "dns_fqdn".to_string(),
                ResolvedValue::String(fqdn.to_string()),
            );
        }
        if let Some(domain_label) = resp
            .get("dnsSettings")
            .and_then(|v| v.get("domainNameLabel"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "dns_domain_label".to_string(),
                ResolvedValue::String(domain_label.to_string()),
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
        vec!["az_public_ip".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_public_ip" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_public_ip', got '{}'",
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
                     'Microsoft.Network/publicIPAddresses/pip-missing' was not found.";
        assert!(AzPublicIpCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_public_ip() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-x'";
        assert!(AzPublicIpCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1'";
        assert!(!AzPublicIpCollector::is_not_found(stderr));
    }
}
