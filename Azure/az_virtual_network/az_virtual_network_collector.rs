//! Azure Virtual Network (VNet) Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_virtual_network;
//  pub use az_virtual_network::AzVirtualNetworkCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzVirtualNetworkCollector::new(
//          "az-virtual-network-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzVirtualNetworkExecutor::new(
//          contracts::create_az_virtual_network_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az network vnet show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields for
//! address space, subnet inventory, peering status, DDoS protection, DNS
//! config, and flow log presence, plus the full response as RecordData for
//! tag-based and per-subnet record_checks.
//!
//! ## NotFound handling
//!
//! Same dual-pattern as other Azure CTNs:
//! - `(ResourceNotFound)` - real RG with missing/malformed VNet name
//! - `(AuthorizationFailed)` scoped to `/virtualNetworks/` - inaccessible RG

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzVirtualNetworkCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzVirtualNetworkCollector {
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
            if lower.contains("/virtualnetworks/") {
                return true;
            }
        }
        false
    }

    /// Count subnets that have no NSG attached.
    fn count_subnets_without_nsg(subnets: &serde_json::Value) -> i64 {
        let Some(arr) = subnets.as_array() else {
            return 0;
        };
        arr.iter()
            .filter(|s| {
                let nsg = s.get("networkSecurityGroup");
                nsg.is_none() || nsg == Some(&serde_json::Value::Null)
            })
            .count() as i64
    }

    /// Count subnets that have a route table attached.
    fn count_subnets_with_route_table(subnets: &serde_json::Value) -> i64 {
        let Some(arr) = subnets.as_array() else {
            return 0;
        };
        arr.iter()
            .filter(|s| {
                let rt = s.get("routeTable");
                rt.is_some() && rt != Some(&serde_json::Value::Null)
            })
            .count() as i64
    }

    /// Count subnets that have service endpoints configured.
    fn count_subnets_with_service_endpoints(subnets: &serde_json::Value) -> i64 {
        let Some(arr) = subnets.as_array() else {
            return 0;
        };
        arr.iter()
            .filter(|s| {
                s.get("serviceEndpoints")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .count() as i64
    }

    /// Count subnets that have delegations.
    fn count_subnets_with_delegations(subnets: &serde_json::Value) -> i64 {
        let Some(arr) = subnets.as_array() else {
            return 0;
        };
        arr.iter()
            .filter(|s| {
                s.get("delegations")
                    .and_then(|v| v.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .count() as i64
    }
}

impl CtnDataCollector for AzVirtualNetworkCollector {
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
                reason: "'name' is required for az_virtual_network".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_virtual_network (az network vnet \
                            show requires -g)"
                        .to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_virtual_network".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "network".to_string(),
            "vnet".to_string(),
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

        let target = format!("vnet:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Virtual Network via Azure CLI")
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
                    "az network vnet show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az network vnet show JSON: {}", e),
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
            ("etag", "etag"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // privateEndpointVNetPolicies
        if let Some(v) = resp
            .get("privateEndpointVNetPolicies")
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "private_endpoint_vnet_policies".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Address space - first prefix as primary, full count
        let empty_arr = serde_json::Value::Array(Vec::new());
        let address_prefixes = resp
            .get("addressSpace")
            .and_then(|v| v.get("addressPrefixes"))
            .unwrap_or(&empty_arr);
        let prefix_count = address_prefixes
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0) as i64;

        data.add_field(
            "address_prefix_count".to_string(),
            ResolvedValue::Integer(prefix_count),
        );
        if let Some(first) = address_prefixes
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "address_prefix".to_string(),
                ResolvedValue::String(first.to_string()),
            );
        }

        // DNS servers
        let dns_servers = resp
            .get("dhcpOptions")
            .and_then(|v| v.get("dnsServers"))
            .unwrap_or(&empty_arr);
        let dns_count = dns_servers.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        data.add_field(
            "dns_server_count".to_string(),
            ResolvedValue::Integer(dns_count),
        );
        data.add_field(
            "has_custom_dns".to_string(),
            ResolvedValue::Boolean(dns_count > 0),
        );

        // DDoS protection
        let ddos_enabled = resp
            .get("enableDdosProtection")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "ddos_protection_enabled".to_string(),
            ResolvedValue::Boolean(ddos_enabled),
        );

        // Subnets
        let subnets = resp.get("subnets").unwrap_or(&empty_arr);
        let subnet_count = subnets.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        data.add_field(
            "subnet_count".to_string(),
            ResolvedValue::Integer(subnet_count),
        );
        data.add_field(
            "has_subnets".to_string(),
            ResolvedValue::Boolean(subnet_count > 0),
        );

        // Subnet analysis
        let without_nsg = Self::count_subnets_without_nsg(subnets);
        data.add_field(
            "subnets_without_nsg_count".to_string(),
            ResolvedValue::Integer(without_nsg),
        );
        data.add_field(
            "all_subnets_have_nsg".to_string(),
            ResolvedValue::Boolean(subnet_count > 0 && without_nsg == 0),
        );

        let with_route_table = Self::count_subnets_with_route_table(subnets);
        data.add_field(
            "subnets_with_route_table_count".to_string(),
            ResolvedValue::Integer(with_route_table),
        );

        let with_service_endpoints = Self::count_subnets_with_service_endpoints(subnets);
        data.add_field(
            "subnets_with_service_endpoints_count".to_string(),
            ResolvedValue::Integer(with_service_endpoints),
        );

        let with_delegations = Self::count_subnets_with_delegations(subnets);
        data.add_field(
            "subnets_with_delegations_count".to_string(),
            ResolvedValue::Integer(with_delegations),
        );

        // Peerings
        let peerings = resp
            .get("virtualNetworkPeerings")
            .unwrap_or(&empty_arr);
        let peering_count = peerings.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        data.add_field(
            "peering_count".to_string(),
            ResolvedValue::Integer(peering_count),
        );
        data.add_field(
            "has_peerings".to_string(),
            ResolvedValue::Boolean(peering_count > 0),
        );

        // Flow logs
        let flow_logs = resp.get("flowLogs").unwrap_or(&empty_arr);
        let flow_log_count = flow_logs.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        data.add_field(
            "flow_log_count".to_string(),
            ResolvedValue::Integer(flow_log_count),
        );
        data.add_field(
            "has_flow_logs".to_string(),
            ResolvedValue::Boolean(flow_log_count > 0),
        );

        // Encryption (may be absent on older VNets)
        if let Some(enc) = resp.get("encryption") {
            let enc_enabled = enc
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            data.add_field(
                "encryption_enabled".to_string(),
                ResolvedValue::Boolean(enc_enabled),
            );
            if let Some(enforcement) = enc.get("enforcement").and_then(|v| v.as_str()) {
                data.add_field(
                    "encryption_enforcement".to_string(),
                    ResolvedValue::String(enforcement.to_string()),
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
        vec!["az_virtual_network".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_virtual_network" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_virtual_network', got '{}'",
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
                     'Microsoft.Network/virtualNetworks/vnet-missing' under resource group \
                     'rg-real' was not found.";
        assert!(AzVirtualNetworkCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_vnet() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg-gone/providers/Microsoft.Network/virtualNetworks/vnet-x'";
        assert!(AzVirtualNetworkCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'";
        assert!(!AzVirtualNetworkCollector::is_not_found(stderr));
    }

    #[test]
    fn subnets_without_nsg_counted() {
        let subnets = serde_json::json!([
            {"name": "snet-a", "networkSecurityGroup": {"id": "/sub/.../nsg-a"}},
            {"name": "snet-b", "networkSecurityGroup": null},
            {"name": "snet-c"}
        ]);
        assert_eq!(AzVirtualNetworkCollector::count_subnets_without_nsg(&subnets), 2);
    }

    #[test]
    fn subnets_with_route_table_counted() {
        let subnets = serde_json::json!([
            {"name": "snet-a", "routeTable": {"id": "/sub/.../rt-a"}},
            {"name": "snet-b", "routeTable": null},
            {"name": "snet-c"}
        ]);
        assert_eq!(AzVirtualNetworkCollector::count_subnets_with_route_table(&subnets), 1);
    }

    #[test]
    fn subnets_with_service_endpoints_counted() {
        let subnets = serde_json::json!([
            {"name": "snet-a", "serviceEndpoints": [{"service": "Microsoft.Storage"}]},
            {"name": "snet-b", "serviceEndpoints": []},
            {"name": "snet-c"}
        ]);
        assert_eq!(AzVirtualNetworkCollector::count_subnets_with_service_endpoints(&subnets), 1);
    }

    #[test]
    fn subnets_with_delegations_counted() {
        let subnets = serde_json::json!([
            {"name": "snet-a", "delegations": [{"name": "d1"}]},
            {"name": "snet-b", "delegations": []},
            {"name": "snet-c"}
        ]);
        assert_eq!(AzVirtualNetworkCollector::count_subnets_with_delegations(&subnets), 1);
    }
}
