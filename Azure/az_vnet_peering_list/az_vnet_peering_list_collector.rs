//! Azure VNet Peering List Collector
//!
//! Wraps `az network vnet peering list -g <rg> --vnet-name <vnet> -o json`.
//! Hoists the cross-link `remoteVirtualNetwork.id` to a top-level
//! `remote_vnet_id` field — that's the single most useful piece of data
//! for reconstructing the hub-spoke topology in the asset graph.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzVnetPeeringListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzVnetPeeringListCollector {
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

    fn project_record(item: &serde_json::Value) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        for (json_key, out_key) in &[
            ("id", "id"),
            ("name", "name"),
            ("type", "type"),
            ("resourceGroup", "resource_group"),
            ("peeringState", "peering_state"),
            ("peeringSyncLevel", "peering_sync_level"),
            ("provisioningState", "provisioning_state"),
        ] {
            if let Some(v) = item.get(*json_key).and_then(|v| v.as_str()) {
                if !v.is_empty() {
                    out.insert(
                        (*out_key).to_string(),
                        serde_json::Value::String(v.to_string()),
                    );
                }
            }
        }

        for (json_key, out_key) in &[
            ("allowForwardedTraffic", "allow_forwarded_traffic"),
            ("allowGatewayTransit", "allow_gateway_transit"),
            ("allowVirtualNetworkAccess", "allow_virtual_network_access"),
            ("useRemoteGateways", "use_remote_gateways"),
        ] {
            if let Some(v) = item.get(*json_key).and_then(|v| v.as_bool()) {
                out.insert((*out_key).to_string(), serde_json::Value::Bool(v));
            }
        }

        // Hoist the remote VNet cross-link — most useful nested field.
        if let Some(remote) = item.get("remoteVirtualNetwork") {
            if let Some(v) = remote.get("id").and_then(|v| v.as_str()) {
                out.insert(
                    "remote_vnet_id".to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
            if let Some(v) = remote.get("resourceGroup").and_then(|v| v.as_str()) {
                out.insert(
                    "remote_vnet_resource_group".to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
        }

        // Hoist remote address space (array of CIDRs).
        if let Some(arr) = item
            .get("remoteAddressSpace")
            .and_then(|s| s.get("addressPrefixes"))
            .and_then(|v| v.as_array())
        {
            if !arr.is_empty() {
                out.insert(
                    "remote_address_prefixes".to_string(),
                    serde_json::Value::Array(arr.clone()),
                );
            }
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzVnetPeeringListCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let resource_group = self
            .extract_string_field(object, "resource_group")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `resource_group`".to_string(),
            })?;
        let vnet_name = self
            .extract_string_field(object, "vnet_name")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `vnet_name`".to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_vnet_peering_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "network".to_string(),
            "vnet".to_string(),
            "peering".to_string(),
            "list".to_string(),
            "--resource-group".to_string(),
            resource_group.clone(),
            "--vnet-name".to_string(),
            vnet_name.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("vnet-peering-list:{}/{}", resource_group, vnet_name);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure VNet peerings via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("resource_group", &resource_group)
            .input("vnet_name", &vnet_name);
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
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az network vnet peering list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az vnet peering list JSON: {}", e),
            }
        })?;

        let raw_array = resp
            .as_array()
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "az vnet peering list did not return a JSON array".to_string(),
            })?;

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("peering_count".to_string(), ResolvedValue::Integer(count));

        let peerings_record = RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "peerings".to_string(),
            ResolvedValue::RecordData(Box::new(peerings_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_vnet_peering_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_vnet_peering_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_vnet_peering_list', got '{}'",
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
