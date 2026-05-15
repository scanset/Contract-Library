//! Azure NSG Rule List Collector
//!
//! Wraps `az network nsg rule list -g <rg> --nsg-name <nsg> -o json`.
//! Note: this returns only **custom** rules; default rules live on the
//! parent NSG's `defaultSecurityRules` array.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzNsgRuleListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzNsgRuleListCollector {
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
            ("access", "access"),
            ("direction", "direction"),
            ("protocol", "protocol"),
            ("provisioningState", "provisioning_state"),
            ("destinationAddressPrefix", "destination_address_prefix"),
            ("destinationPortRange", "destination_port_range"),
            ("sourceAddressPrefix", "source_address_prefix"),
            ("sourcePortRange", "source_port_range"),
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

        if let Some(v) = item.get("priority").and_then(|v| v.as_i64()) {
            out.insert(
                "priority".to_string(),
                serde_json::Value::Number(serde_json::Number::from(v)),
            );
        }

        // Surface multi-value prefix/port arrays only when non-empty.
        for (json_key, out_key) in &[
            ("destinationAddressPrefixes", "destination_address_prefixes"),
            ("destinationPortRanges", "destination_port_ranges"),
            ("sourceAddressPrefixes", "source_address_prefixes"),
            ("sourcePortRanges", "source_port_ranges"),
        ] {
            if let Some(arr) = item.get(*json_key).and_then(|v| v.as_array()) {
                if !arr.is_empty() {
                    out.insert((*out_key).to_string(), serde_json::Value::Array(arr.clone()));
                }
            }
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzNsgRuleListCollector {
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
        let nsg_name = self
            .extract_string_field(object, "nsg_name")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `nsg_name`".to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_nsg_rule_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "network".to_string(),
            "nsg".to_string(),
            "rule".to_string(),
            "list".to_string(),
            "--resource-group".to_string(),
            resource_group.clone(),
            "--nsg-name".to_string(),
            nsg_name.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("nsg-rule-list:{}/{}", resource_group, nsg_name);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure NSG security rules via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("resource_group", &resource_group)
            .input("nsg_name", &nsg_name);
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
                    "az network nsg rule list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az nsg rule list JSON: {}", e),
            }
        })?;

        let raw_array = resp
            .as_array()
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "az nsg rule list did not return a JSON array".to_string(),
            })?;

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("rule_count".to_string(), ResolvedValue::Integer(count));

        let rules_record = RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "rules".to_string(),
            ResolvedValue::RecordData(Box::new(rules_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_nsg_rule_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_nsg_rule_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_nsg_rule_list', got '{}'",
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
