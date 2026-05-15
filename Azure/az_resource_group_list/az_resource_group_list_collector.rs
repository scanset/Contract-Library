//! Azure Resource Group List Collector
//!
//! Single `az group list -o json [--subscription <id>]` call. Projects each
//! returned RG into the canonical snake_case shape and stuffs the array
//! into the `groups` RecordData field.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzResourceGroupListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzResourceGroupListCollector {
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

    /// Project one ARM resource-group record into the canonical
    /// snake-case shape. Hoists `properties.provisioningState` to a
    /// top-level `provisioning_state` for ergonomic STATE assertions.
    fn project_record(item: &serde_json::Value) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        for (json_key, out_key) in &[
            ("id", "id"),
            ("name", "name"),
            ("type", "type"),
            ("location", "location"),
        ] {
            if let Some(v) = item.get(*json_key).and_then(|v| v.as_str()) {
                out.insert((*out_key).to_string(), serde_json::Value::String(v.to_string()));
            }
        }

        if let Some(v) = item
            .get("properties")
            .and_then(|p| p.get("provisioningState"))
            .and_then(|v| v.as_str())
        {
            out.insert(
                "provisioning_state".to_string(),
                serde_json::Value::String(v.to_string()),
            );
        }

        if let Some(tags) = item.get("tags") {
            if !tags.is_null() {
                out.insert("tags".to_string(), tags.clone());
            }
        }

        if let Some(managed_by) = item.get("managedBy") {
            if !managed_by.is_null() {
                out.insert("managed_by".to_string(), managed_by.clone());
            }
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzResourceGroupListCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let scope = self
            .extract_string_field(object, "scope")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `scope` (subscription)".to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_resource_group_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec!["group".to_string(), "list".to_string()];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("rg-list:{}", scope);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure resource groups via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("scope", &scope);
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
                    "az group list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az group list JSON: {}", e),
            }
        })?;

        let raw_array = resp
            .as_array()
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "az group list did not return a JSON array".to_string(),
            })?;

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("group_count".to_string(), ResolvedValue::Integer(count));

        let groups_record = RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "groups".to_string(),
            ResolvedValue::RecordData(Box::new(groups_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_resource_group_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_resource_group_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_resource_group_list', got '{}'",
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
