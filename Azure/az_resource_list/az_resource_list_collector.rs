//! Azure ARM Resource List Collector
//!
//! Single `az resource list -o json` call (optionally narrowed by
//! `--resource-group` and/or `--resource-type`). Returns a single
//! CollectedData carrying `found`, `resource_count`, and the projected
//! record array as `resources` (RecordData).
//!
//! Each array element is the canonical snake-case shape the asset extractor
//! consumes. Fields always populated in this call: `id`, `name`, `type`,
//! `location`, `resource_group`, `provisioning_state`, `created_time`,
//! `changed_time`. Optional: `kind`, `sku_name`, `sku_tier`, `tags`. The
//! ARM `properties` blob is always null in `az resource list` and is
//! deliberately not surfaced — callers needing configuration data go
//! through typed `az_<resource>_list` contracts.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzResourceListCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzResourceListCollector {
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

    /// Project one ARM record into the canonical snake-case shape.
    /// Drops fields that are always null in `az resource list`
    /// (managedBy, plan, extendedLocation, identity, properties).
    fn project_record(item: &serde_json::Value) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        for (json_key, out_key) in &[
            ("id", "id"),
            ("name", "name"),
            ("type", "type"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("createdTime", "created_time"),
            ("changedTime", "changed_time"),
        ] {
            if let Some(v) = item.get(*json_key).and_then(|v| v.as_str()) {
                out.insert((*out_key).to_string(), serde_json::Value::String(v.to_string()));
            }
        }

        if let Some(v) = item.get("kind").and_then(|v| v.as_str()) {
            out.insert("kind".to_string(), serde_json::Value::String(v.to_string()));
        }

        if let Some(sku) = item.get("sku") {
            if let Some(v) = sku.get("name").and_then(|v| v.as_str()) {
                out.insert("sku_name".to_string(), serde_json::Value::String(v.to_string()));
            }
            if let Some(v) = sku.get("tier").and_then(|v| v.as_str()) {
                out.insert("sku_tier".to_string(), serde_json::Value::String(v.to_string()));
            }
        }

        if let Some(tags) = item.get("tags") {
            if !tags.is_null() {
                out.insert("tags".to_string(), tags.clone());
            }
        }

        serde_json::Value::Object(out)
    }
}

impl CtnDataCollector for AzResourceListCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        // Required: scope. Optional: subscription, resource_group, resource_type.
        let scope = self
            .extract_string_field(object, "scope")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `scope` (subscription | resource_group | resource_type)"
                    .to_string(),
            })?;
        let subscription = self.extract_string_field(object, "subscription");
        let resource_group_filter = self.extract_string_field(object, "resource_group");
        let resource_type_filter = self.extract_string_field(object, "resource_type");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_resource_list".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec!["resource".to_string(), "list".to_string()];
        if let Some(ref rg) = resource_group_filter {
            args.push("--resource-group".to_string());
            args.push(rg.clone());
        }
        if let Some(ref rt) = resource_type_filter {
            args.push("--resource-type".to_string());
            args.push(rt.clone());
        }
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("arm-list:{}", scope);

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Enumerate Azure resources via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("scope", &scope);
        if let Some(ref sub) = subscription {
            method_builder = method_builder.input("subscription", sub);
        }
        if let Some(ref rg) = resource_group_filter {
            method_builder = method_builder.input("resource_group", rg);
        }
        if let Some(ref rt) = resource_type_filter {
            method_builder = method_builder.input("resource_type", rt);
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
                    "az resource list failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az resource list JSON: {}", e),
            }
        })?;

        let raw_array = resp
            .as_array()
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "az resource list did not return a JSON array".to_string(),
            })?;

        let projected: Vec<serde_json::Value> =
            raw_array.iter().map(Self::project_record).collect();
        let count = projected.len() as i64;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "resource_count".to_string(),
            ResolvedValue::Integer(count),
        );

        let resources_record = RecordData::from_json_value(serde_json::Value::Array(projected));
        data.add_field(
            "resources".to_string(),
            ResolvedValue::RecordData(Box::new(resources_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_resource_list".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_resource_list" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_resource_list', got '{}'",
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
