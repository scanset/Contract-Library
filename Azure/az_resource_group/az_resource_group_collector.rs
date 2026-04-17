//! Azure Resource Group Collector
//!
//! Single `az group show --name <name> [--subscription <id>] --output json` call.
//! Returns scalar fields plus the full response as RecordData for tag checks.
//!
//! ## NotFound handling
//!
//! Two distinct cases present as a non-zero exit from `az`:
//!
//! 1. **ResourceGroupNotFound** — returned when the caller has subscription-scope
//!    Reader and the RG genuinely does not exist.
//! 2. **AuthorizationFailed** — returned when the caller has Reader scoped to
//!    specific RGs (enumeration protection): Azure cannot distinguish "missing"
//!    from "forbidden" for a non-existent target inside the caller's blind spot.
//!    We match this as NotFound only when the scope string in the error
//!    explicitly names the requested RG — any other AuthorizationFailed is a
//!    real collection failure.
//!
//! Both resolve to `found=false` with an empty RecordData. All other non-zero
//! exits bubble up as `CollectionError::CollectionFailed`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzResourceGroupCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzResourceGroupCollector {
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

    fn is_not_found(stderr: &str, rg_name: &str) -> bool {
        if stderr.contains("ResourceGroupNotFound") || stderr.contains("could not be found") {
            return true;
        }
        // RG-scoped Reader: AuthorizationFailed whose scope names this RG.
        // Azure lowercases `resourcegroups/` in error scopes regardless of
        // how the caller cased the name, so match case-insensitively.
        if stderr.contains("AuthorizationFailed") {
            let needle = format!("resourcegroups/{}", rg_name.to_lowercase());
            if stderr.to_lowercase().contains(&needle) {
                return true;
            }
        }
        false
    }
}

impl CtnDataCollector for AzResourceGroupCollector {
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
                reason: "'name' is required for az_resource_group".to_string(),
            }
        })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_resource_group".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> =
            vec!["group".to_string(), "show".to_string(), "--name".to_string(), name.clone()];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));

        let target = format!("resource-group:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure resource group via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name);
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
            if Self::is_not_found(&output.stderr, &name) {
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
                    "az group show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az group show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = resp.get("name").and_then(|v| v.as_str()) {
            data.add_field("name".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = resp.get("id").and_then(|v| v.as_str()) {
            data.add_field("id".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = resp.get("location").and_then(|v| v.as_str()) {
            data.add_field("location".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = resp
            .get("properties")
            .and_then(|p| p.get("provisioningState"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "provisioning_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        // managedBy: null → empty string; string → value
        let managed_by = resp
            .get("managedBy")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        data.add_field("managed_by".to_string(), ResolvedValue::String(managed_by));

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_resource_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_resource_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_resource_group', got '{}'",
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
    fn not_found_matches_resource_group_not_found() {
        let stderr = "ERROR: (ResourceGroupNotFound) Resource group 'foo' could not be found.";
        assert!(AzResourceGroupCollector::is_not_found(stderr, "foo"));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_rg() {
        let stderr = "ERROR: (AuthorizationFailed) The client 'x' does not have authorization \
                      to perform action 'Microsoft.Resources/subscriptions/resourcegroups/read' \
                      over scope '/subscriptions/abc/resourcegroups/rg-does-not-exist-xyz' or \
                      the scope is invalid.";
        assert!(AzResourceGroupCollector::is_not_found(
            stderr,
            "rg-does-not-exist-xyz"
        ));
    }

    #[test]
    fn not_found_case_insensitive_on_rg_name() {
        let stderr = "AuthorizationFailed ... scope '/subscriptions/abc/resourceGroups/RG-Mixed' ...";
        assert!(AzResourceGroupCollector::is_not_found(stderr, "rg-mixed"));
    }

    #[test]
    fn authz_failed_for_different_scope_is_not_not_found() {
        let stderr = "AuthorizationFailed ... scope '/subscriptions/abc/resourceGroups/other-rg' ...";
        assert!(!AzResourceGroupCollector::is_not_found(
            stderr, "rg-requested"
        ));
    }
}
