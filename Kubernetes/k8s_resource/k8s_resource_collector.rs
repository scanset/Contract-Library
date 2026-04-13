//! Kubernetes Resource Collector
//!
//! Runs `kubectl get <kind> [-n <ns>] [-l <selector>] [<name>] -o json`
//! and parses the response. Returns the first matching item's JSON as
//! RecordData, plus found/count scalars.
//!
//! Authentication: kubectl uses the kubeconfig from KUBECONFIG env var or
//! default ~/.kube/config. For kind clusters, the context is set automatically.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod k8s_resource;
//  pub use k8s_resource::K8sResourceCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct K8sResourceCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl K8sResourceCollector {
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
}

impl CtnDataCollector for K8sResourceCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let kind = self
            .extract_string_field(object, "kind")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'kind'".to_string(),
            })?;

        let namespace = self.extract_string_field(object, "namespace");
        let name = self.extract_string_field(object, "name");
        let name_prefix = self.extract_string_field(object, "name_prefix");
        let label_selector = self.extract_string_field(object, "label_selector");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "k8s_resource".to_string(),
            self.id.clone(),
        );

        // Build kubectl args: get <kind> [-n <ns>] [-l <selector>] [<name>] -o json
        let kind_lower = kind.to_lowercase();
        let mut args: Vec<String> = vec!["get".to_string(), kind_lower.clone()];

        if let Some(ns) = &namespace {
            args.push("-n".to_string());
            args.push(ns.clone());
        }

        if let Some(selector) = &label_selector {
            args.push("-l".to_string());
            args.push(selector.clone());
        }

        if let Some(n) = &name {
            args.push(n.clone());
        }

        args.push("-o".to_string());
        args.push("json".to_string());

        let command_str = format!("kubectl {}", args.join(" "));

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query Kubernetes API resource")
            .target(&kind)
            .command(&command_str)
            .input("kind", &kind)
            .build();
        data.set_method(method);

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self
            .executor
            .execute("kubectl", &arg_refs, Some(Duration::from_secs(30)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute kubectl: {}", e),
            })?;

        if output.exit_code != 0 {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            data.add_field("count".to_string(), ResolvedValue::Integer(0));
            return Ok(data);
        }

        // Parse JSON response
        let json_result: serde_json::Value = serde_json::from_str(output.stdout.trim())
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse kubectl JSON output: {}", e),
            })?;

        // kubectl get returns either a List (with items) or a single resource
        let items: Vec<&serde_json::Value> = if json_result.get("items").is_some() {
            // List response
            json_result["items"]
                .as_array()
                .map(|a| a.iter().collect())
                .unwrap_or_default()
        } else {
            // Single resource response
            vec![&json_result]
        };

        // Apply name_prefix filter if specified (client-side)
        let filtered: Vec<&serde_json::Value> = if let Some(prefix) = &name_prefix {
            items
                .into_iter()
                .filter(|item| {
                    item.get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(|n| n.as_str())
                        .map(|n| n.starts_with(prefix.as_str()))
                        .unwrap_or(false)
                })
                .collect()
        } else {
            items
        };

        let count = filtered.len() as i64;
        let found = count > 0;

        data.add_field("found".to_string(), ResolvedValue::Boolean(found));
        data.add_field("count".to_string(), ResolvedValue::Integer(count));

        // Store the first item's JSON as record data for field-level checks
        if found {
            let record_json = if filtered.len() == 1 {
                filtered[0].to_string()
            } else {
                serde_json::Value::Array(filtered.iter().map(|v| (*v).clone()).collect())
                    .to_string()
            };
            data.add_field(
                "record".to_string(),
                ResolvedValue::String(record_json),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["k8s_resource".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "k8s_resource" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'k8s_resource', got '{}'",
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
