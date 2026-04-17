//! Azure Defender for Cloud Pricing Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_defender_pricing;
//  pub use az_defender_pricing::AzDefenderPricingCollector;
//
///////////////////////////////////////////////////////

//! Single `az security pricing show --name <plan> [--subscription <id>]
//! --output json` call. Returns pricing tier, sub-plan, deprecation status,
//! extension count, and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzDefenderPricingCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzDefenderPricingCollector {
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
        // Defender pricing returns InvalidResourceName for unknown plan names
        stderr.contains("(InvalidResourceName)")
            || stderr.contains("Code: InvalidResourceName")
    }
}

impl CtnDataCollector for AzDefenderPricingCollector {
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
                reason: "'name' is required for az_defender_pricing".to_string(),
            }
        })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_defender_pricing".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "security".to_string(),
            "pricing".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("defender-pricing:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Defender for Cloud pricing via Azure CLI")
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
                    "az security pricing show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|e| {
                CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Failed to parse security pricing show JSON: {}", e),
                }
            })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("pricingTier", "pricing_tier"),
            ("freeTrialRemainingTime", "free_trial_remaining"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // subPlan (nullable string)
        if let Some(v) = resp.get("subPlan").and_then(|v| v.as_str()) {
            data.add_field(
                "sub_plan".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        } else {
            data.add_field(
                "sub_plan".to_string(),
                ResolvedValue::String("none".to_string()),
            );
        }

        // enablementTime (nullable string)
        if let Some(v) = resp.get("enablementTime").and_then(|v| v.as_str()) {
            data.add_field(
                "enablement_time".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // deprecated (nullable bool -> boolean)
        let is_deprecated = resp
            .get("deprecated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "deprecated".to_string(),
            ResolvedValue::Boolean(is_deprecated),
        );

        // extensions array -> extension_count + has_extensions
        let extension_count = resp
            .get("extensions")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "extension_count".to_string(),
            ResolvedValue::Integer(extension_count),
        );
        data.add_field(
            "has_extensions".to_string(),
            ResolvedValue::Boolean(extension_count > 0),
        );

        // is_enabled: convenience boolean -- pricing_tier == "Standard"
        let is_enabled = resp
            .get("pricingTier")
            .and_then(|v| v.as_str())
            .map(|s| s == "Standard")
            .unwrap_or(false);
        data.add_field(
            "is_enabled".to_string(),
            ResolvedValue::Boolean(is_enabled),
        );

        // RecordData
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_defender_pricing".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_defender_pricing" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_defender_pricing', got '{}'",
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
    fn not_found_matches_invalid_resource_name() {
        let stderr = "ERROR: (InvalidResourceName) The name 'FakePlan' is not a valid name.";
        assert!(AzDefenderPricingCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_code_line() {
        let stderr = "Code: InvalidResourceName\nMessage: The name 'FakePlan' is not valid.";
        assert!(AzDefenderPricingCollector::is_not_found(stderr));
    }

    #[test]
    fn unrelated_error_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope '/subscriptions/abc'";
        assert!(!AzDefenderPricingCollector::is_not_found(stderr));
    }
}
