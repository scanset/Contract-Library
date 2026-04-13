//! AWS SSM Maintenance Window Collector
//!
//! Single API call:
//! describe-maintenance-windows --filters Key=Name,Values=<window_name>
//! Takes the first result with an exact Name match.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ssm_maintenance_window;
//  pub use aws_ssm_maintenance_window::AwsSsmMaintenanceWindowCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsSsmMaintenanceWindowCollector {
    id: String,
}

impl AwsSsmMaintenanceWindowCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_ssm_maintenance_window_collector".to_string(),
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

impl Default for AwsSsmMaintenanceWindowCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSsmMaintenanceWindowCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let window_name = self
            .extract_string_field(object, "window_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'window_name' is required for aws_ssm_maintenance_window".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_ssm_maintenance_window".to_string(),
            self.id.clone(),
        );

        let target = format!("ssm-mw:{}", window_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query SSM Maintenance Window configuration via AWS CLI")
            .target(&target)
            .command("aws ssm describe-maintenance-windows")
            .input("window_name", &window_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // Use AWS CLI filter to narrow results — exact match verified in-process
        let filter = format!("Key=Name,Values={}", window_name);
        let args = ["--filters", filter.as_str()];

        match client.execute("ssm", "describe-maintenance-windows", &args) {
            Ok(resp) => {
                let windows = resp
                    .get("WindowIdentities")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Exact name match (filter may return prefix matches)
                let window = windows.iter().find(|w| {
                    w.get("Name").and_then(|v: &serde_json::Value| v.as_str())
                        == Some(window_name.as_str())
                });

                if let Some(w) = window {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                    if let Some(v) = w.get("Name").and_then(|v: &serde_json::Value| v.as_str()) {
                        data.add_field(
                            "window_name".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                    if let Some(v) = w
                        .get("WindowId")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "window_id".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                    if let Some(v) = w
                        .get("Enabled")
                        .and_then(|v: &serde_json::Value| v.as_bool())
                    {
                        data.add_field("enabled".to_string(), ResolvedValue::Boolean(v));
                    }
                    if let Some(v) = w
                        .get("Duration")
                        .and_then(|v: &serde_json::Value| v.as_i64())
                    {
                        data.add_field("duration".to_string(), ResolvedValue::Integer(v));
                    }
                    if let Some(v) = w.get("Cutoff").and_then(|v: &serde_json::Value| v.as_i64()) {
                        data.add_field("cutoff".to_string(), ResolvedValue::Integer(v));
                    }
                    if let Some(v) = w
                        .get("Schedule")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "schedule".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                    if let Some(v) = w
                        .get("Description")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "description".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }

                    let record_data = RecordData::from_json_value(w.clone());
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(record_data)),
                    );
                } else {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                    let empty = RecordData::from_json_value(serde_json::json!({}));
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(empty)),
                    );
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-maintenance-windows): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_ssm_maintenance_window".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_ssm_maintenance_window" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_ssm_maintenance_window', got '{}'",
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
    fn test_collector_id() {
        assert_eq!(
            AwsSsmMaintenanceWindowCollector::new().collector_id(),
            "aws_ssm_maintenance_window_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsSsmMaintenanceWindowCollector::new().supported_ctn_types(),
            vec!["aws_ssm_maintenance_window"]
        );
    }
}
