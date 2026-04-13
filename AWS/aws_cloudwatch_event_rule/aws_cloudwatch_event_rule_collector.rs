//! AWS CloudWatch EventBridge Rule Collector
//!
//! Two API calls:
//! 1. events describe-rule        → rule state, description, EventPattern (JSON string → parsed)
//! 2. events list-targets-by-rule → target ARN and ID
//!
//! EventPattern is a JSON-encoded string. It is parsed and stored under the
//! `EventPattern` key in RecordData so policy authors can use record checks on
//! `EventPattern.source.0`, `EventPattern.detail-type.0`, etc.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Rule.Name                                → "example-org-guardduty-findings"
//! Rule.State                               → "ENABLED"
//! Rule.EventBusName                        → "default"
//! EventPattern.source.0                    → "aws.guardduty"
//! EventPattern.detail-type.0              → "GuardDuty Finding"
//! Targets.0.Id                             → "GuardDutyFindingsToLogs"
//! Targets.0.Arn                            → "arn:aws:logs:..."
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_event_rule;
//  pub use aws_cloudwatch_event_rule::AwsCloudwatchEventRuleCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsCloudwatchEventRuleCollector {
    id: String,
}

impl AwsCloudwatchEventRuleCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_cloudwatch_event_rule_collector".to_string(),
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

    fn is_not_found_error(err_str: &str) -> bool {
        err_str.contains("ResourceNotFoundException")
    }
}

impl Default for AwsCloudwatchEventRuleCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsCloudwatchEventRuleCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let rule_name = self
            .extract_string_field(object, "rule_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'rule_name' is required for aws_cloudwatch_event_rule".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_cloudwatch_event_rule".to_string(),
            self.id.clone(),
        );

        let target = format!("events:{}", rule_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query EventBridge rule configuration and targets via AWS CLI")
            .target(&target)
            .command("aws events describe-rule + list-targets-by-rule")
            .input("rule_name", &rule_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let rule_args = ["--name", rule_name.as_str()];

        // ====================================================================
        // Accumulators for RecordData
        // ====================================================================
        let mut rule_val = serde_json::json!({});
        let mut event_pattern_val = serde_json::json!({});
        let mut targets_val = serde_json::json!([]);

        // ====================================================================
        // Command 1: describe-rule
        // ====================================================================
        match client.execute("events", "describe-rule", &rule_args) {
            Ok(resp) => {
                // Store rule without the raw EventPattern string — we parse it separately
                rule_val = resp.clone();

                if let Some(name) = resp
                    .get("Name")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "rule_name".to_string(),
                        ResolvedValue::String(name.to_string()),
                    );
                }

                if let Some(arn) = resp.get("Arn").and_then(|v: &serde_json::Value| v.as_str()) {
                    data.add_field(
                        "rule_arn".to_string(),
                        ResolvedValue::String(arn.to_string()),
                    );
                }

                if let Some(state) = resp
                    .get("State")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "state".to_string(),
                        ResolvedValue::String(state.to_string()),
                    );
                }

                if let Some(desc) = resp
                    .get("Description")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "description".to_string(),
                        ResolvedValue::String(desc.to_string()),
                    );
                }

                if let Some(bus) = resp
                    .get("EventBusName")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "event_bus_name".to_string(),
                        ResolvedValue::String(bus.to_string()),
                    );
                }

                // Parse EventPattern JSON string into RecordData
                if let Some(pattern_str) = resp
                    .get("EventPattern")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    match serde_json::from_str::<serde_json::Value>(pattern_str) {
                        Ok(parsed) => {
                            event_pattern_val = parsed;
                        }
                        Err(e) => {
                            return Err(CollectionError::CollectionFailed {
                                object_id: object.identifier.clone(),
                                reason: format!("Failed to parse EventPattern JSON: {}", e),
                            });
                        }
                    }
                }

                data.add_field("found".to_string(), ResolvedValue::Boolean(true));
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_found_error(&err_str) {
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
                    reason: format!("AWS API error (describe-rule): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: list-targets-by-rule
        // ====================================================================
        let targets_args = ["--rule", rule_name.as_str()];
        match client.execute("events", "list-targets-by-rule", &targets_args) {
            Ok(resp) => {
                let targets = resp
                    .get("Targets")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                targets_val = serde_json::Value::Array(targets.clone());

                data.add_field(
                    "target_count".to_string(),
                    ResolvedValue::Integer(targets.len() as i64),
                );

                if let Some(first) = targets.first() {
                    if let Some(arn) = first
                        .get("Arn")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "target_arn".to_string(),
                            ResolvedValue::String(arn.to_string()),
                        );
                    }
                    if let Some(id) = first.get("Id").and_then(|v: &serde_json::Value| v.as_str()) {
                        data.add_field(
                            "target_id".to_string(),
                            ResolvedValue::String(id.to_string()),
                        );
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-targets-by-rule): {}", e),
                });
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Rule": rule_val,
            "EventPattern": event_pattern_val,
            "Targets": targets_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_cloudwatch_event_rule".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_cloudwatch_event_rule" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_cloudwatch_event_rule', got '{}'",
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
            AwsCloudwatchEventRuleCollector::new().collector_id(),
            "aws_cloudwatch_event_rule_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsCloudwatchEventRuleCollector::new().supported_ctn_types(),
            vec!["aws_cloudwatch_event_rule"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsCloudwatchEventRuleCollector::is_not_found_error(
            "ResourceNotFoundException"
        ));
        assert!(!AwsCloudwatchEventRuleCollector::is_not_found_error(
            "AccessDenied"
        ));
    }
}
