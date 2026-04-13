//! AWS CloudWatch Log Group Collector

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_log_group;
//  pub use aws_cloudwatch_log_group::AwsCloudwatchLogGroupCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsCloudwatchLogGroupCollector {
    id: String,
}

impl AwsCloudwatchLogGroupCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_cloudwatch_log_group_collector".to_string(),
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

impl Default for AwsCloudwatchLogGroupCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsCloudwatchLogGroupCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let log_group_name = self
            .extract_string_field(object, "log_group_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'log_group_name' is required for aws_cloudwatch_log_group".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_cloudwatch_log_group".to_string(),
            self.id.clone(),
        );

        let target = format!("logs:{}", log_group_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query CloudWatch log group configuration via AWS CLI")
            .target(&target)
            .command("aws logs describe-log-groups")
            .input("log_group_name", &log_group_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--log-group-name-prefix", log_group_name.as_str()];

        match client.execute("logs", "describe-log-groups", &args) {
            Ok(resp) => {
                let log_groups = resp
                    .get("logGroups")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Exact match on logGroupName
                let group = log_groups.iter().find(|g| {
                    g.get("logGroupName")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        == Some(log_group_name.as_str())
                });

                if let Some(group) = group {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                    if let Some(name) = group
                        .get("logGroupName")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "log_group_name".to_string(),
                            ResolvedValue::String(name.to_string()),
                        );
                    }

                    // Use logGroupArn (without :* suffix) — fall back to arn and strip it
                    let arn = group
                        .get("logGroupArn")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            group
                                .get("arn")
                                .and_then(|v: &serde_json::Value| v.as_str())
                                .map(|s| s.trim_end_matches(":*").to_string())
                        });
                    if let Some(arn_val) = arn {
                        data.add_field("log_group_arn".to_string(), ResolvedValue::String(arn_val));
                    }

                    if let Some(ret) = group
                        .get("retentionInDays")
                        .and_then(|v: &serde_json::Value| v.as_i64())
                    {
                        data.add_field(
                            "retention_in_days".to_string(),
                            ResolvedValue::Integer(ret),
                        );
                    }

                    if let Some(class) = group
                        .get("logGroupClass")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "log_group_class".to_string(),
                            ResolvedValue::String(class.to_string()),
                        );
                    }

                    if let Some(bytes) = group
                        .get("storedBytes")
                        .and_then(|v: &serde_json::Value| v.as_i64())
                    {
                        data.add_field("stored_bytes".to_string(), ResolvedValue::Integer(bytes));
                    }

                    if let Some(dp) = group
                        .get("deletionProtectionEnabled")
                        .and_then(|v: &serde_json::Value| v.as_bool())
                    {
                        data.add_field(
                            "deletion_protection_enabled".to_string(),
                            ResolvedValue::Boolean(dp),
                        );
                    }

                    if let Some(mfc) = group
                        .get("metricFilterCount")
                        .and_then(|v: &serde_json::Value| v.as_i64())
                    {
                        data.add_field(
                            "metric_filter_count".to_string(),
                            ResolvedValue::Integer(mfc),
                        );
                    }

                    let record_data = RecordData::from_json_value(group.clone());
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
                    reason: format!("AWS API error (describe-log-groups): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_cloudwatch_log_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_cloudwatch_log_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_cloudwatch_log_group', got '{}'",
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
            AwsCloudwatchLogGroupCollector::new().collector_id(),
            "aws_cloudwatch_log_group_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsCloudwatchLogGroupCollector::new().supported_ctn_types(),
            vec!["aws_cloudwatch_log_group"]
        );
    }
}
