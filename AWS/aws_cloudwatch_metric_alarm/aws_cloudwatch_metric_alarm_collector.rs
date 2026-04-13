//! AWS CloudWatch Metric Alarm Collector
//!
//! Single API call: cloudwatch describe-alarms --alarm-names <alarm_name>
//! Threshold stored as integer (truncated from float).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_metric_alarm;
//  pub use aws_cloudwatch_metric_alarm::AwsCloudwatchMetricAlarmCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsCloudwatchMetricAlarmCollector {
    id: String,
}

impl AwsCloudwatchMetricAlarmCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_cloudwatch_metric_alarm_collector".to_string(),
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

impl Default for AwsCloudwatchMetricAlarmCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsCloudwatchMetricAlarmCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let alarm_name = self
            .extract_string_field(object, "alarm_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'alarm_name' is required for aws_cloudwatch_metric_alarm".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_cloudwatch_metric_alarm".to_string(),
            self.id.clone(),
        );

        let target = format!("alarm:{}", alarm_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query CloudWatch metric alarm via AWS CLI")
            .target(&target)
            .command("aws cloudwatch describe-alarms")
            .input("alarm_name", &alarm_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--alarm-names", alarm_name.as_str()];

        match client.execute("cloudwatch", "describe-alarms", &args) {
            Ok(resp) => {
                let alarm = resp
                    .get("MetricAlarms")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|a| a.first())
                    .cloned();

                match alarm {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(a) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        let str_fields = [
                            ("AlarmName", "alarm_name"),
                            ("StateValue", "state_value"),
                            ("MetricName", "metric_name"),
                            ("Namespace", "namespace"),
                            ("Statistic", "statistic"),
                            ("ComparisonOperator", "comparison_operator"),
                            ("TreatMissingData", "treat_missing_data"),
                        ];
                        for (json_key, field_name) in &str_fields {
                            if let Some(v) = a
                                .get(*json_key)
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    field_name.to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                        }

                        let int_fields = [
                            ("Period", "period"),
                            ("EvaluationPeriods", "evaluation_periods"),
                        ];
                        for (json_key, field_name) in &int_fields {
                            if let Some(v) = a
                                .get(*json_key)
                                .and_then(|v: &serde_json::Value| v.as_i64())
                            {
                                data.add_field(field_name.to_string(), ResolvedValue::Integer(v));
                            }
                        }

                        // Threshold is a float in the API — truncate to i64
                        if let Some(v) = a
                            .get("Threshold")
                            .and_then(|v: &serde_json::Value| v.as_f64())
                        {
                            data.add_field(
                                "threshold".to_string(),
                                ResolvedValue::Integer(v as i64),
                            );
                        }

                        if let Some(v) = a
                            .get("ActionsEnabled")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field(
                                "actions_enabled".to_string(),
                                ResolvedValue::Boolean(v),
                            );
                        }

                        let record_data = RecordData::from_json_value(a.clone());
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(record_data)),
                        );
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-alarms): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_cloudwatch_metric_alarm".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_cloudwatch_metric_alarm" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_cloudwatch_metric_alarm', got '{}'",
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
            AwsCloudwatchMetricAlarmCollector::new().collector_id(),
            "aws_cloudwatch_metric_alarm_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsCloudwatchMetricAlarmCollector::new().supported_ctn_types(),
            vec!["aws_cloudwatch_metric_alarm"]
        );
    }
}
