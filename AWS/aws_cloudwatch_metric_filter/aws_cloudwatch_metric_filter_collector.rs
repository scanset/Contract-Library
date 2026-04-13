//! AWS CloudWatch Metric Filter Collector
//!
//! Single API call: logs describe-metric-filters
//!   --log-group-name <log_group_name> --filter-name-prefix <filter_name>
//!
//! Finds first result where filterName == filter_name (exact match).
//! metricTransformations[0] provides metric_name and metric_namespace.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_metric_filter;
//  pub use aws_cloudwatch_metric_filter::AwsCloudwatchMetricFilterCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsCloudwatchMetricFilterCollector {
    id: String,
}

impl AwsCloudwatchMetricFilterCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_cloudwatch_metric_filter_collector".to_string(),
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

impl Default for AwsCloudwatchMetricFilterCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsCloudwatchMetricFilterCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let filter_name = self
            .extract_string_field(object, "filter_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'filter_name' is required for aws_cloudwatch_metric_filter".to_string(),
            })?;

        let log_group_name = self
            .extract_string_field(object, "log_group_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'log_group_name' is required for aws_cloudwatch_metric_filter".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_cloudwatch_metric_filter".to_string(),
            self.id.clone(),
        );

        let target = format!("metric-filter:{}:{}", log_group_name, filter_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query CloudWatch metric filter via AWS CLI")
            .target(&target)
            .command("aws logs describe-metric-filters")
            .input("filter_name", &filter_name)
            .input("log_group_name", &log_group_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = [
            "--log-group-name",
            log_group_name.as_str(),
            "--filter-name-prefix",
            filter_name.as_str(),
        ];

        match client.execute("logs", "describe-metric-filters", &args) {
            Ok(resp) => {
                let filter = resp
                    .get("metricFilters")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|filters| {
                        filters.iter().find(|f| {
                            f.get("filterName")
                                .and_then(|v: &serde_json::Value| v.as_str())
                                == Some(filter_name.as_str())
                        })
                    })
                    .cloned();

                match filter {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(f) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = f
                            .get("filterName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "filter_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = f
                            .get("logGroupName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "log_group_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = f
                            .get("filterPattern")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "filter_pattern".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // First metric transformation
                        if let Some(mt) = f
                            .get("metricTransformations")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .and_then(|a| a.first())
                        {
                            if let Some(v) = mt
                                .get("metricName")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "metric_name".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                            if let Some(v) = mt
                                .get("metricNamespace")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "metric_namespace".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                        }

                        let record_data = RecordData::from_json_value(f.clone());
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
                    reason: format!("AWS API error (describe-metric-filters): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_cloudwatch_metric_filter".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_cloudwatch_metric_filter" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_cloudwatch_metric_filter', got '{}'",
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
            AwsCloudwatchMetricFilterCollector::new().collector_id(),
            "aws_cloudwatch_metric_filter_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsCloudwatchMetricFilterCollector::new().supported_ctn_types(),
            vec!["aws_cloudwatch_metric_filter"]
        );
    }
}
