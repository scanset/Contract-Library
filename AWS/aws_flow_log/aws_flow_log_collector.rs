//! AWS VPC Flow Log Collector
//!
//! Collects VPC Flow Log configuration from AWS EC2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! FlowLogId                     → "fl-0123456789abcdef0"
//! FlowLogStatus                 → "ACTIVE"
//! ResourceId                    → "vpc-0fedcba9876543210"
//! TrafficType                   → "ALL"
//! LogDestinationType            → "cloud-watch-logs"
//! LogDestination                → "arn:aws:logs:..."
//! LogGroupName                  → "/aws/vpc/example-flow-logs"
//! DeliverLogsStatus             → "SUCCESS"
//! MaxAggregationInterval        → 600
//! LogFormat                     → "${version} ${account-id} ..."
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_flow_log;
//  pub use aws_flow_log::AwsFlowLogCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS VPC Flow Log information
pub struct AwsFlowLogCollector {
    id: String,
}

impl AwsFlowLogCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_flow_log_collector".to_string(),
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

impl Default for AwsFlowLogCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsFlowLogCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let flow_log_id = self.extract_string_field(object, "flow_log_id");
        let resource_id = self.extract_string_field(object, "resource_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        if flow_log_id.is_none() && resource_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'flow_log_id', 'resource_id', or 'tags' must be specified"
                    .to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        // Build CLI arguments
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref id) = flow_log_id {
            arg_strings.push("--flow-log-ids".to_string());
            arg_strings.push(id.clone());
        }

        let mut filter_vec: Vec<String> = Vec::new();

        if let Some(ref rid) = resource_id {
            filter_vec.push(format!("Name=resource-id,Values={}", rid));
        }

        if let Some(ref tags) = tags_filter {
            if let Some((key, value)) = parse_tag_filter(tags) {
                filter_vec.push(format!("Name=tag:{},Values={}", key, value));
            }
        }

        for fs in &filter_vec {
            arg_strings.push("--filter".to_string());
            arg_strings.push(fs.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        let response = client
            .execute("ec2", "describe-flow-logs", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        let flow_logs = response
            .get("FlowLogs")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_flow_log".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = flow_log_id
            .as_ref()
            .map(|id| format!("fl:{}", id))
            .or_else(|| resource_id.as_ref().map(|r| format!("fl:resource:{}", r)))
            .or_else(|| tags_filter.as_ref().map(|t| format!("fl:tag:{}", t)))
            .unwrap_or_else(|| "fl:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query VPC Flow Log configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-flow-logs");

        if let Some(ref id) = flow_log_id {
            method_builder = method_builder.input("flow_log_id", id);
        }
        if let Some(ref rid) = resource_id {
            method_builder = method_builder.input("resource_id", rid);
        }
        if let Some(ref tags) = tags_filter {
            method_builder = method_builder.input("tags", tags);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        if flow_logs.is_empty() {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        } else {
            let fl = &flow_logs[0];

            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Scalar fields extracted from response
            if let Some(id) = fl
                .get("FlowLogId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "flow_log_id".to_string(),
                    ResolvedValue::String(id.to_string()),
                );
            }

            if let Some(status) = fl
                .get("FlowLogStatus")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "flow_log_status".to_string(),
                    ResolvedValue::String(status.to_string()),
                );
            }

            if let Some(rid) = fl
                .get("ResourceId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "resource_id".to_string(),
                    ResolvedValue::String(rid.to_string()),
                );
            }

            if let Some(tt) = fl
                .get("TrafficType")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "traffic_type".to_string(),
                    ResolvedValue::String(tt.to_string()),
                );
            }

            if let Some(ldt) = fl
                .get("LogDestinationType")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "log_destination_type".to_string(),
                    ResolvedValue::String(ldt.to_string()),
                );
            }

            if let Some(ld) = fl
                .get("LogDestination")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "log_destination".to_string(),
                    ResolvedValue::String(ld.to_string()),
                );
            }

            if let Some(lgn) = fl
                .get("LogGroupName")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "log_group_name".to_string(),
                    ResolvedValue::String(lgn.to_string()),
                );
            }

            if let Some(dls) = fl
                .get("DeliverLogsStatus")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "deliver_logs_status".to_string(),
                    ResolvedValue::String(dls.to_string()),
                );
            }

            // Extract Name tag
            if let Some(tags) = fl
                .get("Tags")
                .and_then(|v: &serde_json::Value| v.as_array())
            {
                for tag in tags {
                    if tag.get("Key").and_then(|v: &serde_json::Value| v.as_str()) == Some("Name") {
                        if let Some(name) = tag
                            .get("Value")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "tag_name".to_string(),
                                ResolvedValue::String(name.to_string()),
                            );
                        }
                    }
                }
            }

            // Full API response as RecordData
            let record_data = RecordData::from_json_value(fl.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            if flow_logs.len() > 1 {
                log::warn!(
                    "Multiple flow logs ({}) matched query for object '{}', using first result",
                    flow_logs.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_flow_log".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_flow_log" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_flow_log', got '{}'",
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
        let collector = AwsFlowLogCollector::new();
        assert_eq!(collector.collector_id(), "aws_flow_log_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsFlowLogCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_flow_log"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsFlowLogCollector::default();
        assert_eq!(collector.collector_id(), "aws_flow_log_collector");
    }
}
