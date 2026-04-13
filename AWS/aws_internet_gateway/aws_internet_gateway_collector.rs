//! AWS Internet Gateway Collector
//!
//! Collects Internet Gateway configuration from AWS EC2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! InternetGatewayId              → "igw-0123456789abcdef0"
//! Attachments.0.State            → "available"
//! Attachments.0.VpcId            → "vpc-0fedcba9876543210"
//! Tags.0.Key                     → "Name"
//! Tags.0.Value                   → "example-igw"
//! OwnerId                        → "123456789012"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_internet_gateway;
//  pub use aws_internet_gateway::AwsInternetGatewayCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS Internet Gateway information
pub struct AwsInternetGatewayCollector {
    id: String,
}

impl AwsInternetGatewayCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_internet_gateway_collector".to_string(),
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

impl Default for AwsInternetGatewayCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsInternetGatewayCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let internet_gateway_id = self.extract_string_field(object, "internet_gateway_id");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        if internet_gateway_id.is_none() && vpc_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason:
                    "At least one of 'internet_gateway_id', 'vpc_id', or 'tags' must be specified"
                        .to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        // Build CLI arguments
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref id) = internet_gateway_id {
            arg_strings.push("--internet-gateway-ids".to_string());
            arg_strings.push(id.clone());
        }

        let mut filter_vec: Vec<String> = Vec::new();

        if let Some(ref vid) = vpc_id {
            filter_vec.push(format!("Name=attachment.vpc-id,Values={}", vid));
        }

        if let Some(ref tags) = tags_filter {
            if let Some((key, value)) = parse_tag_filter(tags) {
                filter_vec.push(format!("Name=tag:{},Values={}", key, value));
            }
        }

        for fs in &filter_vec {
            arg_strings.push("--filters".to_string());
            arg_strings.push(fs.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        let response = client
            .execute("ec2", "describe-internet-gateways", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        let gateways = response
            .get("InternetGateways")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_internet_gateway".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = internet_gateway_id
            .as_ref()
            .map(|id| format!("igw:{}", id))
            .or_else(|| vpc_id.as_ref().map(|v| format!("igw:vpc:{}", v)))
            .or_else(|| tags_filter.as_ref().map(|t| format!("igw:tag:{}", t)))
            .unwrap_or_else(|| "igw:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Internet Gateway configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-internet-gateways");

        if let Some(ref id) = internet_gateway_id {
            method_builder = method_builder.input("internet_gateway_id", id);
        }
        if let Some(ref vid) = vpc_id {
            method_builder = method_builder.input("vpc_id", vid);
        }
        if let Some(ref tags) = tags_filter {
            method_builder = method_builder.input("tags", tags);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        if gateways.is_empty() {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        } else {
            let igw = &gateways[0];

            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Internet Gateway ID
            if let Some(id) = igw
                .get("InternetGatewayId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "internet_gateway_id".to_string(),
                    ResolvedValue::String(id.to_string()),
                );
            }

            // Extract Name tag
            if let Some(tags) = igw
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

            // Attachments
            let attachments = igw
                .get("Attachments")
                .and_then(|v: &serde_json::Value| v.as_array());

            let attachment_count = attachments
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "attachment_count".to_string(),
                ResolvedValue::Integer(attachment_count),
            );

            // First attachment details
            if let Some(first) = attachments.and_then(|a: &Vec<serde_json::Value>| a.first()) {
                if let Some(vid) = first
                    .get("VpcId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "attached_vpc_id".to_string(),
                        ResolvedValue::String(vid.to_string()),
                    );
                }
                if let Some(state) = first
                    .get("State")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "attachment_state".to_string(),
                        ResolvedValue::String(state.to_string()),
                    );
                }
            }

            // Full API response as RecordData
            let record_data = RecordData::from_json_value(igw.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            if gateways.len() > 1 {
                log::warn!(
                    "Multiple internet gateways ({}) matched query for object '{}', using first result",
                    gateways.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_internet_gateway".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_internet_gateway" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_internet_gateway', got '{}'",
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
        let collector = AwsInternetGatewayCollector::new();
        assert_eq!(collector.collector_id(), "aws_internet_gateway_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsInternetGatewayCollector::new();
        assert_eq!(
            collector.supported_ctn_types(),
            vec!["aws_internet_gateway"]
        );
    }

    #[test]
    fn test_default() {
        let collector = AwsInternetGatewayCollector::default();
        assert_eq!(collector.collector_id(), "aws_internet_gateway_collector");
    }
}
