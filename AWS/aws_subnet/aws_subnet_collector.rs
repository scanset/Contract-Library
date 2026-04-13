//! AWS Subnet Collector
//!
//! Collects subnet information from AWS EC2 API using the AWS CLI.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_subnet;
//  pub use aws_subnet::AwsSubnetCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS Subnet information
pub struct AwsSubnetCollector {
    id: String,
}

impl AwsSubnetCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_subnet_collector".to_string(),
        }
    }

    /// Extract a string field from the object
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

impl Default for AwsSubnetCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSubnetCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract object fields
        let subnet_id = self.extract_string_field(object, "subnet_id");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        // Validate that at least one filter is provided
        if subnet_id.is_none() && vpc_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'subnet_id', 'vpc_id', or 'tags' must be specified"
                    .to_string(),
            });
        }

        // Create AWS client
        let client = AwsClient::new(region.clone());

        // Build filters for tag-based lookup
        let tag_key_value: Option<(String, String)> = tags_filter.as_ref().and_then(|t| {
            parse_tag_filter(t).map(|(k, v): (&str, &str)| (format!("tag:{}", k), v.to_string()))
        });

        let filter_slice: Option<Vec<(&str, &str)>> = tag_key_value
            .as_ref()
            .map(|(k, v)| vec![(k.as_str(), v.as_str())]);

        // Query AWS API
        let subnets = client
            .describe_subnets(
                subnet_id.as_deref(),
                vpc_id.as_deref(),
                filter_slice.as_deref(),
            )
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_subnet".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let target = subnet_id
            .as_ref()
            .map(|id| format!("subnet:{}", id))
            .or_else(|| vpc_id.as_ref().map(|id| format!("vpc:{}:subnets", id)))
            .or_else(|| tags_filter.as_ref().map(|t| format!("subnet:tag:{}", t)))
            .unwrap_or_else(|| "subnet:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query subnet configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-subnets");

        if let Some(ref id) = subnet_id {
            method_builder = method_builder.input("subnet_id", id);
        }
        if let Some(ref id) = vpc_id {
            method_builder = method_builder.input("vpc_id", id);
        }
        if let Some(ref tags) = tags_filter {
            method_builder = method_builder.input("tags", tags);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        // Handle results
        if subnets.is_empty() {
            // Subnet not found
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        } else {
            // Use the first matching subnet
            let subnet = &subnets[0];

            data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
            data.add_field(
                "subnet_id".to_string(),
                ResolvedValue::String(subnet.subnet_id.clone()),
            );
            data.add_field(
                "vpc_id".to_string(),
                ResolvedValue::String(subnet.vpc_id.clone()),
            );
            data.add_field(
                "cidr_block".to_string(),
                ResolvedValue::String(subnet.cidr_block.clone()),
            );
            data.add_field(
                "availability_zone".to_string(),
                ResolvedValue::String(subnet.availability_zone.clone()),
            );
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(subnet.state.clone()),
            );
            data.add_field(
                "map_public_ip_on_launch".to_string(),
                ResolvedValue::Boolean(subnet.map_public_ip_on_launch),
            );
            data.add_field(
                "available_ip_address_count".to_string(),
                ResolvedValue::Integer(subnet.available_ip_address_count),
            );

            // Extract Name tag
            if let Some(name) = subnet.name() {
                data.add_field(
                    "tag_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }

            // Log if multiple subnets matched
            if subnets.len() > 1 {
                log::warn!(
                    "Multiple subnets ({}) matched query for object '{}', using first result. \
                     Consider using more specific filters.",
                    subnets.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_subnet".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_subnet" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_subnet', got '{}'",
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
        let collector = AwsSubnetCollector::new();
        assert_eq!(collector.collector_id(), "aws_subnet_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsSubnetCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_subnet"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsSubnetCollector::default();
        assert_eq!(collector.collector_id(), "aws_subnet_collector");
    }
}
