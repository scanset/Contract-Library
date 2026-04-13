//! AWS VPC Collector
//!
//! Collects VPC information from AWS EC2 API using the AWS CLI.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_vpc;
//  pub use aws_vpc::AwsVpcCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS VPC information
pub struct AwsVpcCollector {
    id: String,
}

impl AwsVpcCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_vpc_collector".to_string(),
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

impl Default for AwsVpcCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsVpcCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract object fields
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        // Validate that at least one filter is provided
        if vpc_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Either 'vpc_id' or 'tags' must be specified".to_string(),
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
        let vpcs = client
            .describe_vpcs(vpc_id.as_deref(), filter_slice.as_deref())
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_vpc".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let target = vpc_id
            .as_ref()
            .map(|id| format!("vpc:{}", id))
            .or_else(|| tags_filter.as_ref().map(|t| format!("vpc:tag:{}", t)))
            .unwrap_or_else(|| "vpc:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query VPC configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-vpcs");

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
        if vpcs.is_empty() {
            // VPC not found
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        } else {
            // Use the first matching VPC (should typically be exactly one)
            let vpc = &vpcs[0];

            data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
            data.add_field(
                "vpc_id".to_string(),
                ResolvedValue::String(vpc.vpc_id.clone()),
            );
            data.add_field(
                "cidr_block".to_string(),
                ResolvedValue::String(vpc.cidr_block.clone()),
            );
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(vpc.state.clone()),
            );
            data.add_field(
                "is_default".to_string(),
                ResolvedValue::Boolean(vpc.is_default),
            );

            // DNS settings require separate API calls
            let enable_dns_support = client
                .describe_vpc_attribute(&vpc.vpc_id, "enableDnsSupport")
                .unwrap_or_else(|e| {
                    log::warn!("Failed to get enableDnsSupport for {}: {}", vpc.vpc_id, e);
                    false
                });

            let enable_dns_hostnames = client
                .describe_vpc_attribute(&vpc.vpc_id, "enableDnsHostnames")
                .unwrap_or_else(|e| {
                    log::warn!("Failed to get enableDnsHostnames for {}: {}", vpc.vpc_id, e);
                    false
                });

            data.add_field(
                "enable_dns_support".to_string(),
                ResolvedValue::Boolean(enable_dns_support),
            );
            data.add_field(
                "enable_dns_hostnames".to_string(),
                ResolvedValue::Boolean(enable_dns_hostnames),
            );

            // Extract Name tag
            if let Some(name) = vpc.name() {
                data.add_field(
                    "tag_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }

            // Log if multiple VPCs matched (unexpected for specific queries)
            if vpcs.len() > 1 {
                log::warn!(
                    "Multiple VPCs ({}) matched query for object '{}', using first result",
                    vpcs.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_vpc".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_vpc" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_vpc', got '{}'",
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
        // Could support batch collection for multiple VPCs in future
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_id() {
        let collector = AwsVpcCollector::new();
        assert_eq!(collector.collector_id(), "aws_vpc_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsVpcCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_vpc"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsVpcCollector::default();
        assert_eq!(collector.collector_id(), "aws_vpc_collector");
    }
}
