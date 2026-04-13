//! AWS NAT Gateway Collector
//!
//! Collects NAT Gateway configuration from AWS EC2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! NatGatewayId                              → "nat-0123456789abcdef0"
//! State                                     → "available"
//! SubnetId                                  → "subnet-0dddddddddddddddd"
//! VpcId                                     → "vpc-0fedcba9876543210"
//! ConnectivityType                          → "public"
//! NatGatewayAddresses.0.PublicIp            → "203.0.113.42"
//! NatGatewayAddresses.0.PrivateIp           → "10.0.0.100"
//! NatGatewayAddresses.0.AllocationId        → "eipalloc-00ce2060da88c68b2"
//! NatGatewayAddresses.0.Status              → "succeeded"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_nat_gateway;
//  pub use aws_nat_gateway::AwsNatGatewayCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS NAT Gateway information
pub struct AwsNatGatewayCollector {
    id: String,
}

impl AwsNatGatewayCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_nat_gateway_collector".to_string(),
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

impl Default for AwsNatGatewayCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsNatGatewayCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let nat_gateway_id = self.extract_string_field(object, "nat_gateway_id");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        if nat_gateway_id.is_none() && vpc_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'nat_gateway_id', 'vpc_id', or 'tags' must be specified"
                    .to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        // Build CLI arguments
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref id) = nat_gateway_id {
            arg_strings.push("--nat-gateway-ids".to_string());
            arg_strings.push(id.clone());
        }

        let mut filter_vec: Vec<String> = Vec::new();

        if let Some(ref vid) = vpc_id {
            filter_vec.push(format!("Name=vpc-id,Values={}", vid));
        }

        if let Some(ref tags) = tags_filter {
            if let Some((key, value)) = parse_tag_filter(tags) {
                filter_vec.push(format!("Name=tag:{},Values={}", key, value));
            }
        }

        // Filter out deleted NAT gateways by default
        filter_vec.push("Name=state,Values=available,pending".to_string());

        for fs in &filter_vec {
            arg_strings.push("--filter".to_string());
            arg_strings.push(fs.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        let response = client
            .execute("ec2", "describe-nat-gateways", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        let gateways = response
            .get("NatGateways")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_nat_gateway".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = nat_gateway_id
            .as_ref()
            .map(|id| format!("nat:{}", id))
            .or_else(|| vpc_id.as_ref().map(|v| format!("nat:vpc:{}", v)))
            .or_else(|| tags_filter.as_ref().map(|t| format!("nat:tag:{}", t)))
            .unwrap_or_else(|| "nat:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query NAT Gateway configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-nat-gateways");

        if let Some(ref id) = nat_gateway_id {
            method_builder = method_builder.input("nat_gateway_id", id);
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
            let nat = &gateways[0];

            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // NAT Gateway ID
            if let Some(id) = nat
                .get("NatGatewayId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "nat_gateway_id".to_string(),
                    ResolvedValue::String(id.to_string()),
                );
            }

            // State
            if let Some(state) = nat
                .get("State")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "state".to_string(),
                    ResolvedValue::String(state.to_string()),
                );
            }

            // VPC ID
            if let Some(vid) = nat
                .get("VpcId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field("vpc_id".to_string(), ResolvedValue::String(vid.to_string()));
            }

            // Subnet ID
            if let Some(sid) = nat
                .get("SubnetId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "subnet_id".to_string(),
                    ResolvedValue::String(sid.to_string()),
                );
            }

            // Connectivity type
            if let Some(ct) = nat
                .get("ConnectivityType")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "connectivity_type".to_string(),
                    ResolvedValue::String(ct.to_string()),
                );
            }

            // Extract Name tag
            if let Some(tags) = nat
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

            // Primary address details from NatGatewayAddresses[0]
            if let Some(addrs) = nat
                .get("NatGatewayAddresses")
                .and_then(|v: &serde_json::Value| v.as_array())
            {
                if let Some(primary) = addrs.first() {
                    if let Some(pub_ip) = primary
                        .get("PublicIp")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "public_ip".to_string(),
                            ResolvedValue::String(pub_ip.to_string()),
                        );
                    }
                    if let Some(priv_ip) = primary
                        .get("PrivateIp")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "private_ip".to_string(),
                            ResolvedValue::String(priv_ip.to_string()),
                        );
                    }
                }
            }

            // Full API response as RecordData
            let record_data = RecordData::from_json_value(nat.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            if gateways.len() > 1 {
                log::warn!(
                    "Multiple NAT gateways ({}) matched query for object '{}', using first result",
                    gateways.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_nat_gateway".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_nat_gateway" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_nat_gateway', got '{}'",
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
        let collector = AwsNatGatewayCollector::new();
        assert_eq!(collector.collector_id(), "aws_nat_gateway_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsNatGatewayCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_nat_gateway"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsNatGatewayCollector::default();
        assert_eq!(collector.collector_id(), "aws_nat_gateway_collector");
    }
}
