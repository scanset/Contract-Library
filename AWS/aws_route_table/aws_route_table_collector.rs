//! AWS Route Table Collector
//!
//! Collects route table configuration from AWS EC2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! RouteTableId                                → "rtb-0fedcba9876543210"
//! VpcId                                       → "vpc-0fedcba9876543210"
//! Routes.0.DestinationCidrBlock               → "10.0.0.0/16"
//! Routes.0.GatewayId                          → "local"
//! Routes.1.DestinationCidrBlock               → "0.0.0.0/0"
//! Routes.1.NatGatewayId                       → "nat-0123456789abcdef0"
//! Associations.0.SubnetId                     → "subnet-0cccccccccccccccc"
//! Associations.0.Main                         → false
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_route_table;
//  pub use aws_route_table::AwsRouteTableCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::{AwsClient, parse_tag_filter};

/// Collector for AWS Route Table information
pub struct AwsRouteTableCollector {
    id: String,
}

impl AwsRouteTableCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_route_table_collector".to_string(),
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

impl Default for AwsRouteTableCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsRouteTableCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract object fields
        let route_table_id = self.extract_string_field(object, "route_table_id");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags_filter = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        // Validate that at least one lookup field is provided
        if route_table_id.is_none() && vpc_id.is_none() && tags_filter.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'route_table_id', 'vpc_id', or 'tags' must be specified"
                    .to_string(),
            });
        }

        // Create AWS client
        let client = AwsClient::new(region.clone());

        // Build CLI arguments for describe-route-tables
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref id) = route_table_id {
            arg_strings.push("--route-table-ids".to_string());
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

        for fs in &filter_vec {
            arg_strings.push("--filters".to_string());
            arg_strings.push(fs.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        // Execute raw API call to get PascalCase JSON for RecordData
        let response = client
            .execute("ec2", "describe-route-tables", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        // Extract RouteTables array
        let route_tables = response
            .get("RouteTables")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_route_table".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let target = route_table_id
            .as_ref()
            .map(|id| format!("rt:{}", id))
            .or_else(|| tags_filter.as_ref().map(|t| format!("rt:tag:{}", t)))
            .or_else(|| vpc_id.as_ref().map(|v| format!("rt:vpc:{}", v)))
            .unwrap_or_else(|| "rt:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query route table configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-route-tables");

        if let Some(ref id) = route_table_id {
            method_builder = method_builder.input("route_table_id", id);
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

        // Handle results
        if route_tables.is_empty() {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));

            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        } else {
            let rt = &route_tables[0];

            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Route table ID
            if let Some(id) = rt
                .get("RouteTableId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "route_table_id".to_string(),
                    ResolvedValue::String(id.to_string()),
                );
            }

            // VPC ID
            if let Some(vid) = rt.get("VpcId").and_then(|v: &serde_json::Value| v.as_str()) {
                data.add_field("vpc_id".to_string(), ResolvedValue::String(vid.to_string()));
            }

            // Extract Name tag
            if let Some(tags) = rt
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

            // Is main route table
            let is_main = rt
                .get("Associations")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|assocs: &Vec<serde_json::Value>| {
                    assocs.iter().any(|a: &serde_json::Value| {
                        a.get("Main")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            data.add_field("is_main".to_string(), ResolvedValue::Boolean(is_main));

            // Route count
            let routes = rt
                .get("Routes")
                .and_then(|v: &serde_json::Value| v.as_array());
            let route_count = routes
                .map(|r: &Vec<serde_json::Value>| r.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "route_count".to_string(),
                ResolvedValue::Integer(route_count),
            );

            // Association count
            let association_count = rt
                .get("Associations")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "association_count".to_string(),
                ResolvedValue::Integer(association_count),
            );

            // Has IGW route (GatewayId starts with "igw-")
            let has_igw_route = routes
                .map(|r: &Vec<serde_json::Value>| {
                    r.iter().any(|route: &serde_json::Value| {
                        route
                            .get("GatewayId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .is_some_and(|g: &str| g.starts_with("igw-"))
                    })
                })
                .unwrap_or(false);
            data.add_field(
                "has_igw_route".to_string(),
                ResolvedValue::Boolean(has_igw_route),
            );

            // Has NAT route (NatGatewayId present)
            let has_nat_route = routes
                .map(|r: &Vec<serde_json::Value>| {
                    r.iter().any(|route: &serde_json::Value| {
                        route
                            .get("NatGatewayId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .is_some()
                    })
                })
                .unwrap_or(false);
            data.add_field(
                "has_nat_route".to_string(),
                ResolvedValue::Boolean(has_nat_route),
            );

            // Has internet route (0.0.0.0/0 via IGW or NAT)
            let has_internet_route = routes
                .map(|r: &Vec<serde_json::Value>| {
                    r.iter().any(|route: &serde_json::Value| {
                        let is_default = route
                            .get("DestinationCidrBlock")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .is_some_and(|c: &str| c == "0.0.0.0/0");

                        let has_target = route
                            .get("GatewayId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .is_some_and(|g: &str| g.starts_with("igw-"))
                            || route
                                .get("NatGatewayId")
                                .and_then(|v: &serde_json::Value| v.as_str())
                                .is_some();

                        is_default && has_target
                    })
                })
                .unwrap_or(false);
            data.add_field(
                "has_internet_route".to_string(),
                ResolvedValue::Boolean(has_internet_route),
            );

            // Full API response as RecordData
            let record_data = RecordData::from_json_value(rt.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            // Log if multiple route tables matched
            if route_tables.len() > 1 {
                log::warn!(
                    "Multiple route tables ({}) matched query for object '{}', using first result",
                    route_tables.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_route_table".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_route_table" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_route_table', got '{}'",
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
        let collector = AwsRouteTableCollector::new();
        assert_eq!(collector.collector_id(), "aws_route_table_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsRouteTableCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_route_table"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsRouteTableCollector::default();
        assert_eq!(collector.collector_id(), "aws_route_table_collector");
    }
}
