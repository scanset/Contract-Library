//! AWS VPC Endpoint Collector
//!
//! Single API call: describe-vpc-endpoints
//! Lookup by endpoint_id (--vpc-endpoint-ids) or service_name/vpc_id (--filters)
//!
//! PolicyDocument is a JSON-encoded string — parsed and stored under
//! PolicyDocument key in RecordData alongside the raw endpoint object.
//!
//! Interface vs Gateway differences:
//!   Interface: SubnetIds populated, Groups populated, PrivateDnsEnabled=true
//!   Gateway:   RouteTableIds populated, SubnetIds/Groups empty, PrivateDnsEnabled=false

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_vpc_endpoint;
//  pub use aws_vpc_endpoint::AwsVpcEndpointCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsVpcEndpointCollector {
    id: String,
}

impl AwsVpcEndpointCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_vpc_endpoint_collector".to_string(),
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

impl Default for AwsVpcEndpointCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsVpcEndpointCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let endpoint_id = self.extract_string_field(object, "endpoint_id");
        let service_name = self.extract_string_field(object, "service_name");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let region = self.extract_string_field(object, "region");

        if endpoint_id.is_none() && service_name.is_none() && vpc_id.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'endpoint_id', 'service_name', or 'vpc_id' is required for aws_vpc_endpoint".to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_vpc_endpoint".to_string(),
            self.id.clone(),
        );

        // Build method traceability
        let target = endpoint_id
            .as_ref()
            .map(|id| format!("vpce:{}", id))
            .or_else(|| service_name.as_ref().map(|s| format!("vpce:service:{}", s)))
            .unwrap_or_else(|| format!("vpce:vpc:{}", vpc_id.as_deref().unwrap_or("")));

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query VPC endpoint configuration via AWS CLI")
            .target(&target)
            .command("aws ec2 describe-vpc-endpoints");
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        if let Some(ref id) = endpoint_id {
            method_builder = method_builder.input("endpoint_id", id);
        }
        if let Some(ref sn) = service_name {
            method_builder = method_builder.input("service_name", sn);
        }
        if let Some(ref v) = vpc_id {
            method_builder = method_builder.input("vpc_id", v);
        }
        data.set_method(method_builder.build());

        // Build args
        let mut args: Vec<String> = Vec::new();
        if let Some(ref id) = endpoint_id {
            args.push("--vpc-endpoint-ids".to_string());
            args.push(id.clone());
        }
        let mut filters: Vec<String> = Vec::new();
        if let Some(ref sn) = service_name {
            filters.push("--filters".to_string());
            filters.push(format!("Name=service-name,Values={}", sn));
        }
        if let Some(ref v) = vpc_id {
            filters.push("--filters".to_string());
            filters.push(format!("Name=vpc-id,Values={}", v));
        }
        args.extend(filters);

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match client.execute("ec2", "describe-vpc-endpoints", &args_refs) {
            Ok(resp) => {
                let endpoint = resp
                    .get("VpcEndpoints")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|eps| eps.first())
                    .cloned();

                match endpoint {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(ep) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = ep
                            .get("VpcEndpointId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "vpc_endpoint_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = ep
                            .get("VpcEndpointType")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "vpc_endpoint_type".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = ep
                            .get("ServiceName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "service_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) =
                            ep.get("State").and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "state".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) =
                            ep.get("VpcId").and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "vpc_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = ep
                            .get("PrivateDnsEnabled")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field(
                                "private_dns_enabled".to_string(),
                                ResolvedValue::Boolean(v),
                            );
                        }

                        // Derived counts
                        let subnet_count = ep
                            .get("SubnetIds")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|a| a.len() as i64)
                            .unwrap_or(0);
                        data.add_field(
                            "subnet_count".to_string(),
                            ResolvedValue::Integer(subnet_count),
                        );

                        let route_table_count = ep
                            .get("RouteTableIds")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|a| a.len() as i64)
                            .unwrap_or(0);
                        data.add_field(
                            "route_table_count".to_string(),
                            ResolvedValue::Integer(route_table_count),
                        );

                        // First security group
                        if let Some(sg_id) = ep
                            .get("Groups")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .and_then(|gs| gs.first())
                            .and_then(|g: &serde_json::Value| g.get("GroupId"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "security_group_id".to_string(),
                                ResolvedValue::String(sg_id.to_string()),
                            );
                        }

                        // Parse PolicyDocument JSON string
                        let mut policy_doc_val = serde_json::json!({});
                        if let Some(policy_str) = ep
                            .get("PolicyDocument")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(policy_str)
                            {
                                policy_doc_val = parsed;
                            }
                        }

                        // Build merged RecordData: endpoint object + parsed policy
                        let mut merged = ep.clone();
                        merged["PolicyDocument"] = policy_doc_val;

                        let record_data = RecordData::from_json_value(merged);
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
                    reason: format!("AWS API error (describe-vpc-endpoints): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_vpc_endpoint".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_vpc_endpoint" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_vpc_endpoint', got '{}'",
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
            AwsVpcEndpointCollector::new().collector_id(),
            "aws_vpc_endpoint_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsVpcEndpointCollector::new().supported_ctn_types(),
            vec!["aws_vpc_endpoint"]
        );
    }
}
