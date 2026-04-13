//! AWS Security Group Collector
//!
//! Collects security group configuration from AWS EC2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData
//! for detailed rule inspection using record checks.
//!
//! ## RecordData Field Paths
//!
//! The `resource` field contains the raw AWS API response with PascalCase keys,
//! matching `aws ec2 describe-security-groups` output exactly:
//!
//! ```text
//! IpPermissions.0.IpProtocol          → "tcp"
//! IpPermissions.0.FromPort            → 5432
//! IpPermissions.0.ToPort              → 5432
//! IpPermissions.0.UserIdGroupPairs.0.GroupId → "sg-0cccccccccccccccc0"
//! IpPermissions.0.IpRanges.0.CidrIp  → "10.0.0.0/16"
//! IpPermissionsEgress.0.IpRanges.0.CidrIp → "0.0.0.0/0"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_security_group;
//  pub use aws_security_group::AwsSecurityGroupCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS Security Group information
pub struct AwsSecurityGroupCollector {
    id: String,
}

impl AwsSecurityGroupCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_security_group_collector".to_string(),
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

impl Default for AwsSecurityGroupCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSecurityGroupCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate contract compatibility
        self.validate_ctn_compatibility(contract)?;

        // Extract object fields
        let group_id = self.extract_string_field(object, "group_id");
        let group_name = self.extract_string_field(object, "group_name");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let region = self.extract_string_field(object, "region");

        // Validate that at least one lookup field is provided
        if group_id.is_none() && group_name.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Either 'group_id' or 'group_name' must be specified".to_string(),
            });
        }

        // Create AWS client
        let client = AwsClient::new(region.clone());

        // Build CLI arguments for describe-security-groups
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref id) = group_id {
            arg_strings.push("--group-ids".to_string());
            arg_strings.push(id.clone());
        }

        let mut filter_vec: Vec<String> = Vec::new();

        if let Some(ref vid) = vpc_id {
            filter_vec.push(format!("Name=vpc-id,Values={}", vid));
        }

        if let Some(ref name) = group_name {
            // Only use name filter if no group_id (group_id is a direct lookup)
            if group_id.is_none() {
                filter_vec.push(format!("Name=group-name,Values={}", name));
            }
        }

        for fs in &filter_vec {
            arg_strings.push("--filters".to_string());
            arg_strings.push(fs.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        // Execute raw API call to get PascalCase JSON for RecordData
        let response = client
            .execute("ec2", "describe-security-groups", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error: {}", e),
            })?;

        // Extract SecurityGroups array from response
        let security_groups = response
            .get("SecurityGroups")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_security_group".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability
        let target = group_id
            .as_ref()
            .map(|id| format!("sg:{}", id))
            .or_else(|| group_name.as_ref().map(|n| format!("sg:name:{}", n)))
            .unwrap_or_else(|| "sg:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query security group configuration via AWS EC2 API")
            .target(&target)
            .command("aws ec2 describe-security-groups");

        if let Some(ref id) = group_id {
            method_builder = method_builder.input("group_id", id);
        }
        if let Some(ref name) = group_name {
            method_builder = method_builder.input("group_name", name);
        }
        if let Some(ref vid) = vpc_id {
            method_builder = method_builder.input("vpc_id", vid);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        // Handle results
        if security_groups.is_empty() {
            // Security group not found
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));

            // Return empty RecordData
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        } else {
            // Use the first matching security group
            let sg = &security_groups[0];

            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Scalar fields extracted from the response
            if let Some(id) = sg
                .get("GroupId")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "group_id".to_string(),
                    ResolvedValue::String(id.to_string()),
                );
            }

            if let Some(name) = sg
                .get("GroupName")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "group_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }

            if let Some(vid) = sg.get("VpcId").and_then(|v: &serde_json::Value| v.as_str()) {
                data.add_field("vpc_id".to_string(), ResolvedValue::String(vid.to_string()));
            }

            if let Some(desc) = sg
                .get("Description")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "description".to_string(),
                    ResolvedValue::String(desc.to_string()),
                );
            }

            // Ingress rule count
            let ingress_count = sg
                .get("IpPermissions")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "ingress_rule_count".to_string(),
                ResolvedValue::Integer(ingress_count),
            );

            // Egress rule count
            let egress_count = sg
                .get("IpPermissionsEgress")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|a: &Vec<serde_json::Value>| a.len() as i64)
                .unwrap_or(0);
            data.add_field(
                "egress_rule_count".to_string(),
                ResolvedValue::Integer(egress_count),
            );

            // Check for 0.0.0.0/0 or ::/0 in ingress
            let has_ingress_anywhere = sg
                .get("IpPermissions")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|perms: &Vec<serde_json::Value>| {
                    perms.iter().any(|perm: &serde_json::Value| {
                        let ipv4_open = perm
                            .get("IpRanges")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|ranges: &Vec<serde_json::Value>| {
                                ranges.iter().any(|r: &serde_json::Value| {
                                    r.get("CidrIp")
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        .is_some_and(|c: &str| c == "0.0.0.0/0")
                                })
                            })
                            .unwrap_or(false);

                        let ipv6_open = perm
                            .get("Ipv6Ranges")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|ranges: &Vec<serde_json::Value>| {
                                ranges.iter().any(|r: &serde_json::Value| {
                                    r.get("CidrIpv6")
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        .is_some_and(|c: &str| c == "::/0")
                                })
                            })
                            .unwrap_or(false);

                        ipv4_open || ipv6_open
                    })
                })
                .unwrap_or(false);
            data.add_field(
                "has_ingress_from_anywhere".to_string(),
                ResolvedValue::Boolean(has_ingress_anywhere),
            );

            // Check for 0.0.0.0/0 or ::/0 in egress
            let has_egress_anywhere = sg
                .get("IpPermissionsEgress")
                .and_then(|v: &serde_json::Value| v.as_array())
                .map(|perms: &Vec<serde_json::Value>| {
                    perms.iter().any(|perm: &serde_json::Value| {
                        let ipv4_open = perm
                            .get("IpRanges")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|ranges: &Vec<serde_json::Value>| {
                                ranges.iter().any(|r: &serde_json::Value| {
                                    r.get("CidrIp")
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        .is_some_and(|c: &str| c == "0.0.0.0/0")
                                })
                            })
                            .unwrap_or(false);

                        let ipv6_open = perm
                            .get("Ipv6Ranges")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|ranges: &Vec<serde_json::Value>| {
                                ranges.iter().any(|r: &serde_json::Value| {
                                    r.get("CidrIpv6")
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        .is_some_and(|c: &str| c == "::/0")
                                })
                            })
                            .unwrap_or(false);

                        ipv4_open || ipv6_open
                    })
                })
                .unwrap_or(false);
            data.add_field(
                "has_egress_to_anywhere".to_string(),
                ResolvedValue::Boolean(has_egress_anywhere),
            );

            // Full API response as RecordData (PascalCase, matches CLI output)
            let record_data = RecordData::from_json_value(sg.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            // Log if multiple SGs matched
            if security_groups.len() > 1 {
                log::warn!(
                    "Multiple security groups ({}) matched query for object '{}', using first result",
                    security_groups.len(),
                    object.identifier
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_security_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_security_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_security_group', got '{}'",
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
        let collector = AwsSecurityGroupCollector::new();
        assert_eq!(collector.collector_id(), "aws_security_group_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsSecurityGroupCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_security_group"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsSecurityGroupCollector::default();
        assert_eq!(collector.collector_id(), "aws_security_group_collector");
    }
}
