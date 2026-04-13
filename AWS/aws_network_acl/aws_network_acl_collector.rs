//! AWS Network ACL Collector
//!
//! Single API call: describe-network-acls
//! Lookup by nacl_id (--network-acl-ids) or vpc_id/tags (--filters)
//!
//! Entries array contains both ingress (Egress=false) and egress (Egress=true)
//! rules. Derived scalars split them by Egress boolean.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! NetworkAclId                                → "acl-0123456789abcdef0"
//! VpcId                                       → "vpc-0123456789abcdef0"
//! IsDefault                                   → false
//! Entries.0.CidrBlock                         → "0.0.0.0/0"
//! Entries.0.Egress                            → true
//! Entries.0.Protocol                          → "6"
//! Entries.0.RuleAction                        → "allow"
//! Entries.0.RuleNumber                        → 100
//! Entries.0.PortRange.From                    → 443
//! Entries.0.PortRange.To                      → 443
//! Associations.0.SubnetId                     → "subnet-0aaaaaaaaaaaaaaaa"
//! Associations.0.NetworkAclId                 → "acl-0123456789abcdef0"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_network_acl;
//  pub use aws_network_acl::AwsNetworkAclCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsNetworkAclCollector {
    id: String,
}

impl AwsNetworkAclCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_network_acl_collector".to_string(),
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

impl Default for AwsNetworkAclCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsNetworkAclCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let nacl_id = self.extract_string_field(object, "nacl_id");
        let vpc_id = self.extract_string_field(object, "vpc_id");
        let tags = self.extract_string_field(object, "tags");
        let region = self.extract_string_field(object, "region");

        if nacl_id.is_none() && vpc_id.is_none() && tags.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason:
                    "At least one of 'nacl_id', 'vpc_id', or 'tags' is required for aws_network_acl"
                        .to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_network_acl".to_string(),
            self.id.clone(),
        );

        let target = nacl_id
            .as_ref()
            .map(|id| format!("nacl:{}", id))
            .or_else(|| tags.as_ref().map(|t| format!("nacl:tag:{}", t)))
            .unwrap_or_else(|| format!("nacl:vpc:{}", vpc_id.as_deref().unwrap_or("")));

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Network ACL configuration via AWS CLI")
            .target(&target)
            .command("aws ec2 describe-network-acls");
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // Build args
        let mut args: Vec<String> = Vec::new();
        if let Some(ref id) = nacl_id {
            args.push("--network-acl-ids".to_string());
            args.push(id.clone());
        }
        if let Some(ref v) = vpc_id {
            args.push("--filters".to_string());
            args.push(format!("Name=vpc-id,Values={}", v));
        }
        if let Some(ref t) = tags {
            // Parse Key=Value
            if let Some(eq_pos) = t.find('=') {
                let key = &t[..eq_pos];
                let val = &t[eq_pos + 1..];
                args.push("--filters".to_string());
                args.push(format!("Name=tag:{},Values={}", key, val));
            }
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match client.execute("ec2", "describe-network-acls", &args_refs) {
            Ok(resp) => {
                let nacl = resp
                    .get("NetworkAcls")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|acls| {
                        // Prefer non-default when multiple returned
                        acls.iter()
                            .find(|a| {
                                a.get("IsDefault")
                                    .and_then(|v: &serde_json::Value| v.as_bool())
                                    == Some(false)
                            })
                            .or_else(|| acls.first())
                    })
                    .cloned();

                match nacl {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(acl) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = acl
                            .get("NetworkAclId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "nacl_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = acl
                            .get("VpcId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "vpc_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = acl
                            .get("IsDefault")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field("is_default".to_string(), ResolvedValue::Boolean(v));
                        }

                        // Derive entry counts from Entries array
                        let entries = acl
                            .get("Entries")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .cloned()
                            .unwrap_or_default();

                        let entry_count = entries.len() as i64;
                        let ingress_count = entries
                            .iter()
                            .filter(|e| {
                                e.get("Egress")
                                    .and_then(|v: &serde_json::Value| v.as_bool())
                                    == Some(false)
                            })
                            .count() as i64;
                        let egress_count = entries
                            .iter()
                            .filter(|e| {
                                e.get("Egress")
                                    .and_then(|v: &serde_json::Value| v.as_bool())
                                    == Some(true)
                            })
                            .count() as i64;

                        data.add_field(
                            "entry_count".to_string(),
                            ResolvedValue::Integer(entry_count),
                        );
                        data.add_field(
                            "ingress_entry_count".to_string(),
                            ResolvedValue::Integer(ingress_count),
                        );
                        data.add_field(
                            "egress_entry_count".to_string(),
                            ResolvedValue::Integer(egress_count),
                        );

                        // Association count
                        let association_count = acl
                            .get("Associations")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .map(|a| a.len() as i64)
                            .unwrap_or(0);
                        data.add_field(
                            "association_count".to_string(),
                            ResolvedValue::Integer(association_count),
                        );

                        let record_data = RecordData::from_json_value(acl.clone());
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
                    reason: format!("AWS API error (describe-network-acls): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_network_acl".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_network_acl" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_network_acl', got '{}'",
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
            AwsNetworkAclCollector::new().collector_id(),
            "aws_network_acl_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsNetworkAclCollector::new().supported_ctn_types(),
            vec!["aws_network_acl"]
        );
    }
}
