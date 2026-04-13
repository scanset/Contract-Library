//! AWS Identity Store Group Collector
//!
//! Single API call: identitystore list-groups --identity-store-id <id>
//! Iterates all groups to find first where DisplayName == group_name exactly.
//!
//! No separate describe call needed — list-groups returns the full group object.
//! No tags on identity store groups.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! GroupId                → "d0e1f2a3-4567-8901-abcd-ef2345678901"
//! DisplayName            → "ExampleOrgAdmins"
//! Description            → "Maps to Entra group aws-example-org-admins"
//! IdentityStoreId        → "d-906607b0fb"
//! CreatedAt              → "2026-03-23T19:58:33.760000+00:00"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_identitystore_group;
//  pub use aws_identitystore_group::AwsIdentitystoreGroupCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsIdentitystoreGroupCollector {
    id: String,
}

impl AwsIdentitystoreGroupCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_identitystore_group_collector".to_string(),
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

impl Default for AwsIdentitystoreGroupCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsIdentitystoreGroupCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let group_name = self
            .extract_string_field(object, "group_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'group_name' is required for aws_identitystore_group".to_string(),
            })?;

        let identity_store_id = self
            .extract_string_field(object, "identity_store_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'identity_store_id' is required for aws_identitystore_group".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_identitystore_group".to_string(),
            self.id.clone(),
        );

        let target = format!("identitystore-group:{}:{}", identity_store_id, group_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description(
                "Query Identity Store group via AWS CLI (list-groups with DisplayName match)",
            )
            .target(&target)
            .command("aws identitystore list-groups")
            .input("group_name", &group_name)
            .input("identity_store_id", &identity_store_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--identity-store-id", identity_store_id.as_str()];

        match client.execute("identitystore", "list-groups", &args) {
            Ok(resp) => {
                let group = resp
                    .get("Groups")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|groups| {
                        groups.iter().find(|g| {
                            g.get("DisplayName")
                                .and_then(|v: &serde_json::Value| v.as_str())
                                == Some(group_name.as_str())
                        })
                    })
                    .cloned();

                match group {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(g) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = g
                            .get("GroupId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "group_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = g
                            .get("DisplayName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "display_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = g
                            .get("Description")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "description".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = g
                            .get("IdentityStoreId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "identity_store_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        let record_data = RecordData::from_json_value(g.clone());
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
                    reason: format!("AWS API error (list-groups): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_identitystore_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_identitystore_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_identitystore_group', got '{}'",
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
            AwsIdentitystoreGroupCollector::new().collector_id(),
            "aws_identitystore_group_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsIdentitystoreGroupCollector::new().supported_ctn_types(),
            vec!["aws_identitystore_group"]
        );
    }
}
