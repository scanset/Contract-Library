//! Azure Entra ID Group Collector
//!
//! Single API call: az ad group show --group <display_name>

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod az_entra_group;
//  pub use az_entra_group::AzEntraGroupCollector;
//
//////////////////////////////////////////////////////

use crate::contract_kit::commands::az::{AzClient, AzError};
use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

pub struct AzEntraGroupCollector {
    id: String,
}

impl AzEntraGroupCollector {
    pub fn new() -> Self {
        Self {
            id: "az_entra_group_collector".to_string(),
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

impl Default for AzEntraGroupCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AzEntraGroupCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let display_name = self
            .extract_string_field(object, "display_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'display_name' is required for az_entra_group".to_string(),
            })?;

        let client = AzClient::new();

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_group".to_string(),
            self.id.clone(),
        );

        let target = format!("entra-group:{}", display_name);
        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::ApiCall)
                .description("Query Entra ID group via Azure CLI")
                .target(&target)
                .command("az ad group show")
                .input("display_name", &display_name)
                .build(),
        );

        match client.execute(&["ad", "group", "show", "--group", display_name.as_str()]) {
            Err(AzError::NotFound) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Azure CLI error (az ad group show): {}", e),
                });
            }
            Ok(group) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = group.get("id").and_then(|v: &serde_json::Value| v.as_str()) {
                    data.add_field("group_id".to_string(), ResolvedValue::String(v.to_string()));
                }
                if let Some(v) = group
                    .get("displayName")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "display_name".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = group
                    .get("description")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "description".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = group
                    .get("securityEnabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("security_enabled".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = group
                    .get("mailEnabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("mail_enabled".to_string(), ResolvedValue::Boolean(v));
                }

                let record_data = RecordData::from_json_value(group.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_entra_group".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_entra_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_entra_group', got '{}'",
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
