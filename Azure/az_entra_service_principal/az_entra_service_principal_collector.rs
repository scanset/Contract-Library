//! Azure Entra ID Service Principal Collector
//!
//! Single API call: az ad sp show --id <client_id>
//! client_id is the appId of the backing app registration.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod az_entra_service_principal;
//  pub use az_entra_service_principal::AzEntraServicePrincipalCollector;
//
//////////////////////////////////////////////////////

use crate::contract_kit::commands::az::AzClient;
use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

pub struct AzEntraServicePrincipalCollector {
    id: String,
}

impl AzEntraServicePrincipalCollector {
    pub fn new() -> Self {
        Self {
            id: "az_entra_service_principal_collector".to_string(),
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

impl Default for AzEntraServicePrincipalCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AzEntraServicePrincipalCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let client_id = self
            .extract_string_field(object, "client_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'client_id' is required for az_entra_service_principal".to_string(),
            })?;

        let client = AzClient::new();

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_service_principal".to_string(),
            self.id.clone(),
        );

        let target = format!("entra-sp:{}", client_id);
        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::ApiCall)
                .description("Query Entra ID service principal via Azure CLI")
                .target(&target)
                .command("az ad sp show")
                .input("client_id", &client_id)
                .build(),
        );

        match client.execute(&["ad", "sp", "show", "--id", client_id.as_str()]) {
            Err(e) if matches!(e, crate::contract_kit::commands::az::AzError::NotFound) => {
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
                    reason: format!("Azure CLI error (az ad sp show): {}", e),
                });
            }
            Ok(sp) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                let str_fields = [
                    ("id", "sp_object_id"),
                    ("appId", "app_id"),
                    ("displayName", "display_name"),
                    ("servicePrincipalType", "service_principal_type"),
                    ("signInAudience", "sign_in_audience"),
                ];
                for (json_key, field_name) in &str_fields {
                    if let Some(v) = sp
                        .get(*json_key)
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            field_name.to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                }

                if let Some(v) = sp
                    .get("accountEnabled")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("account_enabled".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = sp
                    .get("appRoleAssignmentRequired")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "app_role_assignment_required".to_string(),
                        ResolvedValue::Boolean(v),
                    );
                }

                let key_cred_count = sp
                    .get("keyCredentials")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .map(|a| a.len() as i64)
                    .unwrap_or(0);
                data.add_field(
                    "key_credential_count".to_string(),
                    ResolvedValue::Integer(key_cred_count),
                );

                let record_data = RecordData::from_json_value(sp.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_entra_service_principal".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_entra_service_principal" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_entra_service_principal', got '{}'",
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
