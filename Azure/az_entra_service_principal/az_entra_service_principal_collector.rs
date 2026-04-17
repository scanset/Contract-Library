//! Azure Entra ID Service Principal Collector
//!
//! Single API call: az ad sp show --id <client_id>
//! client_id is the appId of the backing app registration.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzEntraServicePrincipalCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzEntraServicePrincipalCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
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

    fn is_not_found(stderr: &str) -> bool {
        stderr.contains("does not exist")
            || stderr.contains("Not Found")
            || stderr.contains("Resource 'microsoft.graph")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("(NotFound)")
            || stderr.contains("404")
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

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_service_principal".to_string(),
            self.id.clone(),
        );

        let args: Vec<String> = vec![
            "ad".to_string(),
            "sp".to_string(),
            "show".to_string(),
            "--id".to_string(),
            client_id.clone(),
            "--output".to_string(),
            "json".to_string(),
        ];
        let command_str = format!("az {}", args.join(" "));

        let target = format!("entra-sp:{}", client_id);
        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::ApiCall)
                .description("Query Entra ID service principal via Azure CLI")
                .target(&target)
                .command(&command_str)
                .input("client_id", &client_id)
                .build(),
        );

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self
            .executor
            .execute("az", &arg_refs, Some(Duration::from_secs(30)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute az: {}", e),
            })?;

        if output.exit_code != 0 {
            if Self::is_not_found(&output.stderr) {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
                return Ok(data);
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az ad sp show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let sp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az ad sp show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        let str_fields = [
            ("id", "sp_object_id"),
            ("appId", "app_id"),
            ("displayName", "display_name"),
            ("servicePrincipalType", "service_principal_type"),
            ("signInAudience", "sign_in_audience"),
        ];
        for (json_key, field_name) in &str_fields {
            if let Some(v) = sp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        if let Some(v) = sp.get("accountEnabled").and_then(|v| v.as_bool()) {
            data.add_field("account_enabled".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = sp.get("appRoleAssignmentRequired").and_then(|v| v.as_bool()) {
            data.add_field(
                "app_role_assignment_required".to_string(),
                ResolvedValue::Boolean(v),
            );
        }

        let key_cred_count = sp
            .get("keyCredentials")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "key_credential_count".to_string(),
            ResolvedValue::Integer(key_cred_count),
        );

        let record_data = RecordData::from_json_value(sp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

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
