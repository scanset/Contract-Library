//! Azure Entra ID Application Registration Collector
//!
//! Lookup by display_name: az ad app list --display-name <n>  -> takes first result
//! Lookup by client_id:    az ad app show --id <client_id>
//!
//! Tags are a flat string array - not [{Key,Value}] like AWS.
//!   ["esp-daemon","fedramp","prooflayer"]
//!   Access via record check: field tags.* string = `fedramp` at_least_one

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzEntraApplicationCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzEntraApplicationCollector {
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

    fn set_not_found(data: &mut CollectedData) {
        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
        let empty = RecordData::from_json_value(serde_json::json!({}));
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(empty)),
        );
    }
}

impl CtnDataCollector for AzEntraApplicationCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let display_name = self.extract_string_field(object, "display_name");
        let client_id = self.extract_string_field(object, "client_id");

        if display_name.is_none() && client_id.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "At least one of 'display_name' or 'client_id' is required for az_entra_application".to_string(),
            });
        }

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_entra_application".to_string(),
            self.id.clone(),
        );

        let target = client_id
            .as_ref()
            .map(|id| format!("entra-app:{}", id))
            .or_else(|| {
                display_name
                    .as_ref()
                    .map(|n| format!("entra-app:name:{}", n))
            })
            .unwrap();

        // Build argv depending on lookup mode
        let args: Vec<String> = if let Some(ref id) = client_id {
            vec![
                "ad".to_string(),
                "app".to_string(),
                "show".to_string(),
                "--id".to_string(),
                id.clone(),
                "--output".to_string(),
                "json".to_string(),
            ]
        } else {
            let name = display_name.as_ref().unwrap();
            vec![
                "ad".to_string(),
                "app".to_string(),
                "list".to_string(),
                "--display-name".to_string(),
                name.clone(),
                "--output".to_string(),
                "json".to_string(),
            ]
        };
        let command_str = format!("az {}", args.join(" "));

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Entra ID app registration via Azure CLI")
            .target(&target)
            .command(&command_str);
        if let Some(ref n) = display_name {
            method_builder = method_builder.input("display_name", n);
        }
        if let Some(ref id) = client_id {
            method_builder = method_builder.input("client_id", id);
        }
        data.set_method(method_builder.build());

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
                Self::set_not_found(&mut data);
                return Ok(data);
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az ad app failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let parsed: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az ad app JSON: {}", e),
            }
        })?;

        // Pick the app record: direct object for `show`, first array element for `list`.
        let app = if client_id.is_some() {
            parsed
        } else {
            match parsed.as_array().and_then(|a| a.first()).cloned() {
                Some(first) => first,
                None => {
                    // Empty list = not found
                    Self::set_not_found(&mut data);
                    return Ok(data);
                }
            }
        };

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = app.get("appId").and_then(|v| v.as_str()) {
            data.add_field("app_id".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = app.get("id").and_then(|v| v.as_str()) {
            data.add_field(
                "object_id".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = app.get("displayName").and_then(|v| v.as_str()) {
            data.add_field(
                "display_name".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = app.get("signInAudience").and_then(|v| v.as_str()) {
            data.add_field(
                "sign_in_audience".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = app.get("publisherDomain").and_then(|v| v.as_str()) {
            data.add_field(
                "publisher_domain".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Password credentials
        let pwd_count = app
            .get("passwordCredentials")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "password_credential_count".to_string(),
            ResolvedValue::Integer(pwd_count),
        );
        data.add_field(
            "has_password_credentials".to_string(),
            ResolvedValue::Boolean(pwd_count > 0),
        );

        let record_data = RecordData::from_json_value(app);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_entra_application".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_entra_application" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_entra_application', got '{}'",
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
