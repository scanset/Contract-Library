//! Azure Security Contact Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_security_contact;
//  pub use az_security_contact::AzSecurityContactCollector;
//
///////////////////////////////////////////////////////

//! Single `az security contact show --name <name> [--subscription <id>]
//! --output json` call. Returns alert notification settings, email,
//! phone, role notifications, and the full response as RecordData.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzSecurityContactCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzSecurityContactCollector {
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
        // Security contact returns BadRequest for invalid names
        // and ResourceNotFound if no contact is configured
        stderr.contains("(BadRequest)")
            || stderr.contains("(ResourceNotFound)")
            || stderr.contains("Code: ResourceNotFound")
    }

    fn get_nested_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
        let mut current = value;
        for key in path {
            current = current.get(*key)?;
        }
        current.as_str()
    }
}

impl CtnDataCollector for AzSecurityContactCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let name = self.extract_string_field(object, "name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'name' is required for az_security_contact".to_string(),
            }
        })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_security_contact".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "security".to_string(),
            "contact".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = format!("security-contact:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Security Contact via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name);
        if let Some(ref sub) = subscription {
            method_builder = method_builder.input("subscription", sub);
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
                    "az security contact show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value =
            serde_json::from_str(output.stdout.trim()).map_err(|e| {
                CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("Failed to parse security contact show JSON: {}", e),
                }
            })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("emails", "emails"),
            ("phone", "phone"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // Derived booleans
        let has_email = resp
            .get("emails")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        data.add_field(
            "has_email".to_string(),
            ResolvedValue::Boolean(has_email),
        );

        let has_phone = resp
            .get("phone")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        data.add_field(
            "has_phone".to_string(),
            ResolvedValue::Boolean(has_phone),
        );

        // Alert notifications
        if let Some(v) = Self::get_nested_str(&resp, &["alertNotifications", "state"]) {
            data.add_field(
                "alert_notifications_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = Self::get_nested_str(&resp, &["alertNotifications", "minimalSeverity"]) {
            data.add_field(
                "alert_notifications_severity".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Notifications by role
        if let Some(v) = Self::get_nested_str(&resp, &["notificationsByRole", "state"]) {
            data.add_field(
                "notifications_by_role_state".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }

        // Role count
        let role_count = resp
            .get("notificationsByRole")
            .and_then(|v| v.get("roles"))
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        data.add_field(
            "notification_role_count".to_string(),
            ResolvedValue::Integer(role_count),
        );

        // RecordData
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_security_contact".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_security_contact" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_security_contact', got '{}'",
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
    fn not_found_matches_bad_request() {
        let stderr = "ERROR: (BadRequest) security contact name is invalid.";
        assert!(AzSecurityContactCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found() {
        let stderr = "ERROR: (ResourceNotFound) The Resource was not found.";
        assert!(AzSecurityContactCollector::is_not_found(stderr));
    }

    #[test]
    fn unrelated_error_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope '/subscriptions/abc'";
        assert!(!AzSecurityContactCollector::is_not_found(stderr));
    }
}
