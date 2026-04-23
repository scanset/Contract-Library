//! Audit Policy Collector (Windows)
//!
//! Runs `auditpol /get /category:* /r` and parses the CSV to produce
//! per-subcategory fields: `exists`, `setting`, `success_audited`,
//! `failure_audited`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::auditpol::{
    audits_failure, audits_success, parse_auditpol_csv,
};

pub struct AuditPolicyCollector {
    id: String,
    auditpol_executor: SystemCommandExecutor,
}

impl AuditPolicyCollector {
    pub fn new(id: impl Into<String>, auditpol_executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            auditpol_executor,
        }
    }

    fn extract_required_string(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<String, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    return match value {
                        ResolvedValue::String(s) => Ok(s.clone()),
                        _ => Err(CollectionError::InvalidObjectConfiguration {
                            object_id: object.identifier.clone(),
                            reason: format!("Field '{}' must be a string", field_name),
                        }),
                    };
                }
            }
        }
        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: format!("Missing required field '{}'", field_name),
        })
    }
}

impl CtnDataCollector for AuditPolicyCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation {
                reason: e.to_string(),
            }
        })?;

        let subcategory = self.extract_required_string(object, "subcategory")?;

        let args = ["/get", "/category:*", "/r"];
        let output = self
            .auditpol_executor
            .execute("auditpol", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("auditpol execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_audit_policy".to_string(),
            self.id.clone(),
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Enumerate advanced audit policy via auditpol /r")
            .target(&subcategory)
            .command("auditpol /get /category:* /r")
            .input("subcategory", &subcategory)
            .build();
        data.set_method(method);

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();
            if stderr_lower.contains("privilege")
                || stderr_lower.contains("access")
                || stderr_lower.contains("administrator")
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: "auditpol /get requires local administrator privilege".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "auditpol failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let snapshot = parse_auditpol_csv(&output.stdout);

        match snapshot.get(&subcategory) {
            Some(setting) => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
                data.add_field(
                    "setting".to_string(),
                    ResolvedValue::String(setting.to_string()),
                );
                data.add_field(
                    "success_audited".to_string(),
                    ResolvedValue::Boolean(audits_success(setting)),
                );
                data.add_field(
                    "failure_audited".to_string(),
                    ResolvedValue::Boolean(audits_failure(setting)),
                );
            }
            None => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("setting".to_string(), ResolvedValue::String(String::new()));
                data.add_field(
                    "success_audited".to_string(),
                    ResolvedValue::Boolean(false),
                );
                data.add_field(
                    "failure_audited".to_string(),
                    ResolvedValue::Boolean(false),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_audit_policy".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_audit_policy" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_audit_policy', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
