//! Security Policy Collector (Windows)
//!
//! Runs `secedit /export` inside a PowerShell one-liner, parses the INF,
//! and returns the requested policy value. Each object collection
//! re-runs secedit; a future optimisation is batch collection that
//! snapshots the export once per scan.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::powershell::encode_ps_command;
use crate::contract_kit::commands::secedit::{build_secedit_export_command, parse_secedit_export};

pub struct SecurityPolicyCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl SecurityPolicyCollector {
    pub fn new(id: impl Into<String>, powershell_executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            powershell_executor,
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

impl CtnDataCollector for SecurityPolicyCollector {
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

        let policy_name = self.extract_required_string(object, "policy_name")?;

        let command = build_secedit_export_command();
        let encoded = encode_ps_command(&command);
        let args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded];

        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell/secedit execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_security_policy".to_string(),
            self.id.clone(),
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Export security policy + user rights via secedit")
            .target(&policy_name)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                command
            ))
            .input("policy_name", &policy_name)
            .input("executor", "secedit")
            .build();
        data.set_method(method);

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();
            if stderr_lower.contains("access")
                && (stderr_lower.contains("denied") || stderr_lower.contains("administrator"))
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: "secedit /export requires local administrator privilege".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "secedit export failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let export = parse_secedit_export(&output.stdout);

        match export.get(&policy_name) {
            Some(value) => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
                data.add_field(
                    "value".to_string(),
                    ResolvedValue::String(value.to_string()),
                );
            }
            None => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("value".to_string(), ResolvedValue::String(String::new()));
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_security_policy".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_security_policy" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_security_policy', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
