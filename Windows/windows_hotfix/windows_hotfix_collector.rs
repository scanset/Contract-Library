//! Windows HotFix Collector
//!
//! Runs `Get-HotFix -Id <kb_id>` via PowerShell, parses the JSON, and
//! converts the wire-format `/Date(...)/` InstalledOn timestamp into a
//! whole-days delta relative to the moment of collection.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract_kit::commands::get_hotfix::{
    build_get_hotfix_command, days_between_ms, is_safe_kb_id, parse_hotfix_json,
    parse_ps_date_string, RawHotFix,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct HotfixCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl HotfixCollector {
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

    fn emit_not_found(&self, object: &ExecutableObject) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_hotfix".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_hotfix_with_now(
        &self,
        object: &ExecutableObject,
        hf: &RawHotFix,
        now_ms: i64,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_hotfix".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(desc) = hf.description.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(by) = hf.installed_by.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "installed_by".to_string(),
                ResolvedValue::String(by.to_string()),
            );
        }
        if let Some(installed_on) = hf.installed_on.as_ref() {
            if let Some(ms_str) = installed_on.value.as_deref() {
                if let Some(ms) = parse_ps_date_string(ms_str) {
                    let days = days_between_ms(now_ms, ms);
                    data.add_field(
                        "installed_on_days".to_string(),
                        ResolvedValue::Integer(days),
                    );
                }
            }
        }
        data
    }
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl CtnDataCollector for HotfixCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        contract
            .validate_behavior_hints(hints)
            .map_err(|e| CollectionError::CtnContractValidation {
                reason: e.to_string(),
            })?;

        let kb_id = self.extract_required_string(object, "kb_id")?;
        if !is_safe_kb_id(&kb_id) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe kb_id '{}': must match ^KB\\d+$ and be <= 16 chars",
                    kb_id
                ),
            });
        }

        let ps_body = build_get_hotfix_command(&kb_id);
        let encoded = encode_ps_command(&ps_body);
        let args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded];
        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();
            if stderr_lower.contains("access")
                && (stderr_lower.contains("denied") || stderr_lower.contains("administrator"))
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: "Get-HotFix access denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-HotFix failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let hf = parse_hotfix_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-HotFix JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query installed hotfix via Get-HotFix".to_string())
            .target(&kb_id)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("kb_id", &kb_id)
            .build();

        let mut data = if hf.is_found() {
            self.emit_hotfix_with_now(object, &hf, current_unix_ms())
        } else {
            self.emit_not_found(object)
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_hotfix".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_hotfix" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_hotfix', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
