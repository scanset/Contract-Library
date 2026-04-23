//! Windows Scheduled Task Collector
//!
//! Runs `Get-ScheduledTask | Get-ScheduledTaskInfo` via PowerShell,
//! parses the JSON, and converts the wire-format `/Date(...)/`
//! LastRunTime / NextRunTime timestamps into whole-days deltas
//! relative to the moment of collection.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract_kit::commands::get_scheduled_task::{
    build_get_scheduled_task_command, days_delta_ms, decode_task_state, is_safe_task_path,
    parse_ps_date, parse_scheduled_task_json, RawScheduledTask,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct ScheduledTaskCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl ScheduledTaskCollector {
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
            "windows_scheduled_task".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    /// Emit collected task data using a caller-supplied `now_ms` so
    /// the days-delta computation is deterministic in tests.
    pub fn emit_task_with_now(
        &self,
        object: &ExecutableObject,
        t: &RawScheduledTask,
        now_ms: i64,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_scheduled_task".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(state) = t.state {
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(decode_task_state(state).to_string()),
            );
        }
        if let Some(author) = t.author.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "author".to_string(),
                ResolvedValue::String(author.to_string()),
            );
        }
        if let Some(desc) = t.description.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(last) = t.last_run_time.as_deref() {
            if let Some(ms) = parse_ps_date(last) {
                data.add_field(
                    "last_run_time_days".to_string(),
                    ResolvedValue::Integer(days_delta_ms(now_ms, ms)),
                );
            }
        }
        if let Some(next) = t.next_run_time.as_deref() {
            if let Some(ms) = parse_ps_date(next) {
                data.add_field(
                    "next_run_time_days".to_string(),
                    ResolvedValue::Integer(days_delta_ms(now_ms, ms)),
                );
            }
        }
        if let Some(r) = t.last_task_result {
            data.add_field(
                "last_task_result".to_string(),
                ResolvedValue::Integer(r),
            );
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

impl CtnDataCollector for ScheduledTaskCollector {
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

        let path = self.extract_required_string(object, "path")?;
        if !is_safe_task_path(&path) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe task path '{}': must start with '\\' and use only safe \
                     identifier characters",
                    path
                ),
            });
        }

        let ps_body = build_get_scheduled_task_command(&path);
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
                    reason: format!("Get-ScheduledTask access denied for '{}'", path),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-ScheduledTask failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let t = parse_scheduled_task_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-ScheduledTask JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query scheduled task via Get-ScheduledTask".to_string())
            .target(&path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("path", &path)
            .build();

        let mut data = if t.is_found() {
            self.emit_task_with_now(object, &t, current_unix_ms())
        } else {
            self.emit_not_found(object)
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_scheduled_task".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_scheduled_task" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_scheduled_task', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
