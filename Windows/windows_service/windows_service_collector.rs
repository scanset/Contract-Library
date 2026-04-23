//! Service Collector (Windows)

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::powershell::encode_ps_command;
use crate::contract_kit::commands::sc::{
    is_access_denied, is_service_not_found, parse_sc_qc_output, parse_sc_query_output,
};

pub struct ServiceCollector {
    id: String,
    sc_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl ServiceCollector {
    pub fn new(
        id: impl Into<String>,
        sc_executor: SystemCommandExecutor,
        powershell_executor: SystemCommandExecutor,
    ) -> Self {
        Self {
            id: id.into(),
            sc_executor,
            powershell_executor,
        }
    }

    fn extract_required_string(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<String, CollectionError> {
        self.extract_string_field(object, field_name)?
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!("Missing required field '{}'", field_name),
            })
    }

    fn extract_string_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<Option<String>, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    match value {
                        ResolvedValue::String(s) => return Ok(Some(s.clone())),
                        _ => {
                            return Err(CollectionError::InvalidObjectConfiguration {
                                object_id: object.identifier.clone(),
                                reason: format!("Field '{}' must be a string", field_name),
                            });
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn collect_via_sc(
        &self,
        object: &ExecutableObject,
        service_name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_service".to_string(),
            self.id.clone(),
        );

        let query_command = format!("sc.exe query \"{}\"", service_name);
        let qc_command = format!("sc.exe qc \"{}\"", service_name);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query Windows service state and configuration via sc.exe")
            .target(service_name)
            .command(format!("{}; {}", query_command, qc_command))
            .input("service_name", service_name)
            .input("executor", "sc")
            .build();
        data.set_method(method);

        let query_args = ["query", service_name];
        let query_output = self
            .sc_executor
            .execute("sc.exe", &query_args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("sc.exe query execution failed: {}", e),
            })?;

        if is_service_not_found(&query_output.stdout) || is_service_not_found(&query_output.stderr)
        {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        if is_access_denied(&query_output.stdout) || is_access_denied(&query_output.stderr) {
            return Err(CollectionError::AccessDenied {
                object_id: object.identifier.clone(),
                reason: format!("Access denied querying service: {}", service_name),
            });
        }

        if query_output.exit_code != 0 {
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "sc.exe query failed with exit code {}: {}",
                    query_output.exit_code, query_output.stderr
                ),
            });
        }

        let query_info = parse_sc_query_output(&query_output.stdout).ok_or_else(|| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "Failed to parse sc.exe query output".to_string(),
            }
        })?;

        let qc_args = ["qc", service_name];
        let qc_output = self
            .sc_executor
            .execute("sc.exe", &qc_args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("sc.exe qc execution failed: {}", e),
            })?;

        if is_service_not_found(&qc_output.stdout) || is_service_not_found(&qc_output.stderr) {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        if is_access_denied(&qc_output.stdout) || is_access_denied(&qc_output.stderr) {
            return Err(CollectionError::AccessDenied {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Access denied querying service configuration: {}",
                    service_name
                ),
            });
        }

        if qc_output.exit_code != 0 {
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "sc.exe qc failed with exit code {}: {}",
                    qc_output.exit_code, qc_output.stderr
                ),
            });
        }

        let qc_info = parse_sc_qc_output(&qc_output.stdout).ok_or_else(|| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "Failed to parse sc.exe qc output".to_string(),
            }
        })?;

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field("state".to_string(), ResolvedValue::String(query_info.state));
        data.add_field(
            "start_type".to_string(),
            ResolvedValue::String(qc_info.start_type),
        );
        data.add_field(
            "display_name".to_string(),
            ResolvedValue::String(qc_info.display_name),
        );
        data.add_field("path".to_string(), ResolvedValue::String(qc_info.path));
        data.add_field(
            "service_type".to_string(),
            ResolvedValue::String(qc_info.service_type),
        );

        Ok(data)
    }

    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        service_name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_service".to_string(),
            self.id.clone(),
        );

        let command = format!(
            "Get-CimInstance -ClassName Win32_Service -Filter \"Name='{}'\" | Select-Object Name, State, StartMode, DisplayName, PathName, ServiceType, DelayedAutoStart | ConvertTo-Json",
            service_name.replace('\'', "''")
        );

        let encoded = encode_ps_command(&command);
        let args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded];
        let command_str = format!(
            "powershell -NoProfile -NonInteractive -Command \"{}\"",
            command
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::WmiQuery)
            .description("Query Windows service via PowerShell Get-CimInstance (WMI)")
            .target(service_name)
            .command(&command_str)
            .input("service_name", service_name)
            .input("executor", "powershell")
            .input("wmi_class", "Win32_Service")
            .build();
        data.set_method(method);

        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            if stderr_lower.contains("access") && stderr_lower.contains("denied") {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied querying service: {}", service_name),
                });
            }

            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "PowerShell failed with exit code {}: {}",
                    output.exit_code, output.stderr
                ),
            });
        }

        let stdout_trimmed = output.stdout.trim();
        if stdout_trimmed.is_empty() || stdout_trimmed == "null" {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("state".to_string(), ResolvedValue::String(String::new()));
            data.add_field(
                "start_type".to_string(),
                ResolvedValue::String(String::new()),
            );
            return Ok(data);
        }

        let json: serde_json::Value = serde_json::from_str(stdout_trimmed).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse PowerShell JSON output: {}", e),
            }
        })?;

        let state = json
            .get("State")
            .and_then(|v| v.as_str())
            .map(normalize_powershell_state)
            .unwrap_or_else(|| "unknown".to_string());

        let start_mode = json
            .get("StartMode")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let delayed_auto_start = json
            .get("DelayedAutoStart")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let start_type = normalize_powershell_start_type(start_mode, delayed_auto_start);

        let display_name = json
            .get("DisplayName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let path = json
            .get("PathName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let service_type = json
            .get("ServiceType")
            .and_then(|v| v.as_str())
            .map(normalize_powershell_service_type)
            .unwrap_or_else(|| "unknown".to_string());

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field("state".to_string(), ResolvedValue::String(state));
        data.add_field("start_type".to_string(), ResolvedValue::String(start_type));
        data.add_field(
            "display_name".to_string(),
            ResolvedValue::String(display_name),
        );
        data.add_field("path".to_string(), ResolvedValue::String(path));
        data.add_field(
            "service_type".to_string(),
            ResolvedValue::String(service_type),
        );

        Ok(data)
    }
}

impl CtnDataCollector for ServiceCollector {
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

        let service_name = self.extract_required_string(object, "name")?;
        let executor = hints.get_parameter("executor").unwrap_or("sc");

        match executor {
            "sc" => self.collect_via_sc(object, &service_name),
            "powershell" => self.collect_via_powershell(object, &service_name),
            _ => Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Invalid executor '{}'. Valid values: sc, powershell",
                    executor
                ),
            }),
        }
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_service".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_service" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_service', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}

fn normalize_powershell_state(state: &str) -> String {
    match state {
        "Running" => "running".to_string(),
        "Stopped" => "stopped".to_string(),
        "Paused" => "paused".to_string(),
        "StartPending" => "start_pending".to_string(),
        "StopPending" => "stop_pending".to_string(),
        "ContinuePending" => "continue_pending".to_string(),
        "PausePending" => "pause_pending".to_string(),
        _ => "unknown".to_string(),
    }
}

fn normalize_powershell_start_type(start_mode: &str, delayed_auto_start: bool) -> String {
    match start_mode {
        "Automatic" | "Auto" => {
            if delayed_auto_start {
                "auto_delayed".to_string()
            } else {
                "auto".to_string()
            }
        }
        "Manual" => "manual".to_string(),
        "Disabled" => "disabled".to_string(),
        "Boot" => "boot".to_string(),
        "System" => "system".to_string(),
        _ => "unknown".to_string(),
    }
}

fn normalize_powershell_service_type(service_type: &str) -> String {
    match service_type {
        "Own Process" => "own_process".to_string(),
        "Share Process" => "share_process".to_string(),
        "Kernel Driver" => "kernel_driver".to_string(),
        "File System Driver" => "file_system_driver".to_string(),
        _ => {
            let lower = service_type.to_lowercase();
            if lower.contains("own") && lower.contains("process") {
                "own_process".to_string()
            } else if lower.contains("share") && lower.contains("process") {
                "share_process".to_string()
            } else if lower.contains("kernel") {
                "kernel_driver".to_string()
            } else if lower.contains("file") && lower.contains("system") {
                "file_system_driver".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }
}
