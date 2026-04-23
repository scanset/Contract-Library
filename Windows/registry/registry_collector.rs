//! Registry Collector (Windows)
//!
//! Constructor takes pre-built `reg` and `powershell` executors — this matches
//! the agent convention (see `SystemdServiceCollector`) of threading a
//! `SharedChannel` through the registry module once and handing the resulting
//! whitelisted `SystemCommandExecutor` to each collector.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::powershell::{
    build_registry_value_args, parse_powershell_output,
};
use crate::contract_kit::commands::reg::{
    normalize_reg_type, normalize_reg_value, parse_reg_output,
};

pub struct RegistryCollector {
    id: String,
    reg_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl RegistryCollector {
    pub fn new(
        id: impl Into<String>,
        reg_executor: SystemCommandExecutor,
        powershell_executor: SystemCommandExecutor,
    ) -> Self {
        Self {
            id: id.into(),
            reg_executor,
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

    fn normalize_hive_for_reg(&self, hive: &str) -> String {
        match hive.to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM".to_string(),
            "HKCU" | "HKEY_CURRENT_USER" => "HKCU".to_string(),
            "HKCR" | "HKEY_CLASSES_ROOT" => "HKCR".to_string(),
            "HKU" | "HKEY_USERS" => "HKU".to_string(),
            "HKCC" | "HKEY_CURRENT_CONFIG" => "HKCC".to_string(),
            _ => hive.to_string(),
        }
    }

    fn collect_via_reg(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
        name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let normalized_hive = self.normalize_hive_for_reg(hive);
        let full_path = format!("{}\\{}", normalized_hive, key);
        let command_str = format!("reg query \"{}\" /v \"{}\"", full_path, name);

        let args = ["query", &full_path, "/v", name];

        let output = self.reg_executor.execute("reg", &args, None).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("reg.exe execution failed: {}", e),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry".to_string(),
            self.id.clone(),
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Query registry value via reg.exe")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("name", name)
            .input("executor", "reg")
            .build();
        data.set_method(method);

        if output.exit_code == 1 {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("value".to_string(), ResolvedValue::String(String::new()));
            return Ok(data);
        }

        if output.exit_code != 0 {
            if output.stderr.to_lowercase().contains("access")
                && output.stderr.to_lowercase().contains("denied")
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied to registry key: {}", full_path),
                });
            }

            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "reg.exe failed with exit code {}: {}",
                    output.exit_code, output.stderr
                ),
            });
        }

        match parse_reg_output(&output.stdout) {
            Some((reg_type, value)) => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
                data.add_field(
                    "type".to_string(),
                    ResolvedValue::String(normalize_reg_type(&reg_type)),
                );
                let normalized_value = normalize_reg_value(&reg_type, &value);
                data.add_field("value".to_string(), ResolvedValue::String(normalized_value));
            }
            None => {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("value".to_string(), ResolvedValue::String(String::new()));
            }
        }

        Ok(data)
    }

    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
        name: &str,
    ) -> Result<CollectedData, CollectionError> {
        let args = build_registry_value_args(hive, key, name);
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let command_str = format!("powershell {}", args.join(" "));

        let output = self
            .powershell_executor
            .execute("powershell", &args_refs, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry".to_string(),
            self.id.clone(),
        );

        let full_path = format!("{}\\{}", hive, key);
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Query registry value via PowerShell Get-ItemPropertyValue")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("name", name)
            .input("executor", "powershell")
            .build();
        data.set_method(method);

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            if stderr_lower.contains("does not exist")
                || stderr_lower.contains("cannot find path")
                || stderr_lower.contains("property")
            {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("value".to_string(), ResolvedValue::String(String::new()));
                return Ok(data);
            }

            if stderr_lower.contains("access") && stderr_lower.contains("denied") {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: format!("Access denied to registry key: {}\\{}", hive, key),
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

        let value = parse_powershell_output(&output.stdout);

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field("value".to_string(), ResolvedValue::String(value));

        Ok(data)
    }
}

impl CtnDataCollector for RegistryCollector {
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

        let hive = self.extract_required_string(object, "hive")?;
        let key = self.extract_required_string(object, "key")?;
        let name = self.extract_required_string(object, "name")?;

        // `behavior executor powershell` parses as flags=["executor","powershell"] due to the
        // behavior parser treating single-word identifiers as flags rather than param values.
        // Accept both the flag form (has_flag) and the parameter form (get_parameter), and
        // auto-select powershell for key paths containing spaces (cmd.exe splits on them).
        let use_ps = hints.has_flag("powershell")
            || hints.get_parameter("executor") == Some("powershell")
            || key.contains(' ');
        let executor = if use_ps { "powershell" } else { "reg" };

        match executor {
            "reg" => self.collect_via_reg(object, &hive, &key, &name),
            "powershell" => self.collect_via_powershell(object, &hive, &key, &name),
            _ => Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Invalid executor '{}'. Valid values: reg, powershell",
                    executor
                ),
            }),
        }
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["registry".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "registry" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'registry', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
