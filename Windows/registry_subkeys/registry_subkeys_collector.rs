//! Registry Subkeys Collector (Windows)

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct RegistrySubkeysCollector {
    id: String,
    reg_executor: SystemCommandExecutor,
    powershell_executor: SystemCommandExecutor,
}

impl RegistrySubkeysCollector {
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

    fn normalize_hive_for_powershell(&self, hive: &str) -> &'static str {
        match hive.to_uppercase().as_str() {
            "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
            "HKEY_CURRENT_USER" | "HKCU" => "HKCU",
            "HKEY_CLASSES_ROOT" | "HKCR" => "HKCR",
            "HKEY_USERS" | "HKU" => "HKU",
            "HKEY_CURRENT_CONFIG" | "HKCC" => "HKCC",
            _ => "HKLM",
        }
    }

    fn parse_reg_subkeys_output(&self, stdout: &str, parent_path: &str) -> Vec<String> {
        let mut subkeys = Vec::new();
        let parent_normalized = parent_path.to_uppercase();

        for line in stdout.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            if line.starts_with(' ') || line.starts_with('\t') || trimmed.contains("REG_") {
                continue;
            }

            if trimmed.to_uppercase().starts_with("HKEY_")
                || trimmed.to_uppercase().starts_with("HKLM")
                || trimmed.to_uppercase().starts_with("HKCU")
            {
                let trimmed_upper = trimmed.to_uppercase();

                if trimmed_upper == parent_normalized {
                    continue;
                }

                if trimmed_upper.starts_with(&parent_normalized) {
                    let prefix = format!("{}\\", parent_normalized);
                    if let Some(suffix) = trimmed_upper.strip_prefix(&prefix) {
                        if !suffix.contains('\\') && !suffix.is_empty() {
                            let original_suffix = &trimmed[parent_path.len() + 1..];
                            subkeys.push(original_suffix.to_string());
                        }
                    }
                }
            }
        }

        subkeys
    }

    fn parse_powershell_subkeys_output(&self, stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| line.to_string())
            .collect()
    }

    fn collect_via_reg(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
    ) -> Result<CollectedData, CollectionError> {
        let normalized_hive = self.normalize_hive_for_reg(hive);
        let full_path = format!("{}\\{}", normalized_hive, key);
        let command_str = format!("reg query \"{}\"", full_path);

        let args = ["query", &full_path];

        let output = self.reg_executor.execute("reg", &args, None).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("reg.exe execution failed: {}", e),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry_subkeys".to_string(),
            self.id.clone(),
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Enumerate registry subkeys via reg.exe")
            .target(&full_path)
            .command(&command_str)
            .input("hive", hive)
            .input("key", key)
            .input("executor", "reg")
            .build();
        data.set_method(method);

        if output.exit_code == 1 {
            data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
            data.add_field("subkey_count".to_string(), ResolvedValue::Integer(0));
            data.add_field("subkeys".to_string(), ResolvedValue::String(String::new()));
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

        let subkeys = self.parse_reg_subkeys_output(&output.stdout, &full_path);
        let subkey_count = subkeys.len() as i64;

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "subkey_count".to_string(),
            ResolvedValue::Integer(subkey_count),
        );
        data.add_field(
            "subkeys".to_string(),
            ResolvedValue::String(subkeys.join(",")),
        );

        Ok(data)
    }

    fn collect_via_powershell(
        &self,
        object: &ExecutableObject,
        hive: &str,
        key: &str,
    ) -> Result<CollectedData, CollectionError> {
        let ps_hive = self.normalize_hive_for_powershell(hive);

        let command = format!(
            "Get-ChildItem -Path '{}:\\{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName",
            ps_hive, key
        );

        let encoded = encode_ps_command(&command);
        let args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded];

        let output = self
            .powershell_executor
            .execute("powershell", &args, None)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("PowerShell execution failed: {}", e),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "registry_subkeys".to_string(),
            self.id.clone(),
        );

        let full_path = format!("{}:\\{}", ps_hive, key);
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::RegistryQuery)
            .description("Enumerate registry subkeys via PowerShell Get-ChildItem")
            .target(&full_path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                command
            ))
            .input("hive", hive)
            .input("key", key)
            .input("executor", "powershell")
            .build();
        data.set_method(method);

        if output.exit_code != 0 {
            let stderr_lower = output.stderr.to_lowercase();

            if stderr_lower.contains("does not exist")
                || stderr_lower.contains("cannot find path")
                || stderr_lower.contains("itemnotfoundexception")
            {
                data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
                data.add_field("subkey_count".to_string(), ResolvedValue::Integer(0));
                data.add_field("subkeys".to_string(), ResolvedValue::String(String::new()));
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

        let subkeys = self.parse_powershell_subkeys_output(&output.stdout);
        let subkey_count = subkeys.len() as i64;

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "subkey_count".to_string(),
            ResolvedValue::Integer(subkey_count),
        );
        data.add_field(
            "subkeys".to_string(),
            ResolvedValue::String(subkeys.join(",")),
        );

        Ok(data)
    }
}

impl CtnDataCollector for RegistrySubkeysCollector {
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

        let executor = hints.get_parameter("executor").unwrap_or("reg");

        match executor {
            "reg" => self.collect_via_reg(object, &hive, &key),
            "powershell" => self.collect_via_powershell(object, &hive, &key),
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
        vec!["registry_subkeys".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "registry_subkeys" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'registry_subkeys', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
