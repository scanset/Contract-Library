//! Windows File Metadata Collector
//!
//! Runs `Get-Item <path>` (plus `Get-Acl` for owner SID) via PowerShell,
//! parses the JSON, and emits one ResolvedValue per present field.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::get_file_metadata::{
    build_get_file_metadata_command, is_safe_path, parse_file_metadata_json, RawFileMetadata,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct FileMetadataCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl FileMetadataCollector {
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
            "windows_file_metadata".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_metadata(
        &self,
        object: &ExecutableObject,
        md: &RawFileMetadata,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_file_metadata".to_string(),
            self.id.clone(),
        );

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = md.readable {
            data.add_field("readable".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.writable {
            data.add_field("writable".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.is_hidden {
            data.add_field("is_hidden".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.is_system {
            data.add_field("is_system".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.is_directory {
            data.add_field("is_directory".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.is_readonly {
            data.add_field("is_readonly".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.is_archive {
            data.add_field("is_archive".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = md.size {
            data.add_field("size".to_string(), ResolvedValue::Integer(v));
        }
        if let Some(s) = md.owner.as_deref().filter(|s| !s.is_empty()) {
            data.add_field("owner".to_string(), ResolvedValue::String(s.to_string()));
        }
        if let Some(s) = md.owner_id.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "owner_id".to_string(),
                ResolvedValue::String(s.to_string()),
            );
        }
        if let Some(s) = md.owner_error.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "owner_error".to_string(),
                ResolvedValue::String(s.to_string()),
            );
        }
        if let Some(s) = md.attributes.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "attributes".to_string(),
                ResolvedValue::String(s.to_string()),
            );
        }

        data
    }
}

impl CtnDataCollector for FileMetadataCollector {
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
        if !is_safe_path(&path) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe path '{}': contains characters that could break PowerShell \
                     single-quoted string context or inject commands",
                    path
                ),
            });
        }

        let ps_body = build_get_file_metadata_command(&path);
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
                    reason: format!("Get-Item access denied for '{}'", path),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-Item failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let md = parse_file_metadata_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-Item JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query file/directory metadata via Get-Item + Get-Acl".to_string())
            .target(&path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("path", &path)
            .build();

        let mut data = if md.is_found() {
            self.emit_metadata(object, &md)
        } else {
            self.emit_not_found(object)
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_file_metadata".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_file_metadata" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_file_metadata', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
