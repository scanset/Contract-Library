//! Windows File ACL Collector
//!
//! Runs `Get-Acl <path>` via PowerShell, parses the JSON, decodes each
//! ACE's `FileSystemRights` bitmask into a canonical string, and emits
//! denormalised fields (`aces`, `allow_identities`, `deny_identities`)
//! so ESP criteria can use plain string operators.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::collections::BTreeSet;

use crate::contract_kit::commands::get_file_acl::{
    build_get_acl_command, decode_rights_mask, is_safe_path, parse_acl_json, RawAcl,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct FileAclCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl FileAclCollector {
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
            "windows_file_acl".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_acl(
        &self,
        object: &ExecutableObject,
        acl: &RawAcl,
        decode_generic: bool,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_file_acl".to_string(),
            self.id.clone(),
        );

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = acl.inheritance_protected {
            data.add_field(
                "inheritance_protected".to_string(),
                ResolvedValue::Boolean(v),
            );
        }
        if let Some(owner) = acl.owner.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "owner".to_string(),
                ResolvedValue::String(owner.to_string()),
            );
        }
        if let Some(group) = acl.group.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "group".to_string(),
                ResolvedValue::String(group.to_string()),
            );
        }
        if let Some(sddl) = acl.sddl.as_deref().filter(|s| !s.is_empty()) {
            data.add_field("sddl".to_string(), ResolvedValue::String(sddl.to_string()));
        }
        data.add_field(
            "ace_count".to_string(),
            ResolvedValue::Integer(acl.aces.len() as i64),
        );

        // Denormalise ACEs into newline-joined triples.
        let mut ace_lines = Vec::with_capacity(acl.aces.len());
        let mut allow_ids: BTreeSet<String> = BTreeSet::new();
        let mut deny_ids: BTreeSet<String> = BTreeSet::new();

        for ace in &acl.aces {
            let rights = decode_rights_mask(ace.rights_mask, decode_generic);
            let inherited_suffix = if ace.is_inherited == Some(true) {
                "|inherited"
            } else {
                ""
            };
            ace_lines.push(format!(
                "{}|{}|{}{}",
                ace.identity, ace.ace_type, rights, inherited_suffix
            ));

            match ace.ace_type.as_str() {
                "Allow" => {
                    allow_ids.insert(ace.identity.clone());
                }
                "Deny" => {
                    deny_ids.insert(ace.identity.clone());
                }
                _ => {}
            }
        }

        data.add_field(
            "aces".to_string(),
            ResolvedValue::String(ace_lines.join("\n")),
        );
        data.add_field(
            "allow_identities".to_string(),
            ResolvedValue::String(
                allow_ids.into_iter().collect::<Vec<_>>().join(","),
            ),
        );
        data.add_field(
            "deny_identities".to_string(),
            ResolvedValue::String(
                deny_ids.into_iter().collect::<Vec<_>>().join(","),
            ),
        );

        data
    }
}

impl CtnDataCollector for FileAclCollector {
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

        let decode_generic = hints
            .get_parameter("decode_generic_flags")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let ps_body = build_get_acl_command(&path);
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
                    reason: format!("Get-Acl access denied for '{}'", path),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-Acl failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let acl = parse_acl_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-Acl JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query file/directory ACL via Get-Acl".to_string())
            .target(&path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("path", &path)
            .input(
                "decode_generic_flags",
                if decode_generic { "true" } else { "false" },
            )
            .build();

        let mut data = if acl.is_found() {
            self.emit_acl(object, &acl, decode_generic)
        } else {
            self.emit_not_found(object)
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_file_acl".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_file_acl" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_file_acl', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
