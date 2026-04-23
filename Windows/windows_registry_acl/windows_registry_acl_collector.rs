//! Windows Registry ACL Collector
//!
//! Runs `Get-Acl -LiteralPath <key_path>` via PowerShell, parses the
//! JSON, decodes each ACE's `RegistryRights` bitmask into a canonical
//! string, and emits denormalised fields (`aces`, `allow_identities`,
//! `deny_identities`) so ESP criteria can use plain string operators.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::collections::BTreeSet;

use crate::contract_kit::commands::get_registry_acl::{
    build_get_registry_acl_command, decode_registry_rights_mask, is_safe_key_path,
    parse_registry_acl_json, RawRegistryAcl,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct RegistryAclCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl RegistryAclCollector {
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
            "windows_registry_acl".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_acl(
        &self,
        object: &ExecutableObject,
        acl: &RawRegistryAcl,
        decode_generic: bool,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_registry_acl".to_string(),
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

        let mut ace_lines = Vec::with_capacity(acl.aces.len());
        let mut allow_ids: BTreeSet<String> = BTreeSet::new();
        let mut deny_ids: BTreeSet<String> = BTreeSet::new();

        for ace in &acl.aces {
            let rights = decode_registry_rights_mask(ace.rights_mask, decode_generic);
            let inherited_suffix = if ace.is_inherited == Some(true) {
                "|inherited"
            } else {
                ""
            };
            let identity = ace.identity.as_deref().unwrap_or("(unknown)");
            let ace_type = ace.ace_type.as_deref().unwrap_or("");
            ace_lines.push(format!(
                "{}|{}|{}{}",
                identity, ace_type, rights, inherited_suffix
            ));

            match ace_type {
                "Allow" => {
                    allow_ids.insert(identity.to_string());
                }
                "Deny" => {
                    deny_ids.insert(identity.to_string());
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
            ResolvedValue::String(allow_ids.into_iter().collect::<Vec<_>>().join(",")),
        );
        data.add_field(
            "deny_identities".to_string(),
            ResolvedValue::String(deny_ids.into_iter().collect::<Vec<_>>().join(",")),
        );

        data
    }
}

impl CtnDataCollector for RegistryAclCollector {
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

        let key_path = self.extract_required_string(object, "key_path")?;
        if !is_safe_key_path(&key_path) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe key_path '{}': contains characters that could break PowerShell \
                     single-quoted string context or inject commands",
                    key_path
                ),
            });
        }

        let decode_generic = hints
            .get_parameter("decode_generic_flags")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let ps_body = build_get_registry_acl_command(&key_path);
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
                    reason: format!("Get-Acl access denied for '{}'", key_path),
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

        let acl = parse_registry_acl_json(&output.stdout).map_err(|e| {
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
            .description("Query registry key ACL via Get-Acl -LiteralPath".to_string())
            .target(&key_path)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("key_path", &key_path)
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
        vec!["windows_registry_acl".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_registry_acl" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_registry_acl', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
