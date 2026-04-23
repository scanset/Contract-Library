//! Local Group Collector (Windows)
//!
//! Dispatches to one of two PowerShell backends based on
//! `behavior executor <powershell|cim>`:
//!
//! - **powershell** (default): `Get-LocalGroup` + `Get-LocalGroupMember`
//!   — includes PrincipalSource.
//! - **cim**: `Win32_Group` + `Win32_GroupUser` association — no
//!   PrincipalSource, but adds SIDType in the member class mapping.
//!
//! Both backends emit the same denormalised JSON shape (single
//! `LocalGroupRecord`), so the Rust side is uniform.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::get_local_group::{
    build_cim_group_command, build_get_localgroup_command, is_safe_group_identifier, is_safe_sid,
    parse_group_json, LocalGroupRecord,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct LocalGroupCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl LocalGroupCollector {
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
            "windows_local_group".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_record(&self, object: &ExecutableObject, r: &LocalGroupRecord) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_local_group".to_string(),
            self.id.clone(),
        );

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(sid) = r.sid.as_deref().filter(|s| !s.is_empty()) {
            data.add_field("sid".to_string(), ResolvedValue::String(sid.to_string()));
        }
        if let Some(desc) = r.description.as_deref() {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(n) = r.member_count {
            data.add_field("member_count".to_string(), ResolvedValue::Integer(n));
        }
        if let Some(m) = r.members.as_deref() {
            data.add_field("members".to_string(), ResolvedValue::String(m.to_string()));
        }
        if let Some(m) = r.member_sids.as_deref() {
            data.add_field(
                "member_sids".to_string(),
                ResolvedValue::String(m.to_string()),
            );
        }
        if let Some(m) = r.member_classes.as_deref() {
            data.add_field(
                "member_object_classes".to_string(),
                ResolvedValue::String(m.to_string()),
            );
        }
        if let Some(m) = r.member_sources.as_deref() {
            data.add_field(
                "member_sources".to_string(),
                ResolvedValue::String(m.to_string()),
            );
        }

        data
    }
}

impl CtnDataCollector for LocalGroupCollector {
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

        let name = self.extract_required_string(object, "name")?;

        let executor = hints.get_parameter("executor").unwrap_or("powershell");
        let match_by_sid = hints
            .get_parameter("match_by_sid")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Different safety predicate for name-mode vs sid-mode.
        let safe = if match_by_sid {
            is_safe_sid(&name)
        } else {
            is_safe_group_identifier(&name)
        };
        if !safe {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: if match_by_sid {
                    format!(
                        "Unsafe SID '{}': expected S-1-... with digits and dashes only",
                        name
                    )
                } else {
                    format!(
                        "Unsafe group identifier '{}': name must be alphanumerics plus \
                         . _ - $ space (max 256 chars) to be embedded in a PowerShell \
                         command",
                        name
                    )
                },
            });
        }

        let ps_body = match executor {
            "powershell" => build_get_localgroup_command(&name, match_by_sid),
            "cim" => build_cim_group_command(&name, match_by_sid),
            other => {
                return Err(CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "Invalid executor '{}'. Valid values: powershell, cim",
                        other
                    ),
                })
            }
        };

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
                    reason: "local group enumeration denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "local-group query failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let record = parse_group_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse group JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description(format!(
                "Query local group via {} ({})",
                executor,
                if match_by_sid { "by SID" } else { "by name" }
            ))
            .target(&name)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("name", &name)
            .input("executor", executor)
            .input("match_by_sid", if match_by_sid { "true" } else { "false" })
            .build();

        let mut data = if record.is_found() {
            self.emit_record(object, &record)
        } else {
            self.emit_not_found(object)
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_local_group".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_local_group" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_local_group', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
