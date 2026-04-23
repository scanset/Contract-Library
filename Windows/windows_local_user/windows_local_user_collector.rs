//! Local User Collector (Windows)
//!
//! Dispatches to one of two PowerShell backends based on
//! `behavior executor <powershell|cim>`:
//!
//! - **powershell** (default): `Get-LocalUser` — full fidelity including
//!   date fields (PasswordLastSet, PasswordExpires, LastLogon,
//!   AccountExpires).
//! - **cim**: `Get-CimInstance Win32_UserAccount` — no date fields, but
//!   exposes `Lockout`.
//!
//! RID-based lookup (`behavior match_by_rid true`) treats the `name`
//! field as a RID suffix for well-known-account resolution after rename.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract_kit::commands::get_local_user::{
    build_cim_useraccount_command, build_get_localuser_command, days_between, is_safe_identifier,
    parse_cim_json, parse_localuser_json, parse_ps_date, RawCimUser, RawLocalUser,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct LocalUserCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl LocalUserCollector {
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

    fn now_epoch_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn emit_not_found(&self, object: &ExecutableObject) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_local_user".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_localuser(
        &self,
        object: &ExecutableObject,
        u: &RawLocalUser,
        now_ms: i64,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_local_user".to_string(),
            self.id.clone(),
        );

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = u.enabled {
            data.add_field("enabled".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = u.password_required {
            data.add_field("password_required".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = u.user_may_change_password {
            data.add_field(
                "user_may_change_password".to_string(),
                ResolvedValue::Boolean(v),
            );
        }

        // PasswordExpires is a DateTime in Get-LocalUser; treat presence
        // of a non-null value as "policy flag on" for schema parity with
        // the cim backend.
        let pw_expires_policy = u.password_expires.as_deref().map(|s| !s.is_empty());
        if let Some(v) = pw_expires_policy {
            data.add_field("password_expires".to_string(), ResolvedValue::Boolean(v));
        }

        if let Some(sid) = u.sid.as_deref().filter(|s| !s.is_empty()) {
            data.add_field("sid".to_string(), ResolvedValue::String(sid.to_string()));
        }
        if let Some(desc) = u.description.as_deref() {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(fname) = u.full_name.as_deref() {
            data.add_field(
                "full_name".to_string(),
                ResolvedValue::String(fname.to_string()),
            );
        }

        if let Some(ms) = parse_ps_date(&u.password_last_set) {
            data.add_field(
                "password_last_set_days".to_string(),
                ResolvedValue::Integer(days_between(ms, now_ms)),
            );
        }
        if let Some(ms) = parse_ps_date(&u.password_expires) {
            data.add_field(
                "password_expires_days".to_string(),
                // For expiry: negative value means expired
                ResolvedValue::Integer(days_between(ms, now_ms).saturating_neg()),
            );
        }
        if let Some(ms) = parse_ps_date(&u.last_logon) {
            data.add_field(
                "last_logon_days".to_string(),
                ResolvedValue::Integer(days_between(ms, now_ms)),
            );
        }
        if let Some(ms) = parse_ps_date(&u.account_expires) {
            data.add_field(
                "account_expires_days".to_string(),
                ResolvedValue::Integer(days_between(ms, now_ms).saturating_neg()),
            );
        }

        data
    }

    fn emit_cim(&self, object: &ExecutableObject, u: &RawCimUser) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_local_user".to_string(),
            self.id.clone(),
        );

        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        // Enabled = !Disabled
        if let Some(v) = u.disabled {
            data.add_field("enabled".to_string(), ResolvedValue::Boolean(!v));
        }
        if let Some(v) = u.password_required {
            data.add_field("password_required".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = u.password_changeable {
            data.add_field(
                "user_may_change_password".to_string(),
                ResolvedValue::Boolean(v),
            );
        }
        if let Some(v) = u.password_expires {
            data.add_field("password_expires".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = u.lockout {
            data.add_field("lockout".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(sid) = u.sid.as_deref().filter(|s| !s.is_empty()) {
            data.add_field("sid".to_string(), ResolvedValue::String(sid.to_string()));
        }
        if let Some(desc) = u.description.as_deref() {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(fname) = u.full_name.as_deref() {
            data.add_field(
                "full_name".to_string(),
                ResolvedValue::String(fname.to_string()),
            );
        }

        data
    }
}

impl CtnDataCollector for LocalUserCollector {
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
        if !is_safe_identifier(&name) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe identifier '{}': name must be alphanumerics plus . _ - $ \
                     (max 64 chars) to be embedded in a PowerShell command",
                    name
                ),
            });
        }

        let executor = hints.get_parameter("executor").unwrap_or("powershell");
        let match_by_rid = hints
            .get_parameter("match_by_rid")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let ps_body = match executor {
            "powershell" => build_get_localuser_command(&name, match_by_rid),
            "cim" => build_cim_useraccount_command(&name, match_by_rid),
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
                    reason: "local user enumeration denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "local-user query failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description(format!(
                "Query local account via {} ({})",
                executor,
                if match_by_rid { "by RID" } else { "by name" }
            ))
            .target(&name)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("name", &name)
            .input("executor", executor)
            .input("match_by_rid", if match_by_rid { "true" } else { "false" })
            .build();

        let mut data = match executor {
            "powershell" => {
                let users = parse_localuser_json(&output.stdout).map_err(|e| {
                    CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!(
                            "Failed to parse Get-LocalUser JSON: {} (stdout='{}')",
                            e,
                            output.stdout.trim()
                        ),
                    }
                })?;
                match users.first() {
                    Some(u) => self.emit_localuser(object, u, Self::now_epoch_ms()),
                    None => self.emit_not_found(object),
                }
            }
            "cim" => {
                let users = parse_cim_json(&output.stdout).map_err(|e| {
                    CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!(
                            "Failed to parse Win32_UserAccount JSON: {} (stdout='{}')",
                            e,
                            output.stdout.trim()
                        ),
                    }
                })?;
                match users.first() {
                    Some(u) => self.emit_cim(object, u),
                    None => self.emit_not_found(object),
                }
            }
            _ => unreachable!("executor was validated above"),
        };

        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_local_user".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_local_user" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_local_user', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
