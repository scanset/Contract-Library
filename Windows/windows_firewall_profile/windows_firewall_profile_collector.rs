//! Windows Firewall Profile Collector
//!
//! Runs `Get-NetFirewallProfile -Name <profile>` via PowerShell,
//! parses the JSON, and translates the NetSecurity GpoBoolean /
//! GpoAction integer enums back into bool / string values.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::get_firewall_profile::{
    build_get_firewall_profile_command, canonical_profile_name, decode_action, decode_enabled,
    decode_log_flag, parse_profile_json, RawFirewallProfile,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct FirewallProfileCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl FirewallProfileCollector {
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
            "windows_firewall_profile".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_profile(
        &self,
        object: &ExecutableObject,
        p: &RawFirewallProfile,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_firewall_profile".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = decode_enabled(p.enabled) {
            data.add_field("enabled".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = decode_action(p.default_inbound_action) {
            data.add_field(
                "default_inbound_action".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = decode_action(p.default_outbound_action) {
            data.add_field(
                "default_outbound_action".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = decode_log_flag(p.log_allowed) {
            data.add_field("log_allowed".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = decode_log_flag(p.log_blocked) {
            data.add_field("log_blocked".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(fname) = p.log_file_name.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "log_file_name".to_string(),
                ResolvedValue::String(fname.to_string()),
            );
        }
        if let Some(v) = decode_log_flag(p.notify_on_listen) {
            data.add_field("notify_on_listen".to_string(), ResolvedValue::Boolean(v));
        }

        data
    }
}

impl CtnDataCollector for FirewallProfileCollector {
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
        let canonical = match canonical_profile_name(&name) {
            Some(v) => v,
            None => {
                return Err(CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "Unsafe profile name '{}': must be one of Domain, Private, Public",
                        name
                    ),
                })
            }
        };

        let ps_body = build_get_firewall_profile_command(canonical);
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
                    reason: "Get-NetFirewallProfile access denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-NetFirewallProfile failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let profile = parse_profile_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-NetFirewallProfile JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query firewall profile via Get-NetFirewallProfile".to_string())
            .target(canonical)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("name", canonical)
            .build();

        let mut data = match profile {
            Some(p) => self.emit_profile(object, &p),
            None => self.emit_not_found(object),
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_firewall_profile".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_firewall_profile" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_firewall_profile', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
