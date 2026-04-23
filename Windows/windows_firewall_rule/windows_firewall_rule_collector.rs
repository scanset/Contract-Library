//! Windows Firewall Rule Collector
//!
//! Runs `Get-NetFirewallRule` via PowerShell using one of three
//! lookup parameters (Name / DisplayName / DisplayGroup) selected by
//! `behavior match_by`. Parses the JSON and translates NetSecurity's
//! integer enums back into bool / string values.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::get_firewall_rule::{
    build_get_firewall_rule_command, decode_direction, decode_primary_status,
    decode_profile_bitmask, decode_rule_action, decode_rule_enabled, is_safe_rule_identifier,
    parse_rule_json, MatchBy, RawFirewallRule,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct FirewallRuleCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl FirewallRuleCollector {
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
            "windows_firewall_rule".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_rule(&self, object: &ExecutableObject, r: &RawFirewallRule) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_firewall_rule".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = decode_rule_enabled(r.enabled) {
            data.add_field("enabled".to_string(), ResolvedValue::Boolean(v));
        }
        if let Some(v) = decode_direction(r.direction) {
            data.add_field(
                "direction".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        if let Some(v) = decode_rule_action(r.action) {
            data.add_field("action".to_string(), ResolvedValue::String(v.to_string()));
        }
        if let Some(v) = decode_profile_bitmask(r.profile) {
            data.add_field("profile".to_string(), ResolvedValue::String(v));
        }
        if let Some(dn) = r.display_name.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "display_name".to_string(),
                ResolvedValue::String(dn.to_string()),
            );
        }
        if let Some(desc) = r.description.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "description".to_string(),
                ResolvedValue::String(desc.to_string()),
            );
        }
        if let Some(dg) = r.display_group.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "display_group".to_string(),
                ResolvedValue::String(dg.to_string()),
            );
        }
        if let Some(v) = decode_primary_status(r.primary_status) {
            data.add_field(
                "primary_status".to_string(),
                ResolvedValue::String(v.to_string()),
            );
        }
        data
    }
}

impl CtnDataCollector for FirewallRuleCollector {
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
        if !is_safe_rule_identifier(&name) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe rule identifier '{}': contains characters that could break \
                     PowerShell single-quoted string context or inject commands",
                    name
                ),
            });
        }

        let match_by_str = hints.get_parameter("match_by").unwrap_or("name");
        let match_by = match MatchBy::parse(match_by_str) {
            Some(m) => m,
            None => {
                return Err(CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "Invalid match_by '{}'. Valid values: name, display_name, display_group",
                        match_by_str
                    ),
                })
            }
        };

        let ps_body = build_get_firewall_rule_command(&name, match_by);
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
                    reason: "Get-NetFirewallRule access denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Get-NetFirewallRule failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let rule = parse_rule_json(&output.stdout).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Failed to parse Get-NetFirewallRule JSON: {} (stdout='{}')",
                    e,
                    output.stdout.trim()
                ),
            }
        })?;

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query firewall rule via Get-NetFirewallRule".to_string())
            .target(&name)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("name", &name)
            .input("match_by", match_by_str)
            .build();

        let mut data = match rule {
            Some(r) => self.emit_rule(object, &r),
            None => self.emit_not_found(object),
        };
        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_firewall_rule".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_firewall_rule" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_firewall_rule', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
