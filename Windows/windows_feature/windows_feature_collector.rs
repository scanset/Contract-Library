//! Windows Feature Collector
//!
//! Dispatches to one of two PowerShell backends based on
//! `behavior executor <optionalfeature|windowsfeature>`:
//!
//! - **optionalfeature** (default): `Get-WindowsOptionalFeature -Online`.
//! - **windowsfeature**: `Get-WindowsFeature` (Server SKUs only).
//!
//! Not-found semantics: both backends return empty output when the
//! feature name does not exist in their catalog. Empty output is
//! mapped to `exists=false` with no other fields emitted.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::get_windows_feature::{
    build_get_optionalfeature_command, build_get_windowsfeature_command, is_safe_feature_name,
    optionalfeature_state_is_enabled, parse_optionalfeature_json, parse_windowsfeature_json,
    windowsfeature_installstate_is_installed, RawOptionalFeature, RawWindowsFeature,
};
use crate::contract_kit::commands::powershell::encode_ps_command;

pub struct WindowsFeatureCollector {
    id: String,
    powershell_executor: SystemCommandExecutor,
}

impl WindowsFeatureCollector {
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
            "windows_feature".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(false));
        data
    }

    fn emit_optionalfeature(
        &self,
        object: &ExecutableObject,
        f: &RawOptionalFeature,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_feature".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(state) = f.state.as_deref() {
            data.add_field(
                "enabled".to_string(),
                ResolvedValue::Boolean(optionalfeature_state_is_enabled(state)),
            );
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(state.to_string()),
            );
        }
        // DisplayName is null from this backend; skip.
        data.add_field(
            "feature_type".to_string(),
            ResolvedValue::String(
                f.feature_type
                    .clone()
                    .unwrap_or_else(|| "OptionalFeature".to_string()),
            ),
        );
        data
    }

    fn emit_windowsfeature(
        &self,
        object: &ExecutableObject,
        f: &RawWindowsFeature,
    ) -> CollectedData {
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "windows_feature".to_string(),
            self.id.clone(),
        );
        data.add_field("exists".to_string(), ResolvedValue::Boolean(true));

        if let Some(state) = f.install_state.as_deref() {
            data.add_field(
                "enabled".to_string(),
                ResolvedValue::Boolean(windowsfeature_installstate_is_installed(state)),
            );
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(state.to_string()),
            );
        }
        if let Some(dn) = f.display_name.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "display_name".to_string(),
                ResolvedValue::String(dn.to_string()),
            );
        }
        if let Some(ft) = f.feature_type.as_deref().filter(|s| !s.is_empty()) {
            data.add_field(
                "feature_type".to_string(),
                ResolvedValue::String(ft.to_string()),
            );
        }
        data
    }
}

impl CtnDataCollector for WindowsFeatureCollector {
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
        if !is_safe_feature_name(&name) {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unsafe feature name '{}': must be alphanumerics plus - . _ \
                     (max 128 chars) to be embedded in a PowerShell command",
                    name
                ),
            });
        }

        // `behavior executor windowsfeature` parses as flags=["executor","windowsfeature"].
        // Check the flag form first, then fall back to the parameter form.
        let executor = if hints.has_flag("windowsfeature") {
            "windowsfeature"
        } else if hints.has_flag("optionalfeature") {
            "optionalfeature"
        } else {
            hints.get_parameter("executor").unwrap_or("optionalfeature")
        };

        let ps_body = match executor {
            "optionalfeature" => build_get_optionalfeature_command(&name),
            "windowsfeature" => build_get_windowsfeature_command(&name),
            other => {
                return Err(CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "Invalid executor '{}'. Valid values: optionalfeature, windowsfeature",
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
            // Get-WindowsFeature on Client SKUs writes a warning to stderr
            // but still exits 0 with empty stdout. A non-zero exit means
            // something else went wrong.
            let stderr_lower = output.stderr.to_lowercase();
            if stderr_lower.contains("access")
                && (stderr_lower.contains("denied") || stderr_lower.contains("administrator"))
            {
                return Err(CollectionError::AccessDenied {
                    object_id: object.identifier.clone(),
                    reason: "feature enumeration denied".to_string(),
                });
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "feature query failed (exit {}): stderr='{}', stdout='{}'",
                    output.exit_code,
                    output.stderr.trim(),
                    output.stdout.trim()
                ),
            });
        }

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description(format!("Query Windows feature via {}", executor))
            .target(&name)
            .command(format!(
                "powershell -NoProfile -NonInteractive -Command \"{}\"",
                ps_body
            ))
            .input("name", &name)
            .input("executor", executor)
            .build();

        let mut data = match executor {
            "optionalfeature" => {
                let features = parse_optionalfeature_json(&output.stdout).map_err(|e| {
                    CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!(
                            "Failed to parse Get-WindowsOptionalFeature JSON: {} (stdout='{}')",
                            e,
                            output.stdout.trim()
                        ),
                    }
                })?;
                match features.first() {
                    Some(f) => self.emit_optionalfeature(object, f),
                    None => self.emit_not_found(object),
                }
            }
            "windowsfeature" => {
                let features = parse_windowsfeature_json(&output.stdout).map_err(|e| {
                    CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!(
                            "Failed to parse Get-WindowsFeature JSON: {} (stdout='{}')",
                            e,
                            output.stdout.trim()
                        ),
                    }
                })?;
                match features.first() {
                    Some(f) => self.emit_windowsfeature(object, f),
                    None => self.emit_not_found(object),
                }
            }
            _ => unreachable!("executor was validated above"),
        };

        data.set_method(method);
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["windows_feature".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "windows_feature" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'windows_feature', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }
}
