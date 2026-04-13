//! Systemd Service Collector
//!
//! Collects systemd unit status via `systemctl show`.
//! Parses key=value output for ActiveState, SubState, UnitFileState, LoadState.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod systemd_service;
//  pub use systemd_service::SystemdServiceCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct SystemdServiceCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl SystemdServiceCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    /// Parse systemctl show output (key=value format)
    fn parse_systemctl_output(&self, output: &str) -> std::collections::HashMap<String, String> {
        let mut props = std::collections::HashMap::new();
        for line in output.lines() {
            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        props
    }
}

impl CtnDataCollector for SystemdServiceCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let unit_name = self
            .extract_string_field(object, "unit_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'unit_name'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "systemd_service".to_string(),
            self.id.clone(),
        );

        let command_str = format!(
            "systemctl show {} --property=ActiveState,SubState,UnitFileState,LoadState --no-pager",
            unit_name
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query systemd unit status")
            .target(&unit_name)
            .command(&command_str)
            .input("unit_name", &unit_name)
            .build();
        data.set_method(method);

        let args = vec![
            "show",
            unit_name.as_str(),
            "--property=ActiveState,SubState,UnitFileState,LoadState",
            "--no-pager",
        ];

        let args_str: Vec<&str> = args.iter().copied().collect();

        let output = self
            .executor
            .execute("systemctl", &args_str, Some(Duration::from_secs(10)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute systemctl: {}", e),
            })?;

        if output.exit_code != 0 {
            // Unit not found
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        let props = self.parse_systemctl_output(&output.stdout);

        let load_state = props.get("LoadState").map(|s| s.as_str()).unwrap_or("");

        if load_state == "not-found" {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            data.add_field(
                "load_state".to_string(),
                ResolvedValue::String("not-found".to_string()),
            );
            return Ok(data);
        }

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        if let Some(v) = props.get("ActiveState") {
            data.add_field("active_state".to_string(), ResolvedValue::String(v.clone()));
        }

        if let Some(v) = props.get("SubState") {
            data.add_field("sub_state".to_string(), ResolvedValue::String(v.clone()));
        }

        if let Some(v) = props.get("UnitFileState") {
            data.add_field("enabled".to_string(), ResolvedValue::String(v.clone()));
        }

        if let Some(v) = props.get("LoadState") {
            data.add_field("load_state".to_string(), ResolvedValue::String(v.clone()));
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["systemd_service".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "systemd_service" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'systemd_service', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}
