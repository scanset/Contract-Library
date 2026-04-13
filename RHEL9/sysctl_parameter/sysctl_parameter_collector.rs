//! Sysctl Parameter Collector
//!
//! Collects kernel parameter values via `sysctl -n <parameter>`.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod sysctl_parameter;
//  pub use sysctl_parameter::SysctlParameterCollector;
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
pub struct SysctlParameterCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl SysctlParameterCollector {
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
}

impl CtnDataCollector for SysctlParameterCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let parameter = self
            .extract_string_field(object, "parameter")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'parameter'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "sysctl_parameter".to_string(),
            self.id.clone(),
        );

        let command_str = format!("sysctl -n {}", parameter);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query kernel parameter via sysctl")
            .target(&parameter)
            .command(&command_str)
            .input("parameter", &parameter)
            .build();
        data.set_method(method);

        let args = vec!["-n", parameter.as_str()];

        let output = self
            .executor
            .execute("sysctl", &args, Some(Duration::from_secs(5)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute sysctl: {}", e),
            })?;

        if output.exit_code != 0 {
            // Parameter not found
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        let value = output.stdout.trim().to_string();

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("value".to_string(), ResolvedValue::String(value));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["sysctl_parameter".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "sysctl_parameter" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'sysctl_parameter', got '{}'",
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
