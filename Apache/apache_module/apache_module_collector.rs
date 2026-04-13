//! Apache Module Collector
//!
//! Runs `httpd -M` to get the list of loaded modules, then checks
//! for the requested module name. Parses the indented output format:
//!   module_name (static)
//!   module_name (shared)

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod apache_module;
//  pub use apache_module::ApacheModuleCollector;
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
pub struct ApacheModuleCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl ApacheModuleCollector {
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

    /// Parse httpd -M output into a list of (module_name, module_type) tuples.
    /// Input format:
    ///   Loaded Modules:
    ///    core_module (static)
    ///    ssl_module (shared)
    fn parse_module_list(raw: &str) -> Vec<(String, String)> {
        let mut modules = Vec::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            // Skip header line and empty lines
            if trimmed.is_empty() || trimmed.starts_with("Loaded") {
                continue;
            }
            // Parse: "module_name (type)"
            if let Some(paren_start) = trimmed.find('(') {
                if let Some(paren_end) = trimmed.find(')') {
                    let name = trimmed[..paren_start].trim().to_string();
                    let mod_type = trimmed[paren_start + 1..paren_end].trim().to_string();
                    if !name.is_empty() {
                        modules.push((name, mod_type));
                    }
                }
            }
        }
        modules
    }
}

impl CtnDataCollector for ApacheModuleCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let module = self
            .extract_string_field(object, "module")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'module'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "apache_module".to_string(),
            self.id.clone(),
        );

        let command_str = format!("httpd -M");

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("List loaded Apache modules")
            .target(&module)
            .command(&command_str)
            .input("module", &module)
            .build();
        data.set_method(method);

        let output = self
            .executor
            .execute("httpd", &["-M"], Some(Duration::from_secs(10)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute httpd -M: {}", e),
            })?;

        // httpd -M may output to stderr on some systems
        let combined = format!("{}\n{}", output.stdout, output.stderr);
        let modules = Self::parse_module_list(&combined);

        let module_count = modules.len() as i64;
        let module_names: Vec<String> = modules.iter().map(|(name, _)| name.clone()).collect();
        let modules_list = module_names.join(",");

        // Check if the requested module is loaded
        let found = modules.iter().find(|(name, _)| name == &module);

        match found {
            Some((_, mod_type)) => {
                data.add_field("loaded".to_string(), ResolvedValue::Boolean(true));
                data.add_field("module_type".to_string(), ResolvedValue::String(mod_type.clone()));
            }
            None => {
                data.add_field("loaded".to_string(), ResolvedValue::Boolean(false));
            }
        }

        data.add_field("module_count".to_string(), ResolvedValue::Integer(module_count));
        data.add_field("modules_list".to_string(), ResolvedValue::String(modules_list));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["apache_module".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "apache_module" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'apache_module', got '{}'",
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
