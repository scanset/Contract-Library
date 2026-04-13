//! GNOME/dconf Setting Collector
//!
//! Runs `gsettings get <schema> <key>` to read GNOME settings.
//! Parses the GVariant output format, stripping type prefixes.
//! Returns `applicable: false` when gsettings is not installed.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod dconf_setting;
//  pub use dconf_setting::DconfSettingCollector;
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
pub struct DconfSettingCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl DconfSettingCollector {
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

    /// Parse GVariant output from gsettings.
    /// Strips type prefixes:
    ///   "true"       -> "true"
    ///   "false"      -> "false"
    ///   "uint32 300" -> "300"
    ///   "'never'"    -> "never"
    ///   "@as []"     -> "[]"
    fn parse_gsetting_value(raw: &str) -> String {
        let trimmed = raw.trim();

        // Strip GVariant type prefixes: "uint32 300" -> "300"
        let known_prefixes = [
            "uint32 ", "int32 ", "uint64 ", "int64 ",
            "double ", "byte ", "int16 ", "uint16 ",
        ];
        for prefix in &known_prefixes {
            if trimmed.starts_with(prefix) {
                return trimmed[prefix.len()..].to_string();
            }
        }

        // Strip @type prefixes: "@as []" -> "[]"
        if trimmed.starts_with('@') {
            if let Some(space_idx) = trimmed.find(' ') {
                return trimmed[space_idx + 1..].to_string();
            }
        }

        // Strip surrounding quotes: "'never'" -> "never"
        if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
            return trimmed[1..trimmed.len() - 1].to_string();
        }

        trimmed.to_string()
    }
}

impl CtnDataCollector for DconfSettingCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let schema = self
            .extract_string_field(object, "schema")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'schema'".to_string(),
            })?;

        let key = self
            .extract_string_field(object, "key")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'key'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "dconf_setting".to_string(),
            self.id.clone(),
        );

        let command_str = format!("gsettings get {} {}", schema, key);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Read GNOME setting via gsettings")
            .target(&format!("{}.{}", schema, key))
            .command(&command_str)
            .input("schema", &schema)
            .input("key", &key)
            .build();
        data.set_method(method);

        let output = self
            .executor
            .execute("gsettings", &["get", &schema, &key], Some(Duration::from_secs(5)));

        match output {
            Ok(out) => {
                if out.exit_code != 0 {
                    // gsettings exists but schema/key not found
                    let stderr = out.stderr.trim();
                    if stderr.contains("No such schema") || stderr.contains("No such key") {
                        data.add_field("applicable".to_string(), ResolvedValue::Boolean(false));
                    } else {
                        data.add_field("applicable".to_string(), ResolvedValue::Boolean(true));
                    }
                    return Ok(data);
                }

                let parsed = Self::parse_gsetting_value(&out.stdout);
                data.add_field("applicable".to_string(), ResolvedValue::Boolean(true));
                data.add_field("value".to_string(), ResolvedValue::String(parsed));
            }
            Err(_) => {
                // gsettings binary not found - GNOME not installed
                data.add_field("applicable".to_string(), ResolvedValue::Boolean(false));
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["dconf_setting".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "dconf_setting" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'dconf_setting', got '{}'",
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
