//! Mount Point Collector
//!
//! Runs `findmnt -J <path>` to get mount details as JSON, parses the
//! filesystems array, and derives boolean flags for each hardening option.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod mount_point;
//  pub use mount_point::MountPointCollector;
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
pub struct MountPointCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl MountPointCollector {
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

    /// Parse `findmnt -J <path>` output: {"filesystems":[{...}]}
    /// Returns the first filesystem entry as a (source, fstype, options) tuple,
    /// or None if parsing fails or no filesystems present.
    fn parse_findmnt_json(
        &self,
        raw: &str,
    ) -> Option<(String, String, String)> {
        let json: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
        let filesystems = json.get("filesystems")?.as_array()?;
        if filesystems.is_empty() {
            return None;
        }
        let first = &filesystems[0];
        let source = first.get("source")?.as_str()?.to_string();
        let fstype = first.get("fstype")?.as_str()?.to_string();
        let options = first.get("options")?.as_str()?.to_string();
        Some((source, fstype, options))
    }

    /// Check if an option flag is present in a comma-separated options string
    fn has_option(options: &str, flag: &str) -> bool {
        options
            .split(',')
            .any(|opt| opt.trim().eq_ignore_ascii_case(flag))
    }
}

impl CtnDataCollector for MountPointCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let path = self
            .extract_string_field(object, "path")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'path'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "mount_point".to_string(),
            self.id.clone(),
        );

        let command_str = format!("findmnt -J {}", path);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query mount point via findmnt")
            .target(&path)
            .command(&command_str)
            .input("path", &path)
            .build();
        data.set_method(method);

        let args = vec!["-J", path.as_str()];

        let output = self
            .executor
            .execute("findmnt", &args, Some(Duration::from_secs(5)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute findmnt: {}", e),
            })?;

        if output.exit_code != 0 {
            // Path is not a separate mount point
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            // Add default false values for all option flags so policies don't
            // get "field not collected" errors when path is not a mount.
            for flag in &["nosuid", "nodev", "noexec", "ro", "relatime"] {
                data.add_field(flag.to_string(), ResolvedValue::Boolean(false));
            }
            return Ok(data);
        }

        let parsed = self.parse_findmnt_json(&output.stdout);

        match parsed {
            Some((source, fstype, options)) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));
                data.add_field("source".to_string(), ResolvedValue::String(source));
                data.add_field("fstype".to_string(), ResolvedValue::String(fstype));

                // Derive each option flag from the options string
                for flag in &["nosuid", "nodev", "noexec", "ro", "relatime"] {
                    let present = Self::has_option(&options, flag);
                    data.add_field(
                        flag.to_string(),
                        ResolvedValue::Boolean(present),
                    );
                }

                data.add_field("options".to_string(), ResolvedValue::String(options));
            }
            None => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                for flag in &["nosuid", "nodev", "noexec", "ro", "relatime"] {
                    data.add_field(flag.to_string(), ResolvedValue::Boolean(false));
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["mount_point".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "mount_point" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'mount_point', got '{}'",
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
