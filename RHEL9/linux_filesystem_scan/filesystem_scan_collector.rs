//! Filesystem Scan Collector
//!
//! Runs `find` with predefined argument sets for common STIG scans:
//!   - world_writable: -type f -perm -0002
//!   - suid_sgid: -type f ( -perm -4000 -o -perm -2000 )
//!   - nouser: -nouser
//!   - nogroup: -nogroup
//!   - world_writable_dirs_no_sticky: -type d -perm -0002 ! -perm -1000
//!   - unlabeled_devices: -context system_u:object_r:unlabeled_t:*
//!
//! All scans use -xdev to stay on the root filesystem by default.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod filesystem_scan;
//  pub use filesystem_scan::FilesystemScanCollector;
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

const DEFAULT_ROOT: &str = "/";

/// Return the list of `find` arguments (after the root path) for a given
/// scan type. Returns None if the scan_type is unknown.
fn scan_args(scan_type: &str) -> Option<Vec<&'static str>> {
    match scan_type {
        "world_writable" => Some(vec!["-xdev", "-type", "f", "-perm", "-0002"]),
        "suid_sgid" => Some(vec![
            "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        ]),
        "nouser" => Some(vec!["-xdev", "-nouser"]),
        "nogroup" => Some(vec!["-xdev", "-nogroup"]),
        "world_writable_dirs_no_sticky" => Some(vec![
            "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000",
        ]),
        "orphaned_files" => Some(vec!["-xdev", "(", "-nouser", "-o", "-nogroup", ")"]),
        "dev_files_outside_dev" => Some(vec![
            "-xdev", "(", "-type", "b", "-o", "-type", "c", ")",
        ]),
        _ => None,
    }
}

#[derive(Clone)]
pub struct FilesystemScanCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl FilesystemScanCollector {
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

impl CtnDataCollector for FilesystemScanCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let scan_type = self
            .extract_string_field(object, "scan_type")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'scan_type'".to_string(),
            })?;

        let root_path = self
            .extract_string_field(object, "root_path")
            .unwrap_or_else(|| DEFAULT_ROOT.to_string());

        let expected_raw = self
            .extract_string_field(object, "expected")
            .unwrap_or_default();

        let expected_set: std::collections::HashSet<String> = expected_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let find_args = scan_args(&scan_type).ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "Unknown scan_type: '{}'. Valid: world_writable, suid_sgid, nouser, \
                    nogroup, world_writable_dirs_no_sticky, orphaned_files, dev_files_outside_dev",
                    scan_type
                ),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "filesystem_scan".to_string(),
            self.id.clone(),
        );

        // Build argument vector: root_path, then scan args
        let mut args: Vec<&str> = vec![root_path.as_str()];
        args.extend(find_args.iter().copied());

        let command_str = format!("find {} {}", root_path, find_args.join(" "));

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Scan filesystem for policy violations")
            .target(&scan_type)
            .command(&command_str)
            .input("scan_type", &scan_type)
            .input("root_path", &root_path)
            .build();
        data.set_method(method);

        let output = self
            .executor
            .execute("find", &args, Some(Duration::from_secs(120)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute find: {}", e),
            })?;

        // Note: find may return non-zero exit code even on success if it hits
        // permission-denied errors. We treat any output as valid matches.
        let raw = output.stdout.trim();
        let matches: Vec<&str> = if raw.is_empty() {
            Vec::new()
        } else {
            raw.lines().collect()
        };

        let match_count = matches.len() as i64;
        let unexpected_count = if expected_set.is_empty() {
            match_count
        } else {
            matches
                .iter()
                .filter(|m| !expected_set.contains(&m.to_string()))
                .count() as i64
        };

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("match_count".to_string(), ResolvedValue::Integer(match_count));
        data.add_field(
            "unexpected_count".to_string(),
            ResolvedValue::Integer(unexpected_count),
        );
        data.add_field(
            "matches".to_string(),
            ResolvedValue::String(matches.join("\n")),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["filesystem_scan".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "filesystem_scan" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'filesystem_scan', got '{}'",
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
