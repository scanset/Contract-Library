//! RPM Package Collector
//!
//! Queries RPM package installation state via `rpm -q <package>`.
//! Parses exit code and stdout for installed/not-installed determination.
//!
//! STIG: SV-257826 (vsftpd), SV-257835 (tftp-server)

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod rpm_package;
//  pub use rpm_package::RpmPackageCollector;
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
pub struct RpmPackageCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl RpmPackageCollector {
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

impl CtnDataCollector for RpmPackageCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let package_name = self
            .extract_string_field(object, "package_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'package_name' is required for rpm_package".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "rpm_package".to_string(),
            self.id.clone(),
        );

        let command_str = format!("rpm -q {}", package_name);
        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::Command)
                .description("Query RPM package installation state")
                .target(&package_name)
                .command(&command_str)
                .input("package_name", &package_name)
                .build(),
        );

        let output = self
            .executor
            .execute(
                "rpm",
                &["-q", package_name.as_str()],
                Some(Duration::from_secs(10)),
            )
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute rpm: {}", e),
            })?;

        // rpm exit code 0 = installed, 1 = not installed
        let installed = output.exit_code == 0;
        data.add_field("installed".to_string(), ResolvedValue::Boolean(installed));

        if installed {
            let full_name = output.stdout.trim().to_string();
            data.add_field(
                "full_name".to_string(),
                ResolvedValue::String(full_name.clone()),
            );

            // Extract version — everything after first hyphen up to arch
            // Format: name-version-release.arch
            if let Some(rest) = full_name.strip_prefix(&format!("{}-", package_name)) {
                // Strip .arch suffix
                let version_release = if let Some(dot_pos) = rest.rfind('.') {
                    &rest[..dot_pos]
                } else {
                    &rest[..]
                };
                data.add_field(
                    "version".to_string(),
                    ResolvedValue::String(version_release.to_string()),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["rpm_package".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "rpm_package" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'rpm_package', got '{}'",
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
