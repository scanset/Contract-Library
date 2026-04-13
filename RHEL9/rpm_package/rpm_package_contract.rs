//! RPM Package CTN Contract
//!
//! Validates RPM package installation state via `rpm -q`.
//! Checks whether a package is installed or not installed.
//!
//! STIG Coverage:
//!   SV-257826 — No FTP server (vsftpd must not be installed)
//!   SV-257835 — No TFTP server (tftp-server must not be installed)
//!
//! Distro-agnostic name — works on any RPM-based Linux distribution
//! (Rocky Linux, RHEL, AlmaLinux, CentOS, Amazon Linux 2/2023, Fedora).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod rpm_package;
//  pub use rpm_package::create_rpm_package_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_rpm_package_contract() -> CtnContract {
    let mut contract = CtnContract::new("rpm_package".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "package_name".to_string(),
            data_type: DataType::String,
            description: "RPM package name to query".to_string(),
            example_values: vec![
                "vsftpd".to_string(),
                "tftp-server".to_string(),
                "aide".to_string(),
            ],
            validation_notes: Some("Passed directly to rpm -q".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "installed".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether the package is installed".to_string(),
            example_values: vec!["false".to_string(), "true".to_string()],
            validation_notes: Some(
                "true when rpm -q returns exit code 0. false when 'not installed'.".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "version".to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops.clone(),
            description: "Installed package version string".to_string(),
            example_values: vec!["3.0.5-5.el9".to_string()],
            validation_notes: Some("Only populated when installed = true".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "full_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops,
            description: "Full rpm -q output (name-version-release.arch)".to_string(),
            example_values: vec!["vsftpd-3.0.5-5.el9.x86_64".to_string()],
            validation_notes: Some("Only populated when installed = true".to_string()),
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("package_name".to_string(), "package_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["installed".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["version".to_string(), "full_name".to_string()];

    for field in &["installed", "version", "full_name"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "rpm_package".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["rpm_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
