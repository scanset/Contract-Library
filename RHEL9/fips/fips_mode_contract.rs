//! FIPS Mode CTN Contract
//!
//! Validates FIPS 140-3 mode enablement via `fips-mode-setup --check`.
//!
//! STIG Coverage:
//!   SV-258230 — RHEL 9 must enable FIPS mode
//!
//! Distro-agnostic name — works on any Linux system with fips-mode-setup
//! (RHEL 9, Rocky Linux 9, AlmaLinux 9, Amazon Linux 2023).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod fips_mode;
//  pub use fips_mode::create_fips_mode_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_fips_mode_contract() -> CtnContract {
    let mut contract = CtnContract::new("fips_mode".to_string());

    // No required object fields — checks system FIPS state
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "check_kernel".to_string(),
            data_type: DataType::Boolean,
            description: "Also verify kernel FIPS flag at /proc/sys/crypto/fips_enabled"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Default: true".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_ops = vec![Operation::Equals, Operation::NotEqual, Operation::Contains];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether FIPS mode is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived from fips-mode-setup --check output containing 'FIPS mode is enabled'"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "kernel_fips_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether /proc/sys/crypto/fips_enabled == 1".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "status_output".to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops,
            description: "Raw output of fips-mode-setup --check".to_string(),
            example_values: vec!["FIPS mode is enabled.".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tool_available".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether fips-mode-setup binary is available".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "false when fips-mode-setup is not installed (dracut-fips package missing)"
                    .to_string(),
            ),
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("check_kernel".to_string(), "check_kernel".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["enabled".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "kernel_fips_enabled".to_string(),
        "status_output".to_string(),
        "tool_available".to_string(),
    ];

    for field in &[
        "enabled",
        "kernel_fips_enabled",
        "status_output",
        "tool_available",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "fips_mode".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["command_execution".to_string()],
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
