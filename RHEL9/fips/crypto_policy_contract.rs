//! Crypto Policy CTN Contract
//!
//! Validates system-wide cryptographic policy via `update-crypto-policies --check`
//! and symlink validation under /etc/crypto-policies/back-ends/.
//!
//! STIG Coverage:
//!   SV-258236 — RHEL 9 cryptographic policy must not be overridden
//!
//! Distro-agnostic name — works on RHEL 9, Rocky Linux 9, AlmaLinux 9,
//! and any system using the crypto-policies framework.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod crypto_policy;
//  pub use crypto_policy::create_crypto_policy_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_crypto_policy_contract() -> CtnContract {
    let mut contract = CtnContract::new("crypto_policy".to_string());

    // No required object fields
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "expected_policy".to_string(),
            data_type: DataType::String,
            description: "Expected policy name to validate against".to_string(),
            example_values: vec!["FIPS".to_string(), "DEFAULT".to_string()],
            validation_notes: Some(
                "When provided, validates current_policy matches this value".to_string(),
            ),
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
            name: "policy_matches".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether configured policy matches generated policy (no overrides)"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived from update-crypto-policies --check returning 'PASS'".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "current_policy".to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops.clone(),
            description: "Currently active cryptographic policy".to_string(),
            example_values: vec!["FIPS".to_string(), "DEFAULT".to_string()],
            validation_notes: Some("Read from /etc/crypto-policies/state/current".to_string()),
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "backends_point_to_policy".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: bool_ops.clone(),
        description: "Whether all backend symlinks point to the current policy directory".to_string(),
        example_values: vec!["true".to_string()],
        validation_notes: Some(
            "Validates /etc/crypto-policies/back-ends/*.config symlinks all target /usr/share/crypto-policies/<POLICY>/".to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tool_available".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether update-crypto-policies binary is available".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "check_output".to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops,
            description: "Raw output of update-crypto-policies --check".to_string(),
            example_values: vec![
                "The configured policy matches the generated policy\nPASS".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("expected_policy".to_string(), "expected_policy".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["policy_matches".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "current_policy".to_string(),
        "backends_point_to_policy".to_string(),
        "tool_available".to_string(),
        "check_output".to_string(),
    ];

    for field in &[
        "policy_matches",
        "current_policy",
        "backends_point_to_policy",
        "tool_available",
        "check_output",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "crypto_policy".to_string(),
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
