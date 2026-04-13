//! Sysctl Parameter CTN Contract
//!
//! Validates kernel parameters via `sysctl -n`.
//! Returns the parameter value as a string for comparison.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod sysctl_parameter_contracts;
//  pub use sysctl_parameter_contracts::create_sysctl_parameter_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_sysctl_parameter_contract() -> CtnContract {
    let mut contract = CtnContract::new("sysctl_parameter".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "parameter".to_string(),
            data_type: DataType::String,
            description: "Sysctl parameter name".to_string(),
            example_values: vec![
                "net.ipv4.ip_forward".to_string(),
                "kernel.randomize_va_space".to_string(),
            ],
            validation_notes: Some("Dotted sysctl parameter name".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the parameter exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Parameter found in kernel".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Parameter value".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some("Raw string value from sysctl".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("parameter".to_string(), "parameter".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["value".to_string()];

    for field in &["found", "value"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "sysctl_parameter".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["sysctl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(10),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
