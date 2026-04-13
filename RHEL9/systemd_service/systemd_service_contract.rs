//! Systemd Service CTN Contract
//!
//! Validates systemd service unit status via `systemctl show`.
//! Returns scalar fields for active state, enabled state, and sub-state.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod systemd_service_contracts;
//  pub use systemd_service_contracts::create_systemd_service_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_systemd_service_contract() -> CtnContract {
    let mut contract = CtnContract::new("systemd_service".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "unit_name".to_string(),
            data_type: DataType::String,
            description: "Systemd unit name".to_string(),
            example_values: vec!["sshd.service".to_string(), "nginx.service".to_string()],
            validation_notes: Some("Full unit name including .service suffix".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the unit exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Unit found on system".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "active_state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Active state of the unit".to_string(),
            example_values: vec![
                "active".to_string(),
                "inactive".to_string(),
                "failed".to_string(),
            ],
            validation_notes: Some("From systemctl show ActiveState".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "sub_state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Sub-state of the unit".to_string(),
            example_values: vec!["running".to_string(), "dead".to_string()],
            validation_notes: Some("From systemctl show SubState".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enabled".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the unit is enabled at boot".to_string(),
            example_values: vec![
                "enabled".to_string(),
                "disabled".to_string(),
                "masked".to_string(),
            ],
            validation_notes: Some("From systemctl show UnitFileState".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "load_state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Load state of the unit".to_string(),
            example_values: vec![
                "loaded".to_string(),
                "not-found".to_string(),
                "masked".to_string(),
            ],
            validation_notes: Some("From systemctl show LoadState".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("unit_name".to_string(), "unit_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "active_state".to_string(),
        "sub_state".to_string(),
        "enabled".to_string(),
        "load_state".to_string(),
    ];

    for field in &[
        "found",
        "active_state",
        "sub_state",
        "enabled",
        "load_state",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "systemd_service".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["systemctl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
