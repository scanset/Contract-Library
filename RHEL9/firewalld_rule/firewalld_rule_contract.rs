//! Firewalld Rule CTN Contract
//!
//! Validates firewalld configuration via `firewall-cmd --list-all --zone=<zone>`
//! and checks individual properties (services, ports, target, masquerade, etc.)
//! as well as global state (running, panic-mode).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod firewalld_rule;
//  pub use firewalld_rule::create_firewalld_rule_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_firewalld_rule_contract() -> CtnContract {
    let mut contract = CtnContract::new("firewalld_rule".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "zone".to_string(),
            data_type: DataType::String,
            description: "Firewall zone to inspect".to_string(),
            example_values: vec!["public".to_string(), "trusted".to_string()],
            validation_notes: Some(
                "Defaults to active zone if omitted. Use 'panic' for panic-mode check."
                    .to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether firewalld is running and the zone was inspected".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "running".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether firewalld daemon is running".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "panic_mode".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether firewall is in panic mode (drops all traffic)".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "target".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Zone target policy (default, DROP, REJECT, ACCEPT)".to_string(),
            example_values: vec!["default".to_string(), "DROP".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "services".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Space-separated list of allowed services".to_string(),
            example_values: vec!["ssh dhcpv6-client".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ports".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Space-separated list of open ports".to_string(),
            example_values: vec!["".to_string(), "22/tcp".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "masquerade".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether masquerading is enabled".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "interfaces".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Space-separated list of interfaces bound to the zone".to_string(),
            example_values: vec!["enp0s3 enp0s8".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rich_rules".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Rich rules configured for the zone".to_string(),
            example_values: vec!["".to_string()],
            validation_notes: None,
        });

    // -- Field mappings -----------------------------------------------

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("zone".to_string(), "zone".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "running".to_string(),
        "panic_mode".to_string(),
        "target".to_string(),
        "services".to_string(),
        "ports".to_string(),
        "masquerade".to_string(),
        "interfaces".to_string(),
        "rich_rules".to_string(),
    ];

    for field in &[
        "found",
        "running",
        "panic_mode",
        "target",
        "services",
        "ports",
        "masquerade",
        "interfaces",
        "rich_rules",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "firewalld_rule".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["firewall_cmd_access".to_string()],
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
