//! Azure Role Assignment List CTN Contract
//!
//! Wraps `az role assignment list -o json --all`. Returns one record per
//! RBAC role assignment visible to the credential. Each record carries
//! the principal (who), the role definition (what permissions), and the
//! scope (where). Inventory-only — assertions on assignment configuration
//! (e.g. "no Owner roles outside Break-Glass group") would be a Cat 1
//! policy on top of this.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_role_assignment_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_role_assignment_list".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Discovery scope. 'subscription' lists every assignment at or below \
                          subscription scope (with `--all`)."
                .to_string(),
            example_values: vec!["subscription".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subscription".to_string(),
            data_type: DataType::String,
            description: "Subscription ID override.".to_string(),
            example_values: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            validation_notes: None,
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    contract
        .state_requirements
        .add_required_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether the list call succeeded and parsed.".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "role_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of role assignments returned.".to_string(),
            example_values: vec!["9".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "roles".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array of role assignments.".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [("scope", "scope"), ("subscription", "subscription")] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(obj.to_string(), col.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["role_count".to_string(), "roles".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("role_count".to_string(), "role_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("roles".to_string(), "roles".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_role_assignment_list".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
