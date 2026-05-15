//! Azure Policy Assignment List CTN Contract
//!
//! Wraps `az policy assignment list -o json`. Returns one record per
//! Azure Policy assignment visible to the credential — assignments at
//! subscription, resource-group, management-group, or root scope.
//! Each record includes the policy definition reference, the scope it
//! applies at, and the enforcement mode (Default vs DoNotEnforce).
//!
//! Note: "policy assignment" here is Azure-native governance Policy, not
//! ESP `.esp` policies. The two are unrelated.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_policy_assignment_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_policy_assignment_list".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Discovery scope. 'subscription' lists assignments at the active \
                          subscription scope. (Use the optional 'subscription' field to \
                          override which subscription is queried.)"
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
            name: "assignment_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of policy assignments returned.".to_string(),
            example_values: vec!["3".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "assignments".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array of policy assignments.".to_string(),
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
        .optional_data_fields =
        vec!["assignment_count".to_string(), "assignments".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("assignment_count".to_string(), "assignment_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("assignments".to_string(), "assignments".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_policy_assignment_list".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
