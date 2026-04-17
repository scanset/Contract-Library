//! Azure RBAC Role Assignment CTN Contract + Collector
//!
//! Single call: az role assignment list --assignee <principal_id> [--scope <scope>]
//! Returns array - finds first matching roleDefinitionName when role_name provided,
//! otherwise validates the first result.
//!
//! Key scalars: role_definition_name, scope, principal_type, principal_id,
//!   role_definition_id, assignment_id

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_role_assignment_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_role_assignment".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "principal_id".to_string(),
            data_type: DataType::String,
            description: "Service principal or user object ID to list assignments for".to_string(),
            example_values: vec!["33333333-3333-3333-3333-333333333333".to_string()],
            validation_notes: Some("Service principal object ID (not appId)".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "role_name".to_string(),
            data_type: DataType::String,
            description: "Role definition name to match in results".to_string(),
            example_values: vec!["Reader".to_string()],
            validation_notes: Some(
                "When provided, collector finds the first assignment with this roleDefinitionName"
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Scope to filter assignments".to_string(),
            example_values: vec!["/subscriptions/66666666-6666-6666-6666-666666666666".to_string()],
            validation_notes: Some("Passed as --scope to az role assignment list".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether a matching assignment was found",
            "true",
        ),
        (
            "role_definition_name",
            DataType::String,
            str_eq.clone(),
            "Role definition name",
            "Reader",
        ),
        (
            "scope",
            DataType::String,
            str_full.clone(),
            "Assignment scope",
            "/subscriptions/00000000-0000-0000-0000-000000000000/...",
        ),
        (
            "principal_id",
            DataType::String,
            str_eq.clone(),
            "Assignee principal object ID",
            "33333333-3333-3333-3333-333333333333",
        ),
        (
            "principal_type",
            DataType::String,
            str_eq.clone(),
            "Principal type",
            "ServicePrincipal",
        ),
        (
            "assignment_id",
            DataType::String,
            str_full.clone(),
            "Role assignment resource ID",
            "/subscriptions/.../roleAssignments/...",
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: dt.clone(),
                allowed_operations: ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full role assignment object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for field in &["principal_id", "role_name", "scope"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "role_definition_name".to_string(),
        "scope".to_string(),
        "principal_id".to_string(),
        "principal_type".to_string(),
        "assignment_id".to_string(),
    ];

    for field in &[
        "found",
        "role_definition_name",
        "scope",
        "principal_id",
        "principal_type",
        "assignment_id",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "resource".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_role_assignment".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "azure_rbac_read".to_string()],
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
