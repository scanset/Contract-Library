//! AWS Identity Store Group CTN Contract
//!
//! Validates IAM Identity Center identity store group configuration via a
//! single AWS CLI call: identitystore list-groups --identity-store-id <id>
//!
//! The Identity Store API has no lookup-by-name operation. The collector
//! iterates all groups to find one where DisplayName == group_name exactly.
//!
//! Object requires both group_name and identity_store_id.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_identitystore_group;
//  pub use aws_identitystore_group::create_aws_identitystore_group_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_identitystore_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_identitystore_group".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "group_name".to_string(),
            data_type: DataType::String,
            description: "Group display name (exact match against DisplayName)".to_string(),
            example_values: vec!["ExampleOrgAdmins".to_string()],
            validation_notes: Some(
                "Matched against DisplayName field in list-groups results".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "identity_store_id".to_string(),
            data_type: DataType::String,
            description: "Identity store ID for the IAM Identity Center instance".to_string(),
            example_values: vec!["d-906607b0fb".to_string()],
            validation_notes: Some(
                "Found via: aws sso-admin list-instances --query 'Instances[0].IdentityStoreId'"
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // State requirements
    // ========================================================================

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the group was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Group ID (UUID format)".to_string(),
            example_values: vec!["d0e1f2a3-4567-8901-abcd-ef2345678901".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "display_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Group display name".to_string(),
            example_values: vec!["ExampleOrgAdmins".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Group description".to_string(),
            example_values: vec!["Maps to Entra group aws-example-org-admins".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "identity_store_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Identity store ID the group belongs to".to_string(),
            example_values: vec!["d-906607b0fb".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full group object from list-groups as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    for field in &["group_name", "identity_store_id", "region"] {
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
        "group_id".to_string(),
        "display_name".to_string(),
        "description".to_string(),
        "identity_store_id".to_string(),
    ];

    for field in &[
        "found",
        "group_id",
        "display_name",
        "description",
        "identity_store_id",
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

    // ========================================================================
    // Collection strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_identitystore_group".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["aws_cli".to_string(), "identitystore_read".to_string()],
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
