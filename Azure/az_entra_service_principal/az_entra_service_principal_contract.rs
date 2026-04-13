//! Azure Entra ID Service Principal CTN Contract + Collector
//!
//! Contract:
//!   Single call: az ad sp show --id <client_id>
//!   client_id is the appId (NOT the service principal object id).
//!
//! Key scalars: sp_object_id, app_id, display_name, account_enabled,
//!   service_principal_type, app_role_assignment_required, sign_in_audience
//! Tags: flat string array same as app registration.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod az_entra_service_principal;
//  pub use az_entra_service_principal::create_az_entra_service_principal_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_entra_service_principal_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_entra_service_principal".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "client_id".to_string(),
            data_type: DataType::String,
            description: "Application (client) ID — the appId of the backing app registration"
                .to_string(),
            example_values: vec!["d4e5f6a7-b8c9-0123-4567-890abcdef012".to_string()],
            validation_notes: Some("Pass appId, not the service principal object id".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
    ];

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the service principal was found",
            "true",
        ),
        (
            "sp_object_id",
            DataType::String,
            str_eq.clone(),
            "Service principal object ID",
            "b8c9d0e1-2345-6789-0abc-def012345678",
        ),
        (
            "app_id",
            DataType::String,
            str_eq.clone(),
            "Application (client) ID",
            "d4e5f6a7-b8c9-0123-4567-890abcdef012",
        ),
        (
            "display_name",
            DataType::String,
            str_eq.clone(),
            "Service principal display name",
            "example-org-esp-daemon",
        ),
        (
            "sign_in_audience",
            DataType::String,
            str_eq.clone(),
            "Supported account types",
            "AzureADMyOrg",
        ),
        (
            "service_principal_type",
            DataType::String,
            str_eq.clone(),
            "Service principal type",
            "Application",
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
            name: "account_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the service principal is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "app_role_assignment_required".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: bool_ops.clone(),
        description: "Whether users must be assigned before using the app".to_string(),
        example_values: vec!["false".to_string()],
        validation_notes: Some(
            "true = only assigned users/groups can use the app. false = any tenant user can authenticate.".to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_credential_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of certificate credentials attached".to_string(),
            example_values: vec!["0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full service principal object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("client_id".to_string(), "client_id".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "sp_object_id".to_string(),
        "app_id".to_string(),
        "display_name".to_string(),
        "account_enabled".to_string(),
        "service_principal_type".to_string(),
        "app_role_assignment_required".to_string(),
        "sign_in_audience".to_string(),
        "key_credential_count".to_string(),
    ];

    for field in &[
        "found",
        "sp_object_id",
        "app_id",
        "display_name",
        "account_enabled",
        "service_principal_type",
        "app_role_assignment_required",
        "sign_in_audience",
        "key_credential_count",
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
        collector_type: "az_entra_service_principal".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "entra_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
