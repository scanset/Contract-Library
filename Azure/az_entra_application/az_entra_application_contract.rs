//! Azure Entra ID Application Registration CTN Contract
//!
//! Validates an Entra ID app registration via a single Azure CLI call:
//! az ad app list --display-name <name> OR az ad app show --id <client_id>
//!
//! Object requires either display_name or client_id.
//! Tags are a flat string array: ["esp-daemon","fedramp","prooflayer"]
//! sign_in_audience should be "AzureADMyOrg" for single-tenant apps.
//! has_password_credentials derived from passwordCredentials array length.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_entra_application_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_entra_application".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "display_name".to_string(),
            data_type: DataType::String,
            description: "App registration display name for lookup".to_string(),
            example_values: vec!["prooflayer-demo-esp-daemon".to_string()],
            validation_notes: Some(
                "Used as --display-name with az ad app list. Use display_name OR client_id."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "client_id".to_string(),
            data_type: DataType::String,
            description: "Application (client) ID for direct lookup".to_string(),
            example_values: vec!["22222222-2222-2222-2222-222222222222".to_string()],
            validation_notes: Some(
                "Used as --id with az ad app show. Use client_id OR display_name.".to_string(),
            ),
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
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the app registration was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "app_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Application (client) ID".to_string(),
            example_values: vec!["22222222-2222-2222-2222-222222222222".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "object_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "App registration object ID".to_string(),
            example_values: vec!["55555555-5555-5555-5555-555555555555".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "display_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "App registration display name".to_string(),
            example_values: vec!["prooflayer-demo-esp-daemon".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "sign_in_audience".to_string(),
        data_type: DataType::String,
        allowed_operations: str_eq.clone(),
        description: "Supported account types".to_string(),
        example_values: vec!["AzureADMyOrg".to_string()],
        validation_notes: Some(
            "AzureADMyOrg = single tenant only. AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount indicate broader audience.".to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publisher_domain".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Verified publisher domain".to_string(),
            example_values: vec!["binarysparklabs.com".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_password_credentials".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the app has active password credentials (client secrets)"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: true when passwordCredentials array is non-empty".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "password_credential_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of active password credentials".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Full app registration object as RecordData".to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "tags field is a flat string array, not [{Key,Value}]. Use record check: field tags.* string = `fedramp` at_least_one".to_string(),
        ),
    });

    // ========================================================================
    // Field mappings
    // ========================================================================

    for field in &["display_name", "client_id"] {
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
        "app_id".to_string(),
        "object_id".to_string(),
        "display_name".to_string(),
        "sign_in_audience".to_string(),
        "publisher_domain".to_string(),
        "has_password_credentials".to_string(),
        "password_credential_count".to_string(),
    ];

    for field in &[
        "found",
        "app_id",
        "object_id",
        "display_name",
        "sign_in_audience",
        "publisher_domain",
        "has_password_credentials",
        "password_credential_count",
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
        collector_type: "az_entra_application".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "entra_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
