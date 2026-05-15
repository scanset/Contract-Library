//! Azure Diagnostic Setting List CTN Contract
//!
//! Wraps `az monitor diagnostic-settings list --resource <id> -o json`.
//! Diagnostic settings are an *extension* resource type — every Azure
//! resource that supports them attaches diag settings via its own ARM id
//! (or, for storage accounts, via a sub-service path like
//! `<storage_id>/blobServices/default`). The OBJECT takes the resource
//! id as a single field; the cascade builder is responsible for picking
//! the right path per parent type.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_diagnostic_setting_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_diagnostic_setting_list".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_id".to_string(),
            data_type: DataType::String,
            description: "Full ARM id of the parent resource (or sub-resource path for \
                          storage accounts — `<storage_id>/blobServices/default` etc.). \
                          Passed verbatim to `az monitor diagnostic-settings list --resource`."
                .to_string(),
            example_values: vec![
                "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<kv>"
                    .to_string(),
            ],
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
            description: "Whether the list call succeeded.".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "setting_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of diagnostic settings on this resource.".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some(
                "Often 0 — most resources don't have diag settings configured.".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "settings".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array of diagnostic settings.".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [("resource_id", "resource_id"), ("subscription", "subscription")] {
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
        .optional_data_fields = vec!["setting_count".to_string(), "settings".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("setting_count".to_string(), "setting_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("settings".to_string(), "settings".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_diagnostic_setting_list".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(1),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
