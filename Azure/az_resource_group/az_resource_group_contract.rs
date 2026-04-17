//! Azure Resource Group CTN Contract
//!
//! Validates an Azure resource group via `az group show --name <name>`.
//! Returns core scalars (location, provisioningState, managedBy) plus the
//! full response as RecordData for tag-based record_checks.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE rg_compliant
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     location string = `eastus`
//!     managed_by string = ``
//!     record
//!         field tags.Environment string = `demo`
//!         field tags.FedRAMPImpactLevel string = `moderate`
//!     record_end
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_resource_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_resource_group".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Resource group name (exact match)".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some("Required; exact resource group name".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subscription".to_string(),
            data_type: DataType::String,
            description: "Subscription ID override".to_string(),
            example_values: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            validation_notes: Some(
                "Uses AZURE_SUBSCRIPTION_ID env / cached default if not specified".to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the resource group was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Resource group name".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Full ARM resource ID".to_string(),
            example_values: vec![
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prooflayer-demo-eastus"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "location".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Azure region".to_string(),
            example_values: vec!["eastus".to_string(), "westus".to_string()],
            validation_notes: Some("Always lowercase short-name form (e.g. eastus)".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "provisioning_state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "ARM provisioning state".to_string(),
            example_values: vec!["Succeeded".to_string()],
            validation_notes: Some(
                "Values: Succeeded, Creating, Updating, Deleting, Failed, Canceled, Accepted"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "managed_by".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Resource ID of the external manager, empty if directly managed"
                .to_string(),
            example_values: vec!["".to_string()],
            validation_notes: Some(
                "Empty string when the RG is directly managed. Non-empty means an Azure \
                 Managed Application or similar is controlling the RG."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full resource group object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag assertions: field tags.Environment string = `demo`"
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("subscription".to_string(), "subscription".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "name".to_string(),
        "id".to_string(),
        "location".to_string(),
        "provisioning_state".to_string(),
        "managed_by".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "location",
        "provisioning_state",
        "managed_by",
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

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_resource_group".to_string(),
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
