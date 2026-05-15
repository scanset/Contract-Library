//! Azure Resource Group List CTN Contract
//!
//! List-mode contract that wraps `az group list -o json`. Returns one
//! record per resource group visible to the credential's grants. Every
//! record reliably has `id`, `name`, `type`, `location`, and (nested)
//! `properties.provisioningState`; we hoist provisioning_state to the
//! top level in the projected record. `tags` is sometimes null.
//! `managedBy` is dropped as it's null in typical deployments.
//!
//! Used by the discovery flow as a sibling to `az_resource_list` —
//! resource groups are containers, not "resources" in ARM's enumeration
//! sense, so they don't appear in `az resource list`.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_resource_group_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_resource_group_list".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Discovery scope. 'subscription' enumerates every RG visible to the \
                          credential. (Filter modes can be added later — `az group list` does \
                          not natively take filter args, but we can add post-filter on tags.)"
                .to_string(),
            example_values: vec!["subscription".to_string()],
            validation_notes: Some(
                "Only 'subscription' is implemented today.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subscription".to_string(),
            data_type: DataType::String,
            description: "Subscription ID override. Uses AZURE_SUBSCRIPTION_ID env / cached \
                          default if absent."
                .to_string(),
            example_values: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            validation_notes: None,
        });

    // -- State requirements -------------------------------------------

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
            name: "group_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of resource groups returned by `az group list`.".to_string(),
            example_values: vec!["5".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "groups".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array — `[{id, name, type, location, \
                          provisioning_state, tags?}]`."
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // -- Field mappings -----------------------------------------------

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
        .optional_data_fields = vec!["group_count".to_string(), "groups".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("group_count".to_string(), "group_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("groups".to_string(), "groups".to_string());

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_resource_group_list".to_string(),
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
