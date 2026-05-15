//! Azure ARM Resource List CTN Contract
//!
//! List-mode contract that wraps `az resource list -o json`. Returns a flat
//! inventory of resources visible to the credential's grants — every record
//! has `id`, `name`, `type`, `location`, `resourceGroup`, `provisioningState`
//! reliably populated; `kind` / `sku` / `tags` populated for resource types
//! that carry them; `properties` is always null in this call (use typed
//! `az_<resource>_list` contracts for configuration scanning).
//!
//! Designed for DISCOVERY-mode policies once the engine grammar accepts
//! `META.assessment_method = DISCOVERY`. Until that lands, the contract is
//! useable today via `assessment_method = TEST` — STATE asserts the call
//! succeeded and at least one record came back; the full record array is
//! attached to the envelope as RecordData under `resources`.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! OBJECT discovery_scope
//!     scope `subscription`
//! OBJECT_END
//!
//! STATE st_admit
//!     found          boolean = true
//!     resource_count int     >= 1
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_resource_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_resource_list".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Discovery scope. 'subscription' enumerates everything the credential \
                          can see; 'resource_group' narrows to one RG (combine with the \
                          resource_group field); 'resource_type' filters to a specific ARM type \
                          (combine with the resource_type field)."
                .to_string(),
            example_values: vec![
                "subscription".to_string(),
                "resource_group".to_string(),
                "resource_type".to_string(),
            ],
            validation_notes: Some(
                "Currently only 'subscription' is implemented; the narrower modes are reserved \
                 for the next iteration."
                    .to_string(),
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

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Optional resource group filter — collector adds --resource-group <rg> \
                          to the az call."
                .to_string(),
            example_values: vec!["pltestlz-tenant-a-rg".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "resource_type".to_string(),
            data_type: DataType::String,
            description: "Optional resource-type filter — collector adds --resource-type <type>."
                .to_string(),
            example_values: vec!["Microsoft.Storage/storageAccounts".to_string()],
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
            name: "resource_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of resources returned by `az resource list`.".to_string(),
            example_values: vec!["16".to_string()],
            validation_notes: Some(
                "Trivially-true discovery uses `resource_count >= 1` as the admit condition."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "resources".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array — `[{id, name, type, location, \
                          resource_group, provisioning_state, kind?, sku_name?, sku_tier?, \
                          tags?, created_time, changed_time}]`. Use record_checks to assert \
                          on individual records."
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Each element is a single resource. Discovery routing (the engine PR) iterates \
                 this array and emits one asset per element via the asset_callback."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("scope", "scope"),
        ("subscription", "subscription"),
        ("resource_group", "resource_group_filter"),
        ("resource_type", "resource_type_filter"),
    ] {
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
        .optional_data_fields = vec!["resource_count".to_string(), "resources".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("resource_count".to_string(), "resource_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("resources".to_string(), "resources".to_string());

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_resource_list".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(4),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
