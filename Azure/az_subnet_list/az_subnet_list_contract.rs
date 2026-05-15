//! Azure Subnet List CTN Contract
//!
//! Wraps `az network vnet subnet list -g <rg> --vnet-name <vnet> -o json`.
//! Parent-scoped: requires the parent VNet's `resource_group` and
//! `vnet_name` in the OBJECT block. Used by the discovery cascade —
//! after each VNet is discovered via `az_resource_list`, this CTN is
//! dispatched once per VNet to enumerate its subnets.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_subnet_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_subnet_list".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group of the parent VNet.".to_string(),
            example_values: vec!["pltestlz-platform-rg".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "vnet_name".to_string(),
            data_type: DataType::String,
            description: "Parent VNet name.".to_string(),
            example_values: vec!["pltestlz-hub-vnet".to_string()],
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
            name: "subnet_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of subnets returned.".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subnets".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array of subnets.".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [
        ("resource_group", "resource_group"),
        ("vnet_name", "vnet_name"),
        ("subscription", "subscription"),
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
        .optional_data_fields = vec!["subnet_count".to_string(), "subnets".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("subnet_count".to_string(), "subnet_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("subnets".to_string(), "subnets".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_subnet_list".to_string(),
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
