//! Azure NSG Rule List CTN Contract
//!
//! Wraps `az network nsg rule list -g <rg> --nsg-name <nsg> -o json`.
//! Returns one record per **custom** security rule on the parent NSG.
//! Default rules (AllowVnetInBound, DenyAllInBound, etc.) are not
//! returned by this command — those are surfaced via the parent NSG's
//! `defaultSecurityRules` array (which we don't currently capture
//! separately; if needed, it goes in a future `az_nsg_default_rule_list`).

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_nsg_rule_list_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_nsg_rule_list".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group of the parent NSG.".to_string(),
            example_values: vec!["pltestlz-tenant-b-rg".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "nsg_name".to_string(),
            data_type: DataType::String,
            description: "Parent NSG name.".to_string(),
            example_values: vec!["pltestlz-tenant-b-nsg".to_string()],
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
            name: "rule_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of custom security rules.".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some(
                "Excludes default rules (which `az network nsg rule list` does not return)."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rules".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full projected record array of NSG rules.".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [
        ("resource_group", "resource_group"),
        ("nsg_name", "nsg_name"),
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
        .optional_data_fields = vec!["rule_count".to_string(), "rules".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("rule_count".to_string(), "rule_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("rules".to_string(), "rules".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_nsg_rule_list".to_string(),
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
