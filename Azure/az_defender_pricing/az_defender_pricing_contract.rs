//! Azure Defender for Cloud Pricing CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_defender_pricing;
//  pub use az_defender_pricing::create_az_defender_pricing_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_defender_pricing_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_defender_pricing".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Defender plan name".to_string(),
            example_values: vec!["VirtualMachines".to_string(), "KeyVaults".to_string()],
            validation_notes: Some(
                "Passed to az security pricing show --name.".to_string(),
            ),
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

    // strings
    for (name, ops, desc, example) in [
        ("name", str_full.clone(), "Plan name", "VirtualMachines"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../pricings/VirtualMachines"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Security/pricings"),
        ("pricing_tier", str_eq.clone(), "Pricing tier", "Standard"),
        ("sub_plan", str_eq.clone(), "Sub-plan name or none", "P2"),
        ("enablement_time", str_full.clone(), "ISO8601 enablement timestamp", "2026-01-01T00:00:00.000000+00:00"),
        ("free_trial_remaining", str_full.clone(), "Free trial time remaining", "30 days, 0:00:00"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::String,
                allowed_operations: ops,
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    // booleans
    for (name, desc, example) in [
        ("found", "Whether the plan was found", "true"),
        ("is_enabled", "Whether pricing tier is Standard", "true"),
        ("deprecated", "Whether the plan is deprecated", "false"),
        ("has_extensions", "Whether the plan has extensions", "true"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: bool_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    // integers
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "extension_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of extensions on this plan".to_string(),
            example_values: vec!["3".to_string()],
            validation_notes: None,
        });

    // record
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full Defender pricing object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for extension and nested assertions.".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("name", "name"),
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
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "name", "id", "type", "pricing_tier", "sub_plan",
        "enablement_time", "free_trial_remaining",
        "is_enabled", "deprecated", "has_extensions",
        "extension_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "pricing_tier", "sub_plan",
        "enablement_time", "free_trial_remaining",
        "is_enabled", "deprecated", "has_extensions",
        "extension_count",
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
        collector_type: "az_defender_pricing".to_string(),
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
