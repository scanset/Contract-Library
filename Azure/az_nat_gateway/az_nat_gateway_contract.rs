//! Azure NAT Gateway CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_nat_gateway;
//  pub use az_nat_gateway::create_az_nat_gateway_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_nat_gateway_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_nat_gateway".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "NAT gateway name".to_string(),
            example_values: vec!["natgw-example-prod".to_string()],
            validation_notes: Some(
                "Passed to az network nat gateway show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the NAT gateway".to_string(),
            example_values: vec!["rg-example-eastus".to_string()],
            validation_notes: None,
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
        ("name", str_full.clone(), "NAT gateway name", "natgw-example-prod"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../natGateways/natgw-example-prod"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Network/natGateways"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("sku_name", str_eq.clone(), "SKU name (always Standard)", "Standard"),
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
    for (name, desc, example, notes) in [
        ("found", "Whether the NAT gateway was found", "true", None),
        (
            "zone_redundant",
            "Whether the NAT gateway spans multiple zones",
            "false",
            Some("Derived: true when zones array length > 1."),
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: bool_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    // integers
    for (name, desc, example, notes) in [
        (
            "idle_timeout_minutes",
            "Idle timeout in minutes",
            "10",
            Some("Default 4. Range 4-120."),
        ),
        ("public_ip_count", "Number of attached public IPs", "1", None),
        ("public_ip_prefix_count", "Number of attached public IP prefixes", "0", None),
        ("subnet_count", "Number of associated subnets", "1", None),
        ("zone_count", "Number of availability zones", "1", None),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Int,
                allowed_operations: int_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full NAT Gateway object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and nested assertions.".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("name", "name"),
        ("resource_group", "resource_group"),
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
        "name", "id", "type", "location", "resource_group",
        "provisioning_state", "sku_name",
        "zone_redundant",
        "idle_timeout_minutes", "public_ip_count",
        "public_ip_prefix_count", "subnet_count", "zone_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "sku_name",
        "zone_redundant",
        "idle_timeout_minutes", "public_ip_count",
        "public_ip_prefix_count", "subnet_count", "zone_count",
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
        collector_type: "az_nat_gateway".to_string(),
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
