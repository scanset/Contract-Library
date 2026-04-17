//! Azure Load Balancer CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_load_balancer;
//  pub use az_load_balancer::create_az_load_balancer_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_load_balancer_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_load_balancer".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Load balancer name".to_string(),
            example_values: vec!["lb-example-prod".to_string()],
            validation_notes: Some(
                "Passed to az network lb show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the load balancer".to_string(),
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
        ("name", str_full.clone(), "Load balancer name", "lb-example-prod"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../loadBalancers/lb-example-prod"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Network/loadBalancers"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("sku_name", str_eq.clone(), "SKU name (Basic, Standard, or Gateway)", "Standard"),
        ("sku_tier", str_eq.clone(), "SKU tier (Regional or Global)", "Regional"),
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
        ("found", "Whether the load balancer was found", "true", None),
        (
            "has_public_frontend",
            "Whether any frontend has a public IP attached",
            "true",
            Some("Derived: true when any frontendIPConfigurations entry has publicIPAddress."),
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
        ("frontend_ip_count", "Number of frontend IP configurations", "1", None),
        ("backend_pool_count", "Number of backend address pools", "1", None),
        ("load_balancing_rule_count", "Number of load balancing rules", "2", None),
        ("probe_count", "Number of health probes", "2", None),
        ("inbound_nat_rule_count", "Number of inbound NAT rules", "0", None),
        ("outbound_rule_count", "Number of outbound rules", "0", None),
        (
            "inbound_nat_pool_count",
            "Number of inbound NAT pools",
            "0",
            Some("Legacy feature for VMSS. Typically 0."),
        ),
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
            description: "Full Load Balancer object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag, rule, and probe assertions.".to_string(),
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
        "provisioning_state", "sku_name", "sku_tier",
        "has_public_frontend",
        "frontend_ip_count", "backend_pool_count",
        "load_balancing_rule_count", "probe_count",
        "inbound_nat_rule_count", "outbound_rule_count",
        "inbound_nat_pool_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "sku_name", "sku_tier",
        "has_public_frontend",
        "frontend_ip_count", "backend_pool_count",
        "load_balancing_rule_count", "probe_count",
        "inbound_nat_rule_count", "outbound_rule_count",
        "inbound_nat_pool_count",
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
        collector_type: "az_load_balancer".to_string(),
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
