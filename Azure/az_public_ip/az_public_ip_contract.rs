//! Azure Public IP Address CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_public_ip;
//  pub use az_public_ip::create_az_public_ip_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_public_ip_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_public_ip".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Public IP address resource name".to_string(),
            example_values: vec!["pip-example-prod".to_string()],
            validation_notes: Some(
                "Passed to az network public-ip show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the public IP".to_string(),
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
        ("name", str_full.clone(), "Public IP resource name", "pip-example-prod"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../publicIPAddresses/pip-example-prod"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Network/publicIPAddresses"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("ip_address", str_full.clone(), "Assigned IP address", "10.0.0.1"),
        ("allocation_method", str_eq.clone(), "Allocation method (Static or Dynamic)", "Static"),
        ("ip_version", str_eq.clone(), "IP version (IPv4 or IPv6)", "IPv4"),
        ("sku_name", str_eq.clone(), "SKU name (Basic or Standard)", "Standard"),
        ("sku_tier", str_eq.clone(), "SKU tier (Regional or Global)", "Regional"),
        ("ddos_protection_mode", str_eq.clone(), "DDoS protection mode", "VirtualNetworkInherited"),
        ("dns_fqdn", str_full.clone(), "DNS fully qualified domain name", "example.eastus.cloudapp.azure.com"),
        ("dns_domain_label", str_full.clone(), "DNS domain name label", "example"),
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
        ("found", "Whether the public IP was found", "true", None),
        (
            "zone_redundant",
            "Whether the IP is deployed across multiple zones",
            "true",
            Some("Derived: true when zones array length > 1."),
        ),
        (
            "is_associated",
            "Whether the IP is attached to a resource",
            "true",
            Some("True when ipConfiguration or natGateway is present."),
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
            "4",
            Some("Default is 4. Range 4-30."),
        ),
        (
            "zone_count",
            "Number of availability zones",
            "3",
            None,
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
            description: "Full Public IP object as RecordData".to_string(),
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
        "provisioning_state", "ip_address", "allocation_method",
        "ip_version", "sku_name", "sku_tier", "ddos_protection_mode",
        "dns_fqdn", "dns_domain_label",
        "zone_redundant", "is_associated",
        "idle_timeout_minutes", "zone_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "ip_address", "allocation_method",
        "ip_version", "sku_name", "sku_tier", "ddos_protection_mode",
        "dns_fqdn", "dns_domain_label",
        "zone_redundant", "is_associated",
        "idle_timeout_minutes", "zone_count",
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
        collector_type: "az_public_ip".to_string(),
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
