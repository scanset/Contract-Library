//! Azure Bastion Host CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_bastion_host;
//  pub use az_bastion_host::create_az_bastion_host_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_bastion_host_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_bastion_host".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Bastion host name".to_string(),
            example_values: vec!["bas-example-prod".to_string()],
            validation_notes: Some(
                "Passed to az network bastion show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the bastion".to_string(),
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
        ("name", str_full.clone(), "Bastion host name", "bas-example-prod"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../bastionHosts/bas-example-prod"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Network/bastionHosts"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("dns_name", str_full.clone(), "Bastion DNS name", "bst-00000000-0000-0000-0000-000000000000.bastion.azure.com"),
        ("sku_name", str_eq.clone(), "SKU name (Basic or Standard)", "Standard"),
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
        ("found", "Whether the bastion host was found", "true", None),
        (
            "enable_file_copy",
            "Whether file copy (upload/download) is enabled",
            "true",
            Some("Requires Standard SKU. Absent/false on Basic SKU."),
        ),
        (
            "enable_ip_connect",
            "Whether IP-based connect is enabled",
            "true",
            Some("Requires Standard SKU. Allows connecting by IP address."),
        ),
        (
            "enable_tunneling",
            "Whether native client tunneling is enabled",
            "true",
            Some("Requires Standard SKU. Enables az network bastion tunnel."),
        ),
        (
            "enable_shareable_link",
            "Whether shareable link feature is enabled",
            "false",
            Some("Defaults false when absent from response."),
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
            "scale_units",
            "Number of scale units (each = 25 concurrent sessions)",
            "2",
            Some("Standard SKU: 2-50. Basic SKU: always 2."),
        ),
        (
            "ip_configuration_count",
            "Number of IP configurations",
            "1",
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
            description: "Full Bastion Host object as RecordData".to_string(),
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
        "provisioning_state", "dns_name", "sku_name",
        "enable_file_copy", "enable_ip_connect", "enable_tunneling",
        "enable_shareable_link", "scale_units", "ip_configuration_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "dns_name", "sku_name",
        "enable_file_copy", "enable_ip_connect", "enable_tunneling",
        "enable_shareable_link", "scale_units", "ip_configuration_count",
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
        collector_type: "az_bastion_host".to_string(),
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
