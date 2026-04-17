//! Azure Virtual Network (VNet) CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_virtual_network;
//  pub use az_virtual_network::create_az_virtual_network_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates an Azure Virtual Network
//! via `az network vnet show --name <name> --resource-group <rg>`. Exposes
//! address space, subnet inventory with NSG/route-table analysis, peering
//! status, DDoS protection, DNS config, encryption, and flow log presence.
//! Full VNet document available as RecordData for tag and per-subnet
//! record_checks. Requires only the `Reader` role.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE vnet_baseline
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     has_subnets boolean = true
//!     all_subnets_have_nsg boolean = true
//!     ddos_protection_enabled boolean = true
//!     has_flow_logs boolean = true
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_virtual_network_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_virtual_network".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "VNet name".to_string(),
            example_values: vec!["vnet-prooflayer-demo".to_string()],
            validation_notes: Some(
                "Passed to az network vnet show --name. Azure does no client-side validation."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the VNet".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Required by az network vnet show. VNet names are unique within an RG."
                    .to_string(),
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

    // scalar strings
    for (name, ops, desc, example) in [
        ("name", str_full.clone(), "VNet name", "vnet-prooflayer-demo"),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../virtualNetworks/vnet-prooflayer-demo",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type (always Microsoft.Network/virtualNetworks)",
            "Microsoft.Network/virtualNetworks",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the VNet",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "etag",
            str_eq.clone(),
            "Opaque etag (changes on every VNet update)",
            "W/\"abc123\"",
        ),
        (
            "address_prefix",
            str_full.clone(),
            "First address prefix from addressSpace.addressPrefixes[]",
            "10.0.0.0/16",
        ),
        (
            "private_endpoint_vnet_policies",
            str_eq.clone(),
            "Private endpoint VNet policy enforcement",
            "Disabled",
        ),
        (
            "encryption_enforcement",
            str_eq.clone(),
            "VNet encryption enforcement level (when encryption is present)",
            "AllowUnencrypted",
        ),
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
        ("found", "Whether the VNet was found", "true", None),
        (
            "has_subnets",
            "Derived: true when subnets[] has at least one entry",
            "true",
            None,
        ),
        (
            "all_subnets_have_nsg",
            "Derived: true when every subnet has an NSG attached",
            "false",
            Some(
                "False when any subnet has networkSecurityGroup==null or absent. Note: \
                 AzureBastionSubnet intentionally has no NSG per Azure requirement.",
            ),
        ),
        (
            "has_custom_dns",
            "Derived: true when dhcpOptions.dnsServers[] is non-empty",
            "false",
            Some("False means the VNet uses Azure-provided DNS."),
        ),
        (
            "ddos_protection_enabled",
            "Whether DDoS Protection Standard plan is enabled",
            "false",
            Some("False means only Azure DDoS Protection Basic (free tier)."),
        ),
        (
            "has_peerings",
            "Derived: true when virtualNetworkPeerings[] is non-empty",
            "false",
            None,
        ),
        (
            "has_flow_logs",
            "Derived: true when flowLogs[] is non-empty",
            "true",
            Some("Flow log references are inline in the VNet response; details require separate API."),
        ),
        (
            "encryption_enabled",
            "Whether VNet encryption is enabled",
            "false",
            Some("Absent on older VNets; collector only sets this when the encryption object exists."),
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
            "subnet_count",
            "Number of subnets in the VNet",
            "4",
            None,
        ),
        (
            "subnets_without_nsg_count",
            "Number of subnets with no NSG attached",
            "1",
            Some("Includes Azure-managed subnets like AzureBastionSubnet."),
        ),
        (
            "subnets_with_route_table_count",
            "Number of subnets with a route table attached",
            "0",
            None,
        ),
        (
            "subnets_with_service_endpoints_count",
            "Number of subnets with service endpoints configured",
            "0",
            None,
        ),
        (
            "subnets_with_delegations_count",
            "Number of subnets with delegations",
            "0",
            None,
        ),
        (
            "peering_count",
            "Number of VNet peerings",
            "0",
            None,
        ),
        (
            "address_prefix_count",
            "Number of address prefixes in addressSpace",
            "1",
            None,
        ),
        (
            "dns_server_count",
            "Number of custom DNS servers configured",
            "0",
            None,
        ),
        (
            "flow_log_count",
            "Number of flow log references attached to this VNet",
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
            description: "Full VNet object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and per-subnet assertions: \
                 `field tags.Environment string = \\`demo\\`` or \
                 `field subnets[0].name string = \\`snet-app-gw\\``."
                    .to_string(),
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
        "name".to_string(),
        "id".to_string(),
        "type".to_string(),
        "location".to_string(),
        "resource_group".to_string(),
        "provisioning_state".to_string(),
        "etag".to_string(),
        "address_prefix".to_string(),
        "address_prefix_count".to_string(),
        "private_endpoint_vnet_policies".to_string(),
        "subnet_count".to_string(),
        "has_subnets".to_string(),
        "subnets_without_nsg_count".to_string(),
        "all_subnets_have_nsg".to_string(),
        "subnets_with_route_table_count".to_string(),
        "subnets_with_service_endpoints_count".to_string(),
        "subnets_with_delegations_count".to_string(),
        "peering_count".to_string(),
        "has_peerings".to_string(),
        "dns_server_count".to_string(),
        "has_custom_dns".to_string(),
        "ddos_protection_enabled".to_string(),
        "flow_log_count".to_string(),
        "has_flow_logs".to_string(),
        "encryption_enabled".to_string(),
        "encryption_enforcement".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "location",
        "resource_group",
        "provisioning_state",
        "etag",
        "address_prefix",
        "address_prefix_count",
        "private_endpoint_vnet_policies",
        "subnet_count",
        "has_subnets",
        "subnets_without_nsg_count",
        "all_subnets_have_nsg",
        "subnets_with_route_table_count",
        "subnets_with_service_endpoints_count",
        "subnets_with_delegations_count",
        "peering_count",
        "has_peerings",
        "dns_server_count",
        "has_custom_dns",
        "ddos_protection_enabled",
        "flow_log_count",
        "has_flow_logs",
        "encryption_enabled",
        "encryption_enforcement",
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
        collector_type: "az_virtual_network".to_string(),
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
