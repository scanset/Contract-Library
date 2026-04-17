//! Azure Network Security Group (NSG) CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_nsg;
//  pub use az_nsg::create_az_nsg_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates an Azure Network Security Group
//! via `az network nsg show --name <name> --resource-group <rg>`. Exposes the
//! full NSG document - rules, default rules, subnet + NIC bindings, tags -
//! as RecordData so policies can assert on per-rule fields like direction,
//! access, protocol, port ranges and source/destination prefixes. Requires
//! only the `Reader` role at subscription, RG, or NSG scope.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE nsg_baseline
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     is_attached boolean = true
//!     has_internet_inbound_allow boolean = false
//!     has_ssh_open_to_internet boolean = false
//!     has_rdp_open_to_internet boolean = false
//!     inbound_allow_count int <= 10
//!     record
//!         field tags.Environment string = `demo`
//!         field tags.FedRAMPImpactLevel string = `moderate`
//!     record_end
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_nsg_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_nsg".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "NSG name".to_string(),
            example_values: vec!["nsg-snet-app-gw".to_string()],
            validation_notes: Some(
                "Passed to az network nsg show --name. Azure does no client-side validation: \
                 malformed names return ResourceNotFound at runtime, same as genuinely missing \
                 NSGs."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the NSG".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Required by az network nsg show. NSG names are only unique within an RG."
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
        ("name", str_full.clone(), "NSG name", "nsg-snet-app-gw"),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../networkSecurityGroups/nsg-snet-app-gw",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type (always Microsoft.Network/networkSecurityGroups)",
            "Microsoft.Network/networkSecurityGroups",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the NSG",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "resource_guid",
            str_eq.clone(),
            "Resource GUID assigned by Azure",
            "77777777-7777-7777-7777-777777777777",
        ),
        (
            "etag",
            str_eq.clone(),
            "Opaque etag (changes on every NSG update)",
            "W/\"5d6a71c2-...\"",
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
        ("found", "Whether the NSG was found", "true", None),
        (
            "has_subnet_bindings",
            "Derived: true when subnets[] has at least one entry",
            "true",
            Some("False means the NSG is orphaned / unattached to any subnet."),
        ),
        (
            "has_nic_bindings",
            "Derived: true when networkInterfaces[] has at least one entry",
            "false",
            Some(
                "Azure omits the networkInterfaces field entirely when there are no NIC \
                 bindings; collector coalesces to 0.",
            ),
        ),
        (
            "is_attached",
            "Derived: true when subnet_binding_count + nic_binding_count > 0",
            "true",
            Some("Composite of has_subnet_bindings and has_nic_bindings."),
        ),
        (
            "has_custom_rules",
            "Derived: true when securityRules[] has at least one entry",
            "true",
            Some("Azure's 6 default rules always exist; this only reflects operator-added rules."),
        ),
        (
            "has_internet_inbound_allow",
            "Derived: any Inbound Allow rule with source prefix in {Internet, *, 0.0.0.0/0}",
            "false",
            Some(
                "Scans both the singular sourceAddressPrefix and the plural sourceAddressPrefixes \
                 array. Covers custom rules only - Azure defaults always include \
                 AllowInternetOutBound but never an inbound internet allow.",
            ),
        ),
        (
            "has_ssh_open_to_internet",
            "Derived: any Inbound Allow rule exposing port 22 from Internet/*/0.0.0.0/0",
            "false",
            Some(
                "Checks destination port ranges for port 22 (single port, range containing 22, \
                 or wildcard *). Covers custom rules only.",
            ),
        ),
        (
            "has_rdp_open_to_internet",
            "Derived: any Inbound Allow rule exposing port 3389 from Internet/*/0.0.0.0/0",
            "false",
            Some(
                "Checks destination port ranges for port 3389 (single port, range containing \
                 3389, or wildcard *). Covers custom rules only.",
            ),
        ),
        (
            "has_all_ports_open_to_internet",
            "Derived: any Inbound Allow rule with destination port * from Internet/*/0.0.0.0/0",
            "false",
            Some("Only matches explicit wildcard (*) destination port, not large ranges."),
        ),
        (
            "flow_log_enabled",
            "Whether an NSG flow log is configured and enabled (behavior-gated)",
            "true",
            Some("Requires behavior include_flow_log_status true on the OBJECT."),
        ),
        (
            "flow_log_retention_enabled",
            "Whether flow log retention policy is enabled (behavior-gated)",
            "true",
            Some("Requires behavior include_flow_log_status true on the OBJECT."),
        ),
        (
            "flow_log_traffic_analytics_enabled",
            "Whether Traffic Analytics is enabled on the flow log (behavior-gated)",
            "false",
            Some("Requires behavior include_flow_log_status true on the OBJECT."),
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

    // integers - derived counts
    for (name, desc, example, notes) in [
        (
            "security_rule_count",
            "Number of operator-authored custom rules in securityRules[]",
            "4",
            None,
        ),
        (
            "default_security_rule_count",
            "Number of Azure built-in rules in defaultSecurityRules[] (always 6)",
            "6",
            Some(
                "Always 6: AllowVnetInBound, AllowAzureLoadBalancerInBound, DenyAllInBound, \
                 AllowVnetOutBound, AllowInternetOutBound, DenyAllOutBound.",
            ),
        ),
        (
            "subnet_binding_count",
            "Number of subnets bound to this NSG",
            "1",
            None,
        ),
        (
            "nic_binding_count",
            "Number of NICs bound to this NSG (0 when field absent)",
            "0",
            None,
        ),
        (
            "inbound_allow_count",
            "Custom rules with direction=Inbound and access=Allow",
            "3",
            None,
        ),
        (
            "inbound_deny_count",
            "Custom rules with direction=Inbound and access=Deny",
            "0",
            None,
        ),
        (
            "outbound_allow_count",
            "Custom rules with direction=Outbound and access=Allow",
            "0",
            None,
        ),
        (
            "outbound_deny_count",
            "Custom rules with direction=Outbound and access=Deny",
            "0",
            None,
        ),
        (
            "total_rule_count",
            "Total rules: security_rule_count + default_security_rule_count",
            "10",
            None,
        ),
        (
            "flow_log_retention_days",
            "Flow log retention period in days (behavior-gated)",
            "90",
            Some("Requires behavior include_flow_log_status true on the OBJECT."),
        ),
        (
            "flow_log_analytics_interval_minutes",
            "Traffic Analytics processing interval in minutes (behavior-gated)",
            "10",
            Some("Requires behavior include_flow_log_status true. Typically 10 or 60."),
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
            description: "Full NSG object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and per-rule assertions: \
                 `field tags.Environment string = \\`demo\\`` or \
                 `field securityRules[?name==\\`AllowHTTPS\\`].access string = \\`Allow\\`` or \
                 `field defaultSecurityRules[?name==\\`DenyAllInBound\\`].priority int = 65500`."
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
        "resource_guid".to_string(),
        "etag".to_string(),
        "has_subnet_bindings".to_string(),
        "has_nic_bindings".to_string(),
        "is_attached".to_string(),
        "has_custom_rules".to_string(),
        "has_internet_inbound_allow".to_string(),
        "security_rule_count".to_string(),
        "default_security_rule_count".to_string(),
        "subnet_binding_count".to_string(),
        "nic_binding_count".to_string(),
        "inbound_allow_count".to_string(),
        "inbound_deny_count".to_string(),
        "outbound_allow_count".to_string(),
        "outbound_deny_count".to_string(),
        "has_ssh_open_to_internet".to_string(),
        "has_rdp_open_to_internet".to_string(),
        "has_all_ports_open_to_internet".to_string(),
        "total_rule_count".to_string(),
        "flow_log_enabled".to_string(),
        "flow_log_retention_enabled".to_string(),
        "flow_log_retention_days".to_string(),
        "flow_log_traffic_analytics_enabled".to_string(),
        "flow_log_analytics_interval_minutes".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "location",
        "resource_group",
        "provisioning_state",
        "resource_guid",
        "etag",
        "has_subnet_bindings",
        "has_nic_bindings",
        "is_attached",
        "has_custom_rules",
        "has_internet_inbound_allow",
        "security_rule_count",
        "default_security_rule_count",
        "subnet_binding_count",
        "nic_binding_count",
        "inbound_allow_count",
        "inbound_deny_count",
        "outbound_allow_count",
        "outbound_deny_count",
        "has_ssh_open_to_internet",
        "has_rdp_open_to_internet",
        "has_all_ports_open_to_internet",
        "total_rule_count",
        "flow_log_enabled",
        "flow_log_retention_enabled",
        "flow_log_retention_days",
        "flow_log_traffic_analytics_enabled",
        "flow_log_analytics_interval_minutes",
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
        collector_type: "az_nsg".to_string(),
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
