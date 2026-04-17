//! Azure Application Gateway CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_application_gateway;
//  pub use az_application_gateway::create_az_application_gateway_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_application_gateway_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_application_gateway".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Application Gateway name".to_string(),
            example_values: vec!["appgw-prooflayer-demo".to_string()],
            validation_notes: Some(
                "Passed to az network application-gateway show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the gateway".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
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
        ("name", str_full.clone(), "Application Gateway name", "appgw-prooflayer-demo"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../applicationGateways/appgw-prooflayer-demo"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Network/applicationGateways"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-prooflayer-demo-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("operational_state", str_eq.clone(), "Operational state", "Running"),
        ("sku_name", str_eq.clone(), "SKU name", "Standard_v2"),
        ("sku_tier", str_eq.clone(), "SKU tier", "Standard_v2"),
        ("ssl_policy_type", str_eq.clone(), "SSL policy type", "Predefined"),
        ("ssl_policy_name", str_full.clone(), "SSL policy name", "AppGwSslPolicy20220101"),
        ("ssl_min_protocol_version", str_eq.clone(), "Minimum TLS protocol version", "TLSv1_2"),
        ("waf_mode", str_eq.clone(), "WAF firewall mode (when WAF enabled)", "Prevention"),
        ("waf_rule_set_type", str_eq.clone(), "WAF rule set type", "OWASP"),
        ("waf_rule_set_version", str_eq.clone(), "WAF rule set version", "3.2"),
        ("identity_type", str_eq.clone(), "Managed identity type", "UserAssigned"),
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
        ("found", "Whether the gateway was found", "true", None),
        ("waf_enabled", "Whether WAF is enabled", "false", Some("False when SKU is Standard_v2 (WAF requires WAF_v2 tier) or when WAF config block is absent.")),
        ("http2_enabled", "Whether HTTP/2 is enabled", "false", None),
        ("zone_redundant", "Whether the gateway spans multiple availability zones", "true", Some("True when zones[] has more than one entry.")),
        ("autoscale_enabled", "Whether autoscale is configured", "true", Some("True when autoscaleConfiguration block is present.")),
        ("has_https_listener", "Whether any HTTP listener uses HTTPS protocol", "true", None),
        ("has_http_to_https_redirect", "Whether a redirect configuration exists (Permanent or Found)", "true", None),
        ("has_managed_identity", "Whether a managed identity is attached", "false", None),
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
    for (name, desc, example) in [
        ("sku_capacity", "Fixed SKU capacity (when not using autoscale)", "2"),
        ("autoscale_min_capacity", "Autoscale minimum capacity", "2"),
        ("autoscale_max_capacity", "Autoscale maximum capacity", "10"),
        ("zone_count", "Number of availability zones", "3"),
        ("frontend_ip_count", "Number of frontend IP configurations", "1"),
        ("frontend_port_count", "Number of frontend ports", "2"),
        ("http_listener_count", "Number of HTTP listeners", "2"),
        ("backend_pool_count", "Number of backend address pools", "1"),
        ("backend_http_settings_count", "Number of backend HTTP settings", "1"),
        ("request_routing_rule_count", "Number of request routing rules", "2"),
        ("ssl_certificate_count", "Number of SSL certificates", "1"),
        ("probe_count", "Number of health probes", "1"),
        ("redirect_configuration_count", "Number of redirect configurations", "1"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Int,
                allowed_operations: int_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full Application Gateway object as RecordData".to_string(),
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
        "provisioning_state", "operational_state",
        "sku_name", "sku_tier", "sku_capacity",
        "waf_enabled", "waf_mode", "waf_rule_set_type", "waf_rule_set_version",
        "ssl_policy_type", "ssl_policy_name", "ssl_min_protocol_version",
        "http2_enabled", "zone_count", "zone_redundant",
        "autoscale_enabled", "autoscale_min_capacity", "autoscale_max_capacity",
        "frontend_ip_count", "frontend_port_count", "http_listener_count",
        "backend_pool_count", "backend_http_settings_count",
        "request_routing_rule_count", "ssl_certificate_count",
        "probe_count", "redirect_configuration_count",
        "has_https_listener", "has_http_to_https_redirect",
        "has_managed_identity", "identity_type",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "operational_state",
        "sku_name", "sku_tier", "sku_capacity",
        "waf_enabled", "waf_mode", "waf_rule_set_type", "waf_rule_set_version",
        "ssl_policy_type", "ssl_policy_name", "ssl_min_protocol_version",
        "http2_enabled", "zone_count", "zone_redundant",
        "autoscale_enabled", "autoscale_min_capacity", "autoscale_max_capacity",
        "frontend_ip_count", "frontend_port_count", "http_listener_count",
        "backend_pool_count", "backend_http_settings_count",
        "request_routing_rule_count", "ssl_certificate_count",
        "probe_count", "redirect_configuration_count",
        "has_https_listener", "has_http_to_https_redirect",
        "has_managed_identity", "identity_type",
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
        collector_type: "az_application_gateway".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(8),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
