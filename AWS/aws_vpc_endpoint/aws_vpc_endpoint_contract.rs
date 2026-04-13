//! AWS VPC Endpoint CTN Contract
//!
//! Validates VPC endpoint configuration via a single AWS CLI call:
//! describe-vpc-endpoints with either --vpc-endpoint-ids or --filters
//!
//! Supports both Interface and Gateway endpoint types.
//! Key derived scalars:
//!   subnet_count       → length of SubnetIds array
//!   route_table_count  → length of RouteTableIds array (Gateway endpoints)
//!   security_group_id  → Groups[0].GroupId (Interface endpoints)
//!
//! PolicyDocument is a JSON-encoded string — parsed and stored under
//! PolicyDocument key in RecordData for deep inspection.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_vpc_endpoint;
//  pub use aws_vpc_endpoint::create_aws_vpc_endpoint_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_vpc_endpoint_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_vpc_endpoint".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
        name: "endpoint_id".to_string(),
        data_type: DataType::String,
        description: "VPC endpoint ID for direct lookup".to_string(),
        example_values: vec!["vpce-0aaaaaaaaaaaaaaa0".to_string()],
        validation_notes: Some(
            "Use endpoint_id for direct lookup, or service_name + vpc_id for service-based lookup"
                .to_string(),
        ),
    });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "service_name".to_string(),
            data_type: DataType::String,
            description: "AWS service name filter (exact or partial match)".to_string(),
            example_values: vec![
                "com.amazonaws.us-east-1.ssm".to_string(),
                "com.amazonaws.us-east-1.s3".to_string(),
            ],
            validation_notes: Some(
                "Used as --filters Name=service-name,Values=<service_name>".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to scope the endpoint lookup".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: Some("Used as --filters Name=vpc-id,Values=<vpc_id>".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // State requirements
    // ========================================================================

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
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the endpoint was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_endpoint_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "VPC endpoint ID".to_string(),
            example_values: vec!["vpce-0aaaaaaaaaaaaaaa0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_endpoint_type".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Endpoint type: Interface or Gateway".to_string(),
            example_values: vec!["Interface".to_string(), "Gateway".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "service_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Full AWS service name".to_string(),
            example_values: vec!["com.amazonaws.us-east-1.ssm".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Endpoint state".to_string(),
            example_values: vec!["available".to_string(), "pending".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "VPC the endpoint belongs to".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "private_dns_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether private DNS is enabled (Interface endpoints only)".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Always false for Gateway endpoints. Interface endpoints should have this true."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subnet_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of subnets the endpoint is deployed in (Interface endpoints)"
                .to_string(),
            example_values: vec!["2".to_string()],
            validation_notes: Some("Always 0 for Gateway endpoints".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "route_table_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of route tables associated (Gateway endpoints)".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some("Always 0 for Interface endpoints".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "security_group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "First security group ID attached to the endpoint (Interface endpoints)"
                .to_string(),
            example_values: vec!["sg-0aaaaaaaaaaaaaaa0".to_string()],
            validation_notes: Some("Empty for Gateway endpoints".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full endpoint object as RecordData including parsed PolicyDocument"
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "PolicyDocument is parsed from JSON string and stored under PolicyDocument key"
                    .to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    for field in &["endpoint_id", "service_name", "vpc_id", "region"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "vpc_endpoint_id".to_string(),
        "vpc_endpoint_type".to_string(),
        "service_name".to_string(),
        "state".to_string(),
        "vpc_id".to_string(),
        "private_dns_enabled".to_string(),
        "subnet_count".to_string(),
        "route_table_count".to_string(),
        "security_group_id".to_string(),
    ];

    for field in &[
        "found",
        "vpc_endpoint_id",
        "vpc_endpoint_type",
        "service_name",
        "state",
        "vpc_id",
        "private_dns_enabled",
        "subnet_count",
        "route_table_count",
        "security_group_id",
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

    // ========================================================================
    // Collection strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_vpc_endpoint".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "ec2_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
