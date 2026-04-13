//! AWS NAT Gateway CTN Contract
//!
//! Validates AWS EC2 NAT Gateway configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE nat_in_public_subnet
//!     found boolean = true
//!     state string = `available`
//!     subnet_id string = `subnet-0dddddddddddddddd`
//!     connectivity_type string = `public`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_nat_gateway_contracts;
//  pub use aws_nat_gateway_contracts::create_aws_nat_gateway_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_nat_gateway CTN type
pub fn create_aws_nat_gateway_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_nat_gateway".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "nat_gateway_id".to_string(),
            data_type: DataType::String,
            description: "NAT Gateway ID for direct lookup".to_string(),
            example_values: vec!["nat-0123456789abcdef0".to_string()],
            validation_notes: Some("Takes precedence over filter-based lookup".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to find NAT Gateways".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Filters by vpc-id".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in Key=Value format".to_string(),
            example_values: vec!["Name=example-nat".to_string()],
            validation_notes: Some("Used for tag-based lookup".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some("Uses AWS CLI default if not specified".to_string()),
        });

    // ========================================================================
    // State requirements (validation fields)
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the NAT Gateway was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "nat_gateway_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "NAT Gateway ID".to_string(),
            example_values: vec!["nat-0123456789abcdef0".to_string()],
            validation_notes: Some("Validate the resolved NAT Gateway ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of the Name tag".to_string(),
            example_values: vec!["example-nat".to_string()],
            validation_notes: Some("Extracted from Tags array".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "NAT Gateway state".to_string(),
            example_values: vec![
                "available".to_string(),
                "pending".to_string(),
                "failed".to_string(),
                "deleted".to_string(),
            ],
            validation_notes: Some("'available' means operational".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the NAT Gateway belongs to".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Validate VPC association".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subnet_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Subnet the NAT Gateway is placed in".to_string(),
            example_values: vec!["subnet-0dddddddddddddddd".to_string()],
            validation_notes: Some("Must be a public subnet for public NAT Gateway".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "connectivity_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Connectivity type of the NAT Gateway".to_string(),
            example_values: vec!["public".to_string(), "private".to_string()],
            validation_notes: Some(
                "'public' provides internet access; 'private' for VPC-to-VPC".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "public_ip".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Public (Elastic) IP address from the primary address".to_string(),
            example_values: vec!["203.0.113.42".to_string()],
            validation_notes: Some(
                "PublicIp from NatGatewayAddresses[0]; only present for public NAT".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "private_ip".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Private IP address from the primary address".to_string(),
            example_values: vec!["10.0.0.100".to_string()],
            validation_notes: Some("PrivateIp from NatGatewayAddresses[0]".to_string()),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData for record check validation".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Field paths use AWS API PascalCase names (e.g., NatGatewayAddresses.0.PublicIp)"
                    .to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("nat_gateway_id".to_string(), "nat_gateway_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("vpc_id".to_string(), "vpc_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("tags".to_string(), "tags".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("region".to_string(), "region".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "nat_gateway_id".to_string(),
        "tag_name".to_string(),
        "state".to_string(),
        "vpc_id".to_string(),
        "subnet_id".to_string(),
        "connectivity_type".to_string(),
        "public_ip".to_string(),
        "private_ip".to_string(),
    ];

    for field in &[
        "found",
        "nat_gateway_id",
        "tag_name",
        "state",
        "vpc_id",
        "subnet_id",
        "connectivity_type",
        "public_ip",
        "private_ip",
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
        collector_type: "aws_nat_gateway".to_string(),
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
