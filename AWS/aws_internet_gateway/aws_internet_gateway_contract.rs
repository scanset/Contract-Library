//! AWS Internet Gateway CTN Contract
//!
//! Validates AWS EC2 Internet Gateway configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE igw_attached
//!     found boolean = true
//!     attachment_state string = `available`
//!     attached_vpc_id string = `vpc-0fedcba9876543210`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_internet_gateway_contracts;
//  pub use aws_internet_gateway_contracts::create_aws_internet_gateway_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_internet_gateway CTN type
pub fn create_aws_internet_gateway_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_internet_gateway".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "internet_gateway_id".to_string(),
            data_type: DataType::String,
            description: "Internet Gateway ID for direct lookup".to_string(),
            example_values: vec!["igw-0123456789abcdef0".to_string()],
            validation_notes: Some("Takes precedence over vpc_id lookup".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to find attached Internet Gateway".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Filters by attachment.vpc-id".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in Key=Value format".to_string(),
            example_values: vec!["Name=example-igw".to_string()],
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
            description: "Whether the Internet Gateway was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "internet_gateway_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Internet Gateway ID".to_string(),
            example_values: vec!["igw-0123456789abcdef0".to_string()],
            validation_notes: Some("Validate the resolved IGW ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of the Name tag".to_string(),
            example_values: vec!["example-igw".to_string()],
            validation_notes: Some("Extracted from Tags array".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attached_vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC ID from the first attachment".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("VpcId from Attachments[0]".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attachment_state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Attachment state from the first attachment".to_string(),
            example_values: vec!["available".to_string()],
            validation_notes: Some(
                "State from Attachments[0]; 'available' means attached".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attachment_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of VPC attachments".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some("IGWs can only attach to one VPC at a time".to_string()),
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
                "Field paths use AWS API PascalCase names (e.g., Attachments.0.VpcId)".to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert(
            "internet_gateway_id".to_string(),
            "internet_gateway_id".to_string(),
        );
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
        "internet_gateway_id".to_string(),
        "tag_name".to_string(),
        "attached_vpc_id".to_string(),
        "attachment_state".to_string(),
        "attachment_count".to_string(),
    ];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "internet_gateway_id".to_string(),
            "internet_gateway_id".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("tag_name".to_string(), "tag_name".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("attached_vpc_id".to_string(), "attached_vpc_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "attachment_state".to_string(),
            "attachment_state".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "attachment_count".to_string(),
            "attachment_count".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "resource".to_string());

    // ========================================================================
    // Collection strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_internet_gateway".to_string(),
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
