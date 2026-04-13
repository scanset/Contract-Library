//! AWS Route Table CTN Contract
//!
//! Validates AWS EC2 route table configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData
//! for detailed route and association inspection using record checks.
//!
//! ## Design
//!
//! Follows the hybrid pattern established by `aws_security_group`:
//! - Scalar fields (`found`, `route_table_id`, `has_igw_route`, etc.) for quick checks
//! - RecordData (`record` → `resource`) for deep inspection of Routes and Associations
//!
//! Record check field paths use **AWS API PascalCase names** exactly as returned by
//! `aws ec2 describe-route-tables`.
//!
//! ## Lookup Modes
//!
//! - By `route_table_id`: Direct lookup of a specific route table
//! - By `tags` + `vpc_id`: Filter-based lookup (e.g., Name=example-private-rt)
//! - By `vpc_id` alone: Returns first matching RT (use with caution)
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE private_rt_check
//!     found boolean = true
//!     has_igw_route boolean = false
//!     has_nat_route boolean = true
//!     record
//!         field Routes.*.DestinationCidrBlock string = `0.0.0.0/0` at_least_one
//!         field Routes.*.NatGatewayId string starts `nat-` at_least_one
//!     record_end
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_route_table_contracts;
//  pub use aws_route_table_contracts::create_aws_route_table_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_route_table CTN type
pub fn create_aws_route_table_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_route_table".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "route_table_id".to_string(),
            data_type: DataType::String,
            description: "Route table ID for direct lookup".to_string(),
            example_values: vec!["rtb-0fedcba9876543210".to_string()],
            validation_notes: Some(
                "Takes precedence over tag-based lookup if specified".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to scope the route table lookup".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Used as filter; recommended with tags".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in Key=Value format".to_string(),
            example_values: vec![
                "Name=example-private-rt".to_string(),
                "Name=example-public-rt".to_string(),
            ],
            validation_notes: Some("Used with vpc_id for precise lookup".to_string()),
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

    // Scalar fields
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the route table was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "route_table_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Route table ID".to_string(),
            example_values: vec!["rtb-0fedcba9876543210".to_string()],
            validation_notes: Some("Validate the resolved route table ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the route table belongs to".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Validate VPC association".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of the Name tag".to_string(),
            example_values: vec![
                "example-private-rt".to_string(),
                "example-public-rt".to_string(),
            ],
            validation_notes: Some("Extracted from Tags array".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_main".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether this is the main (default) route table for the VPC".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("True if any association has Main=true".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "route_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of routes in the route table".to_string(),
            example_values: vec!["2".to_string()],
            validation_notes: Some("Includes the local route".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "association_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of subnet associations".to_string(),
            example_values: vec!["2".to_string()],
            validation_notes: Some("Count of associated subnets".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_igw_route".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any route targets an Internet Gateway (igw-*)".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("True if any route's GatewayId starts with 'igw-'".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_nat_route".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any route targets a NAT Gateway".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("True if any route has a NatGatewayId".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_internet_route".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a 0.0.0.0/0 route exists via IGW or NAT".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "True if 0.0.0.0/0 destination with GatewayId or NatGatewayId".to_string(),
            ),
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
                "Field paths use AWS API PascalCase names (e.g., Routes.0.GatewayId)".to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    // Object → Collection
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("route_table_id".to_string(), "route_table_id".to_string());
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

    // Required data fields
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    // Optional data fields
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "route_table_id".to_string(),
        "vpc_id".to_string(),
        "tag_name".to_string(),
        "is_main".to_string(),
        "route_count".to_string(),
        "association_count".to_string(),
        "has_igw_route".to_string(),
        "has_nat_route".to_string(),
        "has_internet_route".to_string(),
    ];

    // State → Data validation mappings
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("route_table_id".to_string(), "route_table_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("vpc_id".to_string(), "vpc_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("tag_name".to_string(), "tag_name".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_main".to_string(), "is_main".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("route_count".to_string(), "route_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "association_count".to_string(),
            "association_count".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("has_igw_route".to_string(), "has_igw_route".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("has_nat_route".to_string(), "has_nat_route".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "has_internet_route".to_string(),
            "has_internet_route".to_string(),
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
        collector_type: "aws_route_table".to_string(),
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
