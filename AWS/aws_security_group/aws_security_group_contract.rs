//! AWS Security Group CTN Contract
//!
//! Validates AWS EC2 security group configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData
//! for detailed rule inspection using record checks.
//!
//! ## Design
//!
//! Follows the hybrid pattern established by `k8s_resource`:
//! - Scalar fields (`found`, `group_id`, `group_name`, etc.) for quick identity checks
//! - RecordData (`record` → `resource`) for deep inspection of `IpPermissions` rules
//!
//! Record check field paths use **AWS API PascalCase names** exactly as returned by
//! `aws ec2 describe-security-groups`, so policy authors can reference CLI output directly.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE rds_sg_check
//!     found boolean = true
//!     group_name string = `example-rds`
//!     record
//!         field IpPermissions.0.IpProtocol string = `tcp`
//!         field IpPermissions.0.FromPort int = 5432
//!         field IpPermissions.0.ToPort int = 5432
//!         field IpPermissions.0.UserIdGroupPairs.*.GroupId string = `sg-0cccccccccccccccc0` at_least_one
//!         field IpPermissionsEgress.*.IpRanges.*.CidrIp string != `0.0.0.0/0` all
//!     record_end
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_security_group_contracts;
//  pub use aws_security_group_contracts::create_aws_security_group_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_security_group CTN type
///
/// Queries AWS EC2 API for security group configuration and returns both
/// scalar summary fields and full API response as RecordData.
pub fn create_aws_security_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_security_group".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "group_id".to_string(),
            data_type: DataType::String,
            description: "Security group ID for direct lookup".to_string(),
            example_values: vec!["sg-0bbbbbbbbbbbbbbbb0".to_string()],
            validation_notes: Some(
                "Takes precedence over group_name if both specified".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "group_name".to_string(),
            data_type: DataType::String,
            description: "Security group name for filter-based lookup".to_string(),
            example_values: vec!["example-rds".to_string()],
            validation_notes: Some("Used as Name filter if group_id not specified".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to scope the security group lookup".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Optional additional filter".to_string()),
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

    // Scalar fields for quick checks
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the security group was found".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Security group ID".to_string(),
            example_values: vec!["sg-0bbbbbbbbbbbbbbbb0".to_string()],
            validation_notes: Some("Validate the resolved security group ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "group_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Security group name".to_string(),
            example_values: vec!["example-rds".to_string()],
            validation_notes: Some("Validate the security group name".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the security group belongs to".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Validate VPC association".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Security group description".to_string(),
            example_values: vec!["Allow PostgreSQL access from EKS nodes".to_string()],
            validation_notes: Some("Validate SG description".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ingress_rule_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of ingress rules (IpPermissions entries)".to_string(),
            example_values: vec!["1".to_string(), "2".to_string()],
            validation_notes: Some("Validates rule count shape".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "egress_rule_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of egress rules (IpPermissionsEgress entries)".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some("Validates rule count shape".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_ingress_from_anywhere".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any ingress rule allows 0.0.0.0/0 or ::/0".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("Quick check for open ingress".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_egress_to_anywhere".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any egress rule allows 0.0.0.0/0 or ::/0".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Quick check for open egress".to_string()),
        });

    // RecordData field for deep rule inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData for record check validation".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Field paths use AWS API PascalCase names (e.g., IpPermissions.0.FromPort)"
                    .to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    // Object → Collection mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("group_id".to_string(), "group_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("group_name".to_string(), "group_name".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("vpc_id".to_string(), "vpc_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("region".to_string(), "region".to_string());

    // Required data fields from collection
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    // Optional data fields
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "group_id".to_string(),
        "group_name".to_string(),
        "vpc_id".to_string(),
        "description".to_string(),
        "ingress_rule_count".to_string(),
        "egress_rule_count".to_string(),
        "has_ingress_from_anywhere".to_string(),
        "has_egress_to_anywhere".to_string(),
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
        .insert("group_id".to_string(), "group_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("group_name".to_string(), "group_name".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("vpc_id".to_string(), "vpc_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("description".to_string(), "description".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "ingress_rule_count".to_string(),
            "ingress_rule_count".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "egress_rule_count".to_string(),
            "egress_rule_count".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "has_ingress_from_anywhere".to_string(),
            "has_ingress_from_anywhere".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "has_egress_to_anywhere".to_string(),
            "has_egress_to_anywhere".to_string(),
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
        collector_type: "aws_security_group".to_string(),
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
