//! AWS IAM Role CTN Contract
//!
//! Validates AWS IAM Role configurations via the AWS CLI.
//! Collects from three API calls:
//! 1. `iam get-role` — role configuration and trust policy
//! 2. `iam list-attached-role-policies` — managed policy attachments
//! 3. `iam list-role-policies` — inline policy names
//!
//! Results are merged into scalar fields and RecordData.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE node_role_valid
//!     found boolean = true
//!     role_name string = `example-node-role`
//!     attached_policy_count int = 3
//!     inline_policy_count int = 0
//!     record
//!         field AssumeRolePolicyDocument.Statement.0.Principal.Service string = `ec2.amazonaws.com`
//!         field AttachedPolicies.*.PolicyName string = `AmazonEKSWorkerNodePolicy` at_least_one
//!     record_end
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_iam_role_contracts;
//  pub use aws_iam_role_contracts::create_aws_iam_role_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_iam_role CTN type
pub fn create_aws_iam_role_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_iam_role".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "role_name".to_string(),
            data_type: DataType::String,
            description: "IAM role name (required)".to_string(),
            example_values: vec![
                "example-node-role".to_string(),
                "example-flow-logs-role".to_string(),
            ],
            validation_notes: Some("Role name, not ARN".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some(
                "IAM is global, but region may affect CLI profile selection".to_string(),
            ),
        });

    // ========================================================================
    // State requirements
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the IAM role was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "role_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Role name".to_string(),
            example_values: vec!["example-node-role".to_string()],
            validation_notes: Some("RoleName from get-role".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "role_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Role ARN".to_string(),
            example_values: vec!["arn:aws:iam::123456789012:role/example-node-role".to_string()],
            validation_notes: Some("Arn from get-role".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Role path".to_string(),
            example_values: vec!["/".to_string()],
            validation_notes: Some("Path from get-role".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "max_session_duration".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Maximum session duration in seconds".to_string(),
            example_values: vec!["3600".to_string()],
            validation_notes: Some("MaxSessionDuration from get-role".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attached_policy_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of managed policies attached".to_string(),
            example_values: vec!["3".to_string()],
            validation_notes: Some("Count from list-attached-role-policies".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "inline_policy_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of inline policies".to_string(),
            example_values: vec!["0".to_string()],
            validation_notes: Some("Count from list-role-policies".to_string()),
        });

    // RecordData
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged role config + policies as RecordData for record check validation"
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Contains get-role fields + AttachedPolicies array + InlinePolicyNames array"
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
        .insert("role_name".to_string(), "role_name".to_string());
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
        "role_name".to_string(),
        "role_arn".to_string(),
        "path".to_string(),
        "max_session_duration".to_string(),
        "attached_policy_count".to_string(),
        "inline_policy_count".to_string(),
    ];

    for field in &[
        "found",
        "role_name",
        "role_arn",
        "path",
        "max_session_duration",
        "attached_policy_count",
        "inline_policy_count",
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
        collector_type: "aws_iam_role".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "iam_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(4000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
