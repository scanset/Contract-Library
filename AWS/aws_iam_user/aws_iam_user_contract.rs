//! AWS IAM User CTN Contract
//!
//! Validates IAM user configuration via three AWS CLI calls:
//! 1. iam get-user                    → user metadata, path, tags
//! 2. iam list-user-policies          → inline policy names
//! 3. iam list-attached-user-policies → managed policy attachments
//!
//! RecordData merge:
//!   User object (get-user) + InlinePolicyNames + AttachedPolicies
//!
//! Tags are a flat [{Key, Value}] array — flattened to tag_key:<Key> scalars.
//! Commands 2 and 3 are skipped if Command 1 returns NoSuchEntity.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_iam_user;
//  pub use aws_iam_user::create_aws_iam_user_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_iam_user_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_iam_user".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "user_name".to_string(),
            data_type: DataType::String,
            description: "IAM user name (exact match, not ARN)".to_string(),
            example_values: vec!["example-org-esp-scanner".to_string()],
            validation_notes: Some(
                "Required; passed as --user-name to all three calls".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override (IAM is global; affects CLI profile only)"
                .to_string(),
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
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the user was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "user_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "IAM user name".to_string(),
            example_values: vec!["example-org-esp-scanner".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "user_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "IAM user ARN".to_string(),
            example_values: vec![
                "arn:aws:iam::123456789012:user/esp/example-org-esp-scanner".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "IAM path for the user".to_string(),
            example_values: vec!["/esp/".to_string(), "/".to_string()],
            validation_notes: Some(
                "Non-default paths indicate intentional organisational scoping".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
        name: "attached_policy_count".to_string(),
        data_type: DataType::Int,
        allowed_operations: int_ops.clone(),
        description: "Number of managed policies attached directly to the user".to_string(),
        example_values: vec!["0".to_string()],
        validation_notes: Some(
            "Best practice: use group-based policy assignment; direct user attachments should be 0"
                .to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "inline_policy_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of inline policies attached directly to the user".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>".to_string(),
            example_values: vec![
                "tag_key:Purpose → `ESP AWS daemon dev container identity`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Merged user config + InlinePolicyNames + AttachedPolicies as RecordData"
            .to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "InlinePolicyNames: array of inline policy names. AttachedPolicies: array of {PolicyName, PolicyArn}".to_string(),
        ),
    });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("user_name".to_string(), "user_name".to_string());
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
        "user_name".to_string(),
        "user_arn".to_string(),
        "path".to_string(),
        "attached_policy_count".to_string(),
        "inline_policy_count".to_string(),
    ];

    for field in &[
        "found",
        "user_name",
        "user_arn",
        "path",
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
        collector_type: "aws_iam_user".to_string(),
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
