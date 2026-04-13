//! AWS KMS Key CTN Contract
//!
//! Validates KMS key configuration via three AWS CLI calls:
//! 1. kms describe-key               → key state, usage, spec, origin
//! 2. kms get-key-rotation-status    → rotation enabled, period
//! 3. kms get-key-policy             → key policy (JSON string → parsed RecordData)
//!
//! IMPORTANT: key_id must be the key ID or ARN — NOT an alias.
//! KMS aliases are not supported by get-key-rotation-status or get-key-policy.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_kms_key;
//  pub use aws_kms_key::create_aws_kms_key_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_kms_key_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_kms_key".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "key_id".to_string(),
            data_type: DataType::String,
            description: "KMS key ID or ARN (NOT an alias)".to_string(),
            example_values: vec![
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: Some(
                "Aliases (alias/*) are NOT supported — use key ID or ARN".to_string(),
            ),
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
            description: "Whether the key was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Key ID (UUID format)".to_string(),
            example_values: vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Key ARN".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the key is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_state".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Key state".to_string(),
            example_values: vec![
                "Enabled".to_string(),
                "Disabled".to_string(),
                "PendingDeletion".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_usage".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Key usage type".to_string(),
            example_values: vec!["ENCRYPT_DECRYPT".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_spec".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Key spec (cryptographic algorithm family)".to_string(),
            example_values: vec!["SYMMETRIC_DEFAULT".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "key_manager".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Whether key is CUSTOMER or AWS managed".to_string(),
            example_values: vec!["CUSTOMER".to_string(), "AWS".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "origin".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Key material origin".to_string(),
            example_values: vec!["AWS_KMS".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "multi_region".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the key is a multi-region key".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Key description".to_string(),
            example_values: vec!["ExampleOrg secrets encryption key".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rotation_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether automatic key rotation is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("From get-key-rotation-status".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rotation_period_in_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Key rotation period in days".to_string(),
            example_values: vec!["90".to_string()],
            validation_notes: Some("Only present when rotation_enabled = true".to_string()),
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Merged key metadata + parsed key policy as RecordData".to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "Keys: KeyMetadata (describe-key), KeyPolicy (parsed from JSON string), RotationStatus (get-key-rotation-status)".to_string(),
        ),
    });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("key_id".to_string(), "key_id".to_string());
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
        "key_id".to_string(),
        "key_arn".to_string(),
        "enabled".to_string(),
        "key_state".to_string(),
        "key_usage".to_string(),
        "key_spec".to_string(),
        "key_manager".to_string(),
        "origin".to_string(),
        "multi_region".to_string(),
        "description".to_string(),
        "rotation_enabled".to_string(),
        "rotation_period_in_days".to_string(),
    ];

    for field in &[
        "found",
        "key_id",
        "key_arn",
        "enabled",
        "key_state",
        "key_usage",
        "key_spec",
        "key_manager",
        "origin",
        "multi_region",
        "description",
        "rotation_enabled",
        "rotation_period_in_days",
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

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_kms_key".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "kms_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
