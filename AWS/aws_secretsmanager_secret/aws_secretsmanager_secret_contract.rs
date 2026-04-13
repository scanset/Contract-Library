//! AWS Secrets Manager Secret CTN Contract
//!
//! Validates Secrets Manager secret configuration via a single AWS CLI call:
//! secretsmanager describe-secret --secret-id <secret_id>
//!
//! secret_id can be the secret name or ARN.
//! Tags are a flat [{Key, Value}] array — flattened to tag_key:<Key> scalars.
//! has_current_version derived: true when any version has AWSCURRENT stage.
//! rotation_enabled derived: true when RotationEnabled field is present and true.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_secretsmanager_secret;
//  pub use aws_secretsmanager_secret::create_aws_secretsmanager_secret_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_secretsmanager_secret_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_secretsmanager_secret".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "secret_id".to_string(),
            data_type: DataType::String,
            description: "Secret name or ARN".to_string(),
            example_values: vec!["example-org/db/credentials".to_string()],
            validation_notes: Some("Required; secret name or full ARN".to_string()),
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the secret exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "secret_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Secret name".to_string(),
            example_values: vec!["example-org/db/credentials".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "secret_arn".to_string(),
        data_type: DataType::String,
        allowed_operations: str_full.clone(),
        description: "Secret ARN".to_string(),
        example_values: vec![
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:example-org/db/credentials-Sp6FkL"
                .to_string(),
        ],
        validation_notes: None,
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "kms_key_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "KMS key ARN used to encrypt the secret".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: Some("Absent if using the default AWS managed key".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Secret description".to_string(),
            example_values: vec!["ExampleOrg PostgreSQL credentials".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rotation_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether automatic rotation is enabled".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some(
                "Absent (defaults to false) when rotation is not configured".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_current_version".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the secret has an AWSCURRENT version".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: true when any VersionIdsToStages entry contains AWSCURRENT".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>".to_string(),
            example_values: vec![
                "tag_key:SecretType → `database`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full secret metadata object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Does not include secret value — only metadata from describe-secret".to_string(),
            ),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("secret_id".to_string(), "secret_id".to_string());
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
        "secret_name".to_string(),
        "secret_arn".to_string(),
        "kms_key_id".to_string(),
        "description".to_string(),
        "rotation_enabled".to_string(),
        "has_current_version".to_string(),
    ];

    for field in &[
        "found",
        "secret_name",
        "secret_arn",
        "kms_key_id",
        "description",
        "rotation_enabled",
        "has_current_version",
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
        collector_type: "aws_secretsmanager_secret".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["aws_cli".to_string(), "secretsmanager_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(1500),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
