//! AWS ECR Repository CTN Contract
//!
//! Validates AWS ECR repository configurations via the AWS CLI.
//! Returns scalar fields for common security checks and the full API
//! response as RecordData.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ecr_repository_contracts;
//  pub use aws_ecr_repository_contracts::create_aws_ecr_repository_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_ecr_repository_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_ecr_repository".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "repository_name".to_string(),
            data_type: DataType::String,
            description: "ECR repository name".to_string(),
            example_values: vec!["scanset/transparency-log".to_string()],
            validation_notes: Some("Required; exact repository name".to_string()),
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

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the repository was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "repository_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Repository name".to_string(),
            example_values: vec!["scanset/transparency-log".to_string()],
            validation_notes: Some("repositoryName from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "repository_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Repository ARN".to_string(),
            example_values: vec![
                "arn:aws:ecr:us-east-1:123456789012:repository/scanset/transparency-log"
                    .to_string(),
            ],
            validation_notes: Some("repositoryArn from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "image_tag_mutability".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Image tag mutability setting".to_string(),
            example_values: vec!["IMMUTABLE".to_string(), "MUTABLE".to_string()],
            validation_notes: Some(
                "IMMUTABLE prevents tag overwriting; critical for supply chain".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "scan_on_push".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether image scanning on push is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("imageScanningConfiguration.scanOnPush from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "encryption_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Encryption type".to_string(),
            example_values: vec!["AES256".to_string(), "KMS".to_string()],
            validation_notes: Some("encryptionConfiguration.encryptionType from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some("Field paths use camelCase as returned by ECR API".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("repository_name".to_string(), "repository_name".to_string());
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
        "repository_name".to_string(),
        "repository_arn".to_string(),
        "image_tag_mutability".to_string(),
        "scan_on_push".to_string(),
        "encryption_type".to_string(),
    ];

    for field in &[
        "found",
        "repository_name",
        "repository_arn",
        "image_tag_mutability",
        "scan_on_push",
        "encryption_type",
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
        collector_type: "aws_ecr_repository".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "ecr_read".to_string()],
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
