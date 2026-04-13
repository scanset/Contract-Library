//! AWS CloudWatch Log Group CTN Contract

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_log_group;
//  pub use aws_cloudwatch_log_group::create_aws_cloudwatch_log_group_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_cloudwatch_log_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_cloudwatch_log_group".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "log_group_name".to_string(),
            data_type: DataType::String,
            description: "Log group name (exact match via prefix lookup)".to_string(),
            example_values: vec!["/example-org/security/findings".to_string()],
            validation_notes: Some("Required; exact log group name".to_string()),
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

    for (name, data_type, ops, description, notes) in &[
        (
            "found",
            DataType::Boolean,
            vec![Operation::Equals, Operation::NotEqual],
            "Whether the log group was found",
            None,
        ),
        (
            "log_group_class",
            DataType::String,
            vec![Operation::Equals, Operation::NotEqual],
            "Log group class (STANDARD or INFREQUENT_ACCESS)",
            None,
        ),
        (
            "deletion_protection_enabled",
            DataType::Boolean,
            vec![Operation::Equals, Operation::NotEqual],
            "Whether deletion protection is enabled",
            None,
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: data_type.clone(),
                allowed_operations: ops.clone(),
                description: description.to_string(),
                example_values: vec![],
                validation_notes: notes.map(|s: &str| s.to_string()),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_group_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Log group name".to_string(),
            example_values: vec!["/example-org/security/findings".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_group_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Log group ARN (without :* suffix)".to_string(),
            example_values: vec![
                "arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "retention_in_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Log retention in days (absent if no retention policy is set)".to_string(),
            example_values: vec!["365".to_string()],
            validation_notes: Some("Not present if log group has no retention policy".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "stored_bytes".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Bytes stored in the log group".to_string(),
            example_values: vec!["304155".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "metric_filter_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Number of metric filters on the log group".to_string(),
            example_values: vec!["0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full log group object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("log_group_name".to_string(), "log_group_name".to_string());
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
        "log_group_name".to_string(),
        "log_group_arn".to_string(),
        "retention_in_days".to_string(),
        "log_group_class".to_string(),
        "stored_bytes".to_string(),
        "deletion_protection_enabled".to_string(),
        "metric_filter_count".to_string(),
    ];

    for field in &[
        "found",
        "log_group_name",
        "log_group_arn",
        "retention_in_days",
        "log_group_class",
        "stored_bytes",
        "deletion_protection_enabled",
        "metric_filter_count",
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
        collector_type: "aws_cloudwatch_log_group".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["aws_cli".to_string(), "cloudwatch_logs_read".to_string()],
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
