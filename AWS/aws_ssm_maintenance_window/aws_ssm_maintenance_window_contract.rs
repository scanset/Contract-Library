//! AWS SSM Maintenance Window CTN Contract
//!
//! Validates SSM Maintenance Window configuration via a single AWS CLI call:
//! describe-maintenance-windows --filters Key=Name,Values=<name>

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ssm_maintenance_window;
//  pub use aws_ssm_maintenance_window::create_aws_ssm_maintenance_window_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_ssm_maintenance_window_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_ssm_maintenance_window".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "window_name".to_string(),
            data_type: DataType::String,
            description: "SSM Maintenance Window name (exact match via filter)".to_string(),
            example_values: vec!["example-org-backup-prep".to_string()],
            validation_notes: Some("Required; exact window name".to_string()),
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the maintenance window was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "window_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Window name".to_string(),
            example_values: vec!["example-org-backup-prep".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "window_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Window ID".to_string(),
            example_values: vec!["mw-0a4a75b49ee74fe35".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the maintenance window is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "duration".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Duration of the maintenance window in hours".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cutoff".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Hours before window ends when new tasks stop being initiated".to_string(),
            example_values: vec!["0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "schedule".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Window schedule (cron or rate expression)".to_string(),
            example_values: vec!["cron(0 2 * * ? *)".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Window description".to_string(),
            example_values: vec!["Pre-backup PostgreSQL dump".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full window object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("window_name".to_string(), "window_name".to_string());
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
        "window_name".to_string(),
        "window_id".to_string(),
        "enabled".to_string(),
        "duration".to_string(),
        "cutoff".to_string(),
        "schedule".to_string(),
        "description".to_string(),
    ];

    for field in &[
        "found",
        "window_name",
        "window_id",
        "enabled",
        "duration",
        "cutoff",
        "schedule",
        "description",
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
        collector_type: "aws_ssm_maintenance_window".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["aws_cli".to_string(), "ssm_read".to_string()],
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
