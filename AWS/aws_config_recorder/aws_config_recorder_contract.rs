//! AWS Config Configuration Recorder CTN Contract
//!
//! Validates AWS Config recorder configuration via two AWS CLI calls:
//! 1. configservice describe-configuration-recorders → recording scope, mode
//! 2. configservice describe-configuration-recorder-status → recording active, last status

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_config_recorder;
//  pub use aws_config_recorder::create_aws_config_recorder_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_config_recorder_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_config_recorder".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "recorder_name".to_string(),
            data_type: DataType::String,
            description: "Config recorder name".to_string(),
            example_values: vec!["example-org-config-recorder".to_string()],
            validation_notes: Some("Required; exact recorder name".to_string()),
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

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the recorder was found",
            "true",
        ),
        (
            "recording",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the recorder is actively recording",
            "true",
        ),
        (
            "all_supported",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether all supported resource types are recorded",
            "true",
        ),
        (
            "include_global_resource_types",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether global resource types (IAM) are included",
            "true",
        ),
        (
            "last_status",
            DataType::String,
            str_eq.clone(),
            "Status of the last recording delivery",
            "SUCCESS",
        ),
        (
            "recording_frequency",
            DataType::String,
            str_eq.clone(),
            "Recording frequency mode",
            "CONTINUOUS",
        ),
        (
            "recorder_name",
            DataType::String,
            str_eq.clone(),
            "Recorder name",
            "example-org-config-recorder",
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: dt.clone(),
                allowed_operations: ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Merged recorder config + status as RecordData".to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some("Keys: Recorder (describe-configuration-recorders), Status (describe-configuration-recorder-status)".to_string()),
    });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("recorder_name".to_string(), "recorder_name".to_string());
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
        "recorder_name".to_string(),
        "recording".to_string(),
        "all_supported".to_string(),
        "include_global_resource_types".to_string(),
        "last_status".to_string(),
        "recording_frequency".to_string(),
    ];

    for field in &[
        "found",
        "recorder_name",
        "recording",
        "all_supported",
        "include_global_resource_types",
        "last_status",
        "recording_frequency",
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
        collector_type: "aws_config_recorder".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "config_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
