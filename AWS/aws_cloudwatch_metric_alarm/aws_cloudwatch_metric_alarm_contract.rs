//! AWS CloudWatch Metric Alarm CTN Contract
//!
//! Single API call: cloudwatch describe-alarms --alarm-names <alarm_name>
//!
//! Key scalars: alarm_name, state_value, metric_name, namespace,
//!   statistic, period, evaluation_periods, threshold,
//!   comparison_operator, treat_missing_data, actions_enabled

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_metric_alarm;
//  pub use aws_cloudwatch_metric_alarm::create_aws_cloudwatch_metric_alarm_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_cloudwatch_metric_alarm_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_cloudwatch_metric_alarm".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "alarm_name".to_string(),
            data_type: DataType::String,
            description: "Alarm name (exact match)".to_string(),
            example_values: vec!["example-org-root-login-alarm".to_string()],
            validation_notes: Some("Required; passed as --alarm-names".to_string()),
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

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the alarm was found",
            "true",
        ),
        (
            "alarm_name",
            DataType::String,
            str_eq.clone(),
            "Alarm name",
            "example-org-root-login-alarm",
        ),
        (
            "state_value",
            DataType::String,
            str_eq.clone(),
            "Current alarm state: OK | ALARM | INSUFFICIENT_DATA",
            "OK",
        ),
        (
            "metric_name",
            DataType::String,
            str_eq.clone(),
            "Metric being monitored",
            "RootLoginCount",
        ),
        (
            "namespace",
            DataType::String,
            str_eq.clone(),
            "Metric namespace",
            "ExampleOrg/Security",
        ),
        (
            "statistic",
            DataType::String,
            str_eq.clone(),
            "Statistic: Sum | Average | Maximum | Minimum | SampleCount",
            "Sum",
        ),
        (
            "comparison_operator",
            DataType::String,
            str_full.clone(),
            "Comparison operator",
            "GreaterThanOrEqualToThreshold",
        ),
        (
            "treat_missing_data",
            DataType::String,
            str_eq.clone(),
            "Missing data treatment: notBreaching | breaching | ignore | missing",
            "notBreaching",
        ),
        (
            "actions_enabled",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether alarm actions are enabled",
            "true",
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

    for (name, desc, example) in &[
        ("period", "Evaluation period in seconds", "300"),
        ("evaluation_periods", "Number of periods to evaluate", "1"),
        ("threshold", "Alarm threshold value", "1"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Int,
                allowed_operations: int_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full alarm object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for field in &["alarm_name", "region"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "alarm_name".to_string(),
        "state_value".to_string(),
        "metric_name".to_string(),
        "namespace".to_string(),
        "statistic".to_string(),
        "period".to_string(),
        "evaluation_periods".to_string(),
        "threshold".to_string(),
        "comparison_operator".to_string(),
        "treat_missing_data".to_string(),
        "actions_enabled".to_string(),
    ];

    for field in &[
        "found",
        "alarm_name",
        "state_value",
        "metric_name",
        "namespace",
        "statistic",
        "period",
        "evaluation_periods",
        "threshold",
        "comparison_operator",
        "treat_missing_data",
        "actions_enabled",
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
        collector_type: "aws_cloudwatch_metric_alarm".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "cloudwatch_read".to_string()],
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
