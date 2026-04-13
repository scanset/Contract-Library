//! AWS CloudWatch Metric Filter CTN Contract
//!
//! Single API call: logs describe-metric-filters
//!   --log-group-name <log_group_name>
//!   --filter-name-prefix <filter_name>
//!
//! Both filter_name and log_group_name required.
//! Matches first filter where filterName == filter_name exactly.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_metric_filter;
//  pub use aws_cloudwatch_metric_filter::create_aws_cloudwatch_metric_filter_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_cloudwatch_metric_filter_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_cloudwatch_metric_filter".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "filter_name".to_string(),
            data_type: DataType::String,
            description: "Metric filter name (exact match)".to_string(),
            example_values: vec!["example-org-root-login".to_string()],
            validation_notes: Some(
                "Used as --filter-name-prefix; exact match applied on result".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "log_group_name".to_string(),
            data_type: DataType::String,
            description: "Log group the filter is attached to".to_string(),
            example_values: vec!["/example-org/cloudtrail".to_string()],
            validation_notes: Some("Used as --log-group-name".to_string()),
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

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the filter was found",
            "true",
        ),
        (
            "filter_name",
            DataType::String,
            str_eq.clone(),
            "Filter name",
            "example-org-root-login",
        ),
        (
            "log_group_name",
            DataType::String,
            str_eq.clone(),
            "Log group name",
            "/example-org/cloudtrail",
        ),
        (
            "metric_name",
            DataType::String,
            str_eq.clone(),
            "Metric name produced by the filter",
            "RootLoginCount",
        ),
        (
            "metric_namespace",
            DataType::String,
            str_eq.clone(),
            "Metric namespace",
            "ExampleOrg/Security",
        ),
        (
            "filter_pattern",
            DataType::String,
            str_full.clone(),
            "Filter pattern expression",
            "{ $.userIdentity.type = \"Root\" }",
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full metric filter object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for field in &["filter_name", "log_group_name", "region"] {
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
        "filter_name".to_string(),
        "log_group_name".to_string(),
        "metric_name".to_string(),
        "metric_namespace".to_string(),
        "filter_pattern".to_string(),
    ];

    for field in &[
        "found",
        "filter_name",
        "log_group_name",
        "metric_name",
        "metric_namespace",
        "filter_pattern",
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
        collector_type: "aws_cloudwatch_metric_filter".to_string(),
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
