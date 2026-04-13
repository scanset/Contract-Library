//! AWS CloudWatch EventBridge Rule CTN Contract

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudwatch_event_rule;
//  pub use aws_cloudwatch_event_rule::create_aws_cloudwatch_event_rule_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_cloudwatch_event_rule_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_cloudwatch_event_rule".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "rule_name".to_string(),
            data_type: DataType::String,
            description: "EventBridge rule name (exact match)".to_string(),
            example_values: vec!["example-org-guardduty-findings".to_string()],
            validation_notes: Some("Required; exact rule name".to_string()),
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

    // State fields
    let string_eq_ne = vec![Operation::Equals, Operation::NotEqual];
    let string_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];
    let string_contains = vec![Operation::Equals, Operation::NotEqual, Operation::Contains];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
    ];

    for (name, data_type, ops, description, example, notes) in &[
        (
            "found",
            DataType::Boolean,
            vec![Operation::Equals, Operation::NotEqual],
            "Whether the rule exists",
            "true",
            None,
        ),
        (
            "state",
            DataType::String,
            string_eq_ne.clone(),
            "Rule state",
            "ENABLED",
            None,
        ),
        (
            "event_bus_name",
            DataType::String,
            string_eq_ne.clone(),
            "EventBus the rule is attached to",
            "default",
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
                example_values: vec![example.to_string()],
                validation_notes: notes.map(|s: &str| s.to_string()),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rule_name".to_string(),
            data_type: DataType::String,
            allowed_operations: string_full.clone(),
            description: "Rule name".to_string(),
            example_values: vec!["example-org-guardduty-findings".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rule_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: string_full.clone(),
            description: "Rule ARN".to_string(),
            example_values: vec![
                "arn:aws:events:us-east-1:123456789012:rule/example-org-guardduty-findings"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: string_contains.clone(),
            description: "Rule description".to_string(),
            example_values: vec!["Capture GuardDuty findings severity >= 4".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "target_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of targets configured for the rule".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "target_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: string_full.clone(),
            description: "ARN of the first target (e.g. CloudWatch log group ARN)".to_string(),
            example_values: vec![
                "arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings"
                    .to_string(),
            ],
            validation_notes: Some(
                "First target only; use record checks for multi-target validation".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "target_id".to_string(),
            data_type: DataType::String,
            allowed_operations: string_contains.clone(),
            description: "ID of the first target".to_string(),
            example_values: vec!["GuardDutyFindingsToLogs".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged rule + parsed EventPattern + targets as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Rule, EventPattern (parsed from JSON string), Targets array".to_string(),
            ),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("rule_name".to_string(), "rule_name".to_string());
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
        "rule_name".to_string(),
        "rule_arn".to_string(),
        "state".to_string(),
        "description".to_string(),
        "event_bus_name".to_string(),
        "target_count".to_string(),
        "target_arn".to_string(),
        "target_id".to_string(),
    ];

    for field in &[
        "found",
        "rule_name",
        "rule_arn",
        "state",
        "description",
        "event_bus_name",
        "target_count",
        "target_arn",
        "target_id",
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
        collector_type: "aws_cloudwatch_event_rule".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "events_read".to_string()],
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
