//! AWS Backup Plan CTN Contract
//!
//! Validates AWS Backup plan configuration via two AWS CLI calls:
//! 1. list-backup-plans  → find plan by BackupPlanName
//! 2. get-backup-plan    → full plan detail with rules
//!
//! Rule-level scalars are derived from the Rules array:
//!   rule_count           → total number of rules
//!   has_daily_rule       → any rule with daily schedule (cron 0 * * * ? *)
//!   has_weekly_rule      → any rule with weekly schedule (cron * * ? * SUN *)
//!   has_monthly_rule     → any rule with monthly schedule (cron * * 1 * ? *)
//!   has_cross_region_copy → any rule with CopyActions
//!   max_delete_after_days → maximum DeleteAfterDays across all rules

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_backup_plan;
//  pub use aws_backup_plan::create_aws_backup_plan_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_backup_plan_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_backup_plan".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "plan_name".to_string(),
            data_type: DataType::String,
            description: "Backup plan name (matched against BackupPlanName)".to_string(),
            example_values: vec!["example-org-backup-plan".to_string()],
            validation_notes: Some("Required; exact plan name".to_string()),
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
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the backup plan was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "plan_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Backup plan name".to_string(),
            example_values: vec!["example-org-backup-plan".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "plan_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Backup plan ARN".to_string(),
            example_values: vec![
            "arn:aws:backup:us-east-1:123456789012:backup-plan:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                .to_string(),
        ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rule_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Total number of backup rules in the plan".to_string(),
            example_values: vec!["3".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_daily_rule".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a daily backup rule exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: any rule where ScheduleExpression contains 'cron(0' with daily pattern"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_weekly_rule".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a weekly backup rule exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: any rule where ScheduleExpression contains 'SUN'".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_monthly_rule".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a monthly backup rule exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: any rule where ScheduleExpression contains day-of-month '1 * ?'"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_cross_region_copy".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any rule has cross-region copy actions configured".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: any rule where CopyActions array is non-empty".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "max_delete_after_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Maximum DeleteAfterDays across all rules (longest retention)".to_string(),
            example_values: vec!["2555".to_string()],
            validation_notes: Some(
                "Derived: max of all Lifecycle.DeleteAfterDays values across rules".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full backup plan object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "BackupPlan.Rules array contains full rule detail including CopyActions"
                    .to_string(),
            ),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("plan_name".to_string(), "plan_name".to_string());
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
        "plan_name".to_string(),
        "plan_arn".to_string(),
        "rule_count".to_string(),
        "has_daily_rule".to_string(),
        "has_weekly_rule".to_string(),
        "has_monthly_rule".to_string(),
        "has_cross_region_copy".to_string(),
        "max_delete_after_days".to_string(),
    ];

    for field in &[
        "found",
        "plan_name",
        "plan_arn",
        "rule_count",
        "has_daily_rule",
        "has_weekly_rule",
        "has_monthly_rule",
        "has_cross_region_copy",
        "max_delete_after_days",
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
        collector_type: "aws_backup_plan".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "backup_read".to_string()],
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
