//! AWS Macie2 Account CTN Contract
//!
//! Validates AWS Macie2 session status and classification job configuration
//! via two or three AWS CLI calls:
//! 1. get-macie-session           → session status, finding publishing frequency
//! 2. list-classification-jobs    → find job targeting specified bucket
//! 3. describe-classification-job → full job detail (when job exists)
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE macie_compliant
//!     found boolean = true
//!     session_status string = `ENABLED`
//!     finding_publishing_frequency string = `FIFTEEN_MINUTES`
//!     has_classification_job boolean = true
//!     job_type string = `SCHEDULED`
//!     last_run_error_code string = `NONE`
//!     sampling_percentage int = 100
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_macie2_account;
//  pub use aws_macie2_account::create_aws_macie2_account_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_macie2_account CTN type
pub fn create_aws_macie2_account_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_macie2_account".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some(
                "Uses AWS CLI default if not specified. One Macie2 session per account per region."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "bucket_name".to_string(),
            data_type: DataType::String,
            description: "S3 bucket name to find associated classification job".to_string(),
            example_values: vec!["example-org-security-findings".to_string()],
            validation_notes: Some(
                "If provided, finds the first job whose bucketDefinitions includes this bucket. If omitted, uses the first job returned."
                    .to_string(),
            ),
        });

    // ========================================================================
    // State requirements
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether Macie2 is enabled in the account/region".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "False when ResourceNotFoundException returned by get-macie-session".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "session_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Macie2 session status".to_string(),
            example_values: vec!["ENABLED".to_string(), "PAUSED".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "finding_publishing_frequency".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "How often Macie2 publishes findings".to_string(),
            example_values: vec![
                "FIFTEEN_MINUTES".to_string(),
                "ONE_HOUR".to_string(),
                "SIX_HOURS".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_classification_job".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description:
                "Whether a classification job exists (optionally matching the specified bucket)"
                    .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Derived from list-classification-jobs response".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "job_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Classification job status".to_string(),
            example_values: vec![
                "IDLE".to_string(),
                "RUNNING".to_string(),
                "PAUSED".to_string(),
                "CANCELLED".to_string(),
            ],
            validation_notes: Some(
                "Scheduled jobs show IDLE between runs. Validate job_type and last_run_error_code for compliance checks rather than job_status."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "job_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Classification job type".to_string(),
            example_values: vec!["SCHEDULED".to_string(), "ONE_TIME".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "job_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Classification job name".to_string(),
            example_values: vec!["example-org-security-bucket-scan".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "managed_data_identifier_selector".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Which managed data identifiers the job uses".to_string(),
            example_values: vec![
                "RECOMMENDED".to_string(),
                "ALL".to_string(),
                "NONE".to_string(),
            ],
            validation_notes: Some(
                "RECOMMENDED uses AWS-managed identifiers for common sensitive data types"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "sampling_percentage".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThanOrEqual,
                Operation::GreaterThan,
            ],
            description: "Percentage of objects sampled per job run (1-100)".to_string(),
            example_values: vec!["100".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "last_run_error_code".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Error code from the last job run".to_string(),
            example_values: vec!["NONE".to_string()],
            validation_notes: Some(
                "NONE indicates no errors on last run. Check this rather than job_status for compliance."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "schedule_day_of_week".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Day of week for weekly scheduled jobs".to_string(),
            example_values: vec!["MONDAY".to_string(), "SUNDAY".to_string()],
            validation_notes: Some(
                "Only present when job has a weeklySchedule frequency".to_string(),
            ),
        });

    // tag_key dynamic fields
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>. Tags come from the classification job tags flat map."
                .to_string(),
            example_values: vec![
                "tag_key:Environment → `demo`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: Some(
                "Tags are from the classification job, not the Macie2 session (session has no tags)."
                    .to_string(),
            ),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged session + classification job config as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Session (always), ClassificationJob (when job exists)".to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("region".to_string(), "region".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("bucket_name".to_string(), "bucket_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "session_status".to_string(),
        "finding_publishing_frequency".to_string(),
        "has_classification_job".to_string(),
        "job_status".to_string(),
        "job_type".to_string(),
        "job_name".to_string(),
        "managed_data_identifier_selector".to_string(),
        "sampling_percentage".to_string(),
        "last_run_error_code".to_string(),
        "schedule_day_of_week".to_string(),
        // tag_key:<Key> fields are dynamic
    ];

    for field in &[
        "found",
        "session_status",
        "finding_publishing_frequency",
        "has_classification_job",
        "job_status",
        "job_type",
        "job_name",
        "managed_data_identifier_selector",
        "sampling_percentage",
        "last_run_error_code",
        "schedule_day_of_week",
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

    // ========================================================================
    // Collection strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_macie2_account".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "macie2_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(4000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
