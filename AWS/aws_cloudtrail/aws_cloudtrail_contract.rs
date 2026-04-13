//! AWS CloudTrail CTN Contract
//!
//! Validates AWS CloudTrail trail configurations via the AWS CLI.
//! Collects from both `describe-trails` (configuration) and `get-trail-status`
//! (operational state), merging results into scalar fields and RecordData.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE trail_compliant
//!     found boolean = true
//!     is_logging boolean = true
//!     is_multi_region boolean = true
//!     log_file_validation_enabled boolean = true
//!     include_global_service_events boolean = true
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudtrail_contracts;
//  pub use aws_cloudtrail_contracts::create_aws_cloudtrail_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_cloudtrail CTN type
pub fn create_aws_cloudtrail_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_cloudtrail".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "trail_name".to_string(),
            data_type: DataType::String,
            description: "Trail name or ARN for direct lookup".to_string(),
            example_values: vec![
                "example-trail".to_string(),
                "arn:aws:cloudtrail:us-east-1:123456789012:trail/example-trail".to_string(),
            ],
            validation_notes: Some(
                "If not specified, returns first trail from describe-trails".to_string(),
            ),
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

    // ========================================================================
    // State requirements (validation fields)
    // ========================================================================

    // Existence
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a CloudTrail trail was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    // From describe-trails
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "trail_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Trail name".to_string(),
            example_values: vec!["example-trail".to_string()],
            validation_notes: Some("Name field from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "trail_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Trail ARN".to_string(),
            example_values: vec![
                "arn:aws:cloudtrail:us-east-1:123456789012:trail/example-trail".to_string(),
            ],
            validation_notes: Some("TrailARN from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "s3_bucket_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "S3 bucket where trail logs are delivered".to_string(),
            example_values: vec!["example-org-cloudtrail-123456789012".to_string()],
            validation_notes: Some("S3BucketName from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_multi_region".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the trail is multi-region".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("IsMultiRegionTrail from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "include_global_service_events".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether global service events (IAM, STS) are included".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("IncludeGlobalServiceEvents from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_file_validation_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether log file integrity validation is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("LogFileValidationEnabled from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_organization_trail".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether this is an organization trail".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("IsOrganizationTrail from describe-trails".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "home_region".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Home region of the trail".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some("HomeRegion from describe-trails".to_string()),
        });

    // From get-trail-status
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_logging".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the trail is currently logging".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("IsLogging from get-trail-status".to_string()),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged trail config + status as RecordData for record check validation"
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Contains both describe-trails and get-trail-status fields merged into one object"
                    .to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("trail_name".to_string(), "trail_name".to_string());
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
        "trail_name".to_string(),
        "trail_arn".to_string(),
        "s3_bucket_name".to_string(),
        "is_multi_region".to_string(),
        "include_global_service_events".to_string(),
        "log_file_validation_enabled".to_string(),
        "is_organization_trail".to_string(),
        "home_region".to_string(),
        "is_logging".to_string(),
    ];

    for field in &[
        "found",
        "trail_name",
        "trail_arn",
        "s3_bucket_name",
        "is_multi_region",
        "include_global_service_events",
        "log_file_validation_enabled",
        "is_organization_trail",
        "home_region",
        "is_logging",
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
        collector_type: "aws_cloudtrail".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "cloudtrail_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
