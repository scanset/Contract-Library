//! AWS GuardDuty Detector CTN Contract
//!
//! Validates AWS GuardDuty detector configuration via two or three AWS CLI calls:
//! 1. get-detector                    → status, features, data sources, tags
//! 2. list-publishing-destinations    → destination existence and type
//! 3. describe-publishing-destination → destination ARN and KMS key (when destination exists)
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE detector_compliant
//!     found boolean = true
//!     status string = `ENABLED`
//!     finding_publishing_frequency string = `FIFTEEN_MINUTES`
//!     feature_cloud_trail string = `ENABLED`
//!     feature_s3_data_events string = `ENABLED`
//!     feature_ebs_malware_protection string = `ENABLED`
//!     has_publishing_destination boolean = true
//!     publishing_destination_status string = `PUBLISHING`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_guardduty_detector_contracts;
//  pub use aws_guardduty_detector_contracts::create_aws_guardduty_detector_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_guardduty_detector CTN type
pub fn create_aws_guardduty_detector_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_guardduty_detector".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "detector_id".to_string(),
            data_type: DataType::String,
            description: "GuardDuty detector ID".to_string(),
            example_values: vec!["00000000000000000000000000000000".to_string()],
            validation_notes: Some("Required; exact detector ID".to_string()),
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
    // State requirements
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the detector was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "detector_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Detector ID (echoed from object field)".to_string(),
            example_values: vec!["00000000000000000000000000000000".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Detector status".to_string(),
            example_values: vec!["ENABLED".to_string(), "DISABLED".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "finding_publishing_frequency".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "How often findings are published".to_string(),
            example_values: vec![
                "FIFTEEN_MINUTES".to_string(),
                "ONE_HOUR".to_string(),
                "SIX_HOURS".to_string(),
            ],
            validation_notes: None,
        });

    // Feature scalar fields — one per known feature name
    for (field_name, feature_name) in &[
        ("feature_cloud_trail", "CLOUD_TRAIL"),
        ("feature_dns_logs", "DNS_LOGS"),
        ("feature_flow_logs", "FLOW_LOGS"),
        ("feature_s3_data_events", "S3_DATA_EVENTS"),
        ("feature_ebs_malware_protection", "EBS_MALWARE_PROTECTION"),
        ("feature_eks_audit_logs", "EKS_AUDIT_LOGS"),
        ("feature_rds_login_events", "RDS_LOGIN_EVENTS"),
        ("feature_eks_runtime_monitoring", "EKS_RUNTIME_MONITORING"),
        ("feature_lambda_network_logs", "LAMBDA_NETWORK_LOGS"),
        ("feature_runtime_monitoring", "RUNTIME_MONITORING"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: field_name.to_string(),
                data_type: DataType::String,
                allowed_operations: vec![Operation::Equals, Operation::NotEqual],
                description: format!("Status of {} feature from Features array", feature_name),
                example_values: vec!["ENABLED".to_string(), "DISABLED".to_string()],
                validation_notes: Some(format!(
                    "Absent if {} not present in Features array",
                    feature_name
                )),
            });
    }

    // Publishing destination fields
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_publishing_destination".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a publishing destination is configured".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Derived; false if Destinations list is empty".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publishing_destination_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Destination type".to_string(),
            example_values: vec!["S3".to_string()],
            validation_notes: Some(
                "Only present when has_publishing_destination is true".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publishing_destination_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Publishing destination status".to_string(),
            example_values: vec!["PUBLISHING".to_string(), "PENDING_VERIFICATION".to_string()],
            validation_notes: Some(
                "Only present when has_publishing_destination is true".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publishing_destination_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "ARN of the publishing destination (S3 bucket ARN)".to_string(),
            example_values: vec!["arn:aws:s3:::example-org-security-findings".to_string()],
            validation_notes: Some(
                "Only present when has_publishing_destination is true".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publishing_destination_kms_key_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "KMS key ARN used to encrypt published findings".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: Some(
                "Only present when has_publishing_destination is true".to_string(),
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
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>. Tags are always collected from get-detector response (no behavior flag required).".to_string(),
            example_values: vec![
                "tag_key:Environment → `demo`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: Some(
                "Tags come from the flat Tags map in get-detector (not a TagSet array)".to_string(),
            ),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged detector + publishing destination config as RecordData"
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Detector (always), PublishingDestination (when destination exists)"
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
        .insert("detector_id".to_string(), "detector_id".to_string());
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
        "detector_id".to_string(),
        "status".to_string(),
        "finding_publishing_frequency".to_string(),
        "feature_cloud_trail".to_string(),
        "feature_dns_logs".to_string(),
        "feature_flow_logs".to_string(),
        "feature_s3_data_events".to_string(),
        "feature_ebs_malware_protection".to_string(),
        "feature_eks_audit_logs".to_string(),
        "feature_rds_login_events".to_string(),
        "feature_eks_runtime_monitoring".to_string(),
        "feature_lambda_network_logs".to_string(),
        "feature_runtime_monitoring".to_string(),
        "has_publishing_destination".to_string(),
        "publishing_destination_type".to_string(),
        "publishing_destination_status".to_string(),
        "publishing_destination_arn".to_string(),
        "publishing_destination_kms_key_arn".to_string(),
        // tag_key:<Key> fields are dynamic
    ];

    for field in &[
        "found",
        "detector_id",
        "status",
        "finding_publishing_frequency",
        "feature_cloud_trail",
        "feature_dns_logs",
        "feature_flow_logs",
        "feature_s3_data_events",
        "feature_ebs_malware_protection",
        "feature_eks_audit_logs",
        "feature_rds_login_events",
        "feature_eks_runtime_monitoring",
        "feature_lambda_network_logs",
        "feature_runtime_monitoring",
        "has_publishing_destination",
        "publishing_destination_type",
        "publishing_destination_status",
        "publishing_destination_arn",
        "publishing_destination_kms_key_arn",
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
        collector_type: "aws_guardduty_detector".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "guardduty_read".to_string()],
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
