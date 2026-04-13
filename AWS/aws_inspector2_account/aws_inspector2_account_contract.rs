//! AWS Inspector2 Account CTN Contract
//!
//! Validates AWS Inspector2 scan configuration and coverage via two AWS CLI calls:
//! 1. get-configuration → ECR rescan duration, EC2 scan mode
//! 2. list-coverage     → derived coverage booleans per resource type
//!
//! Coverage scalars are derived by scanning the coveredResources array:
//!   ec2_scan_active     → any AWS_EC2_INSTANCE entry with ACTIVE status
//!   ecr_scan_active     → any AWS_ECR_REPOSITORY entry with ACTIVE status
//!   network_scan_active → AWS_ACCOUNT NETWORK entry with ACTIVE status
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE inspector2_compliant
//!     found boolean = true
//!     ec2_scan_active boolean = true
//!     ecr_scan_active boolean = true
//!     network_scan_active boolean = true
//!     ec2_scan_mode_status string = `SUCCESS`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_inspector2_account;
//  pub use aws_inspector2_account::create_aws_inspector2_account_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_inspector2_account CTN type
pub fn create_aws_inspector2_account_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_inspector2_account".to_string());

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
                "Uses AWS CLI default if not specified. One Inspector2 configuration per account per region."
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
            description: "Whether Inspector2 is enabled in the account/region".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "False when Inspector2 is not enabled (AccessDeniedException on get-configuration)"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ecr_rescan_duration".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "How long Inspector2 rescans ECR images after initial push".to_string(),
            example_values: vec![
                "DAYS_14".to_string(),
                "DAYS_30".to_string(),
                "DAYS_180".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ecr_pull_date_rescan_duration".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "How long Inspector2 rescans ECR images after last pull".to_string(),
            example_values: vec!["DAYS_14".to_string(), "DAYS_30".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ecr_pull_date_rescan_mode".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "The pull date mode used for ECR rescan scheduling".to_string(),
            example_values: vec!["LAST_IN_USE_AT".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ec2_scan_mode".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "EC2 scanning mode".to_string(),
            example_values: vec![
                "EC2_HYBRID".to_string(),
                "EC2_SSM_AGENT_BASED".to_string(),
                "EC2_AGENTLESS".to_string(),
            ],
            validation_notes: Some(
                "EC2_HYBRID uses SSM agent when available, falls back to agentless".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ec2_scan_mode_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Status of the EC2 scan mode configuration".to_string(),
            example_values: vec!["SUCCESS".to_string(), "PENDING".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
        name: "ec2_scan_active".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: vec![Operation::Equals, Operation::NotEqual],
        description: "Whether at least one EC2 instance has an ACTIVE Inspector2 scan".to_string(),
        example_values: vec!["true".to_string()],
        validation_notes: Some(
            "Derived from list-coverage: any AWS_EC2_INSTANCE with scanStatus.statusCode=ACTIVE"
                .to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
        name: "ecr_scan_active".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: vec![Operation::Equals, Operation::NotEqual],
        description: "Whether at least one ECR repository has an ACTIVE Inspector2 scan"
            .to_string(),
        example_values: vec!["true".to_string()],
        validation_notes: Some(
            "Derived from list-coverage: any AWS_ECR_REPOSITORY with scanStatus.statusCode=ACTIVE"
                .to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "network_scan_active".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the account-level network scan is ACTIVE".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived from list-coverage: AWS_ACCOUNT entry with scanType=NETWORK and scanStatus.statusCode=ACTIVE"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "covered_resource_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Total number of resources in the coverage list".to_string(),
            example_values: vec!["2".to_string()],
            validation_notes: None,
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged configuration + coverage as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Configuration (get-configuration), Coverage (list-coverage)".to_string(),
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
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "ecr_rescan_duration".to_string(),
        "ecr_pull_date_rescan_duration".to_string(),
        "ecr_pull_date_rescan_mode".to_string(),
        "ec2_scan_mode".to_string(),
        "ec2_scan_mode_status".to_string(),
        "ec2_scan_active".to_string(),
        "ecr_scan_active".to_string(),
        "network_scan_active".to_string(),
        "covered_resource_count".to_string(),
    ];

    for field in &[
        "found",
        "ecr_rescan_duration",
        "ecr_pull_date_rescan_duration",
        "ecr_pull_date_rescan_mode",
        "ec2_scan_mode",
        "ec2_scan_mode_status",
        "ec2_scan_active",
        "ecr_scan_active",
        "network_scan_active",
        "covered_resource_count",
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
        collector_type: "aws_inspector2_account".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "inspector2_read".to_string()],
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
