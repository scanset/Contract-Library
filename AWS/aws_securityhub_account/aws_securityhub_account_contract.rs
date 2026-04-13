//! AWS Security Hub Account CTN Contract
//!
//! Validates AWS Security Hub account configuration via three or four AWS CLI calls:
//! 1. describe-hub              → hub ARN, auto-enable controls, control finding generator
//! 2. get-enabled-standards     → per-standard booleans, standards count
//! 3. list-finding-aggregators  → aggregator existence
//! 4. get-finding-aggregator    → aggregation region and linking mode (when aggregator exists)
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE hub_compliant
//!     found boolean = true
//!     auto_enable_controls boolean = true
//!     standard_fsbp_enabled boolean = true
//!     standard_nist_800_53_enabled boolean = true
//!     has_finding_aggregator boolean = true
//!     finding_aggregator_region_linking_mode string = `ALL_REGIONS`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_securityhub_account_contracts;
//  pub use aws_securityhub_account_contracts::create_securityhub_account_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_securityhub_account CTN type
pub fn create_securityhub_account_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_securityhub_account".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    // No required identifier — one hub per account per region
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some(
                "Uses AWS CLI default if not specified. One hub exists per account per region."
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
            description: "Whether Security Hub is enabled in the account/region".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "False when InvalidAccessException returned by describe-hub".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "hub_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Security Hub ARN".to_string(),
            example_values: vec![
                "arn:aws:securityhub:us-east-1:123456789012:hub/default".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "auto_enable_controls".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description:
                "Whether new controls are automatically enabled when standards are updated"
                    .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Relevant to KSI-SVC-EIS".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "control_finding_generator".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Finding generator mode".to_string(),
            example_values: vec![
                "SECURITY_CONTROL".to_string(),
                "STANDARD_CONTROL".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "standards_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Number of standards subscriptions with status READY".to_string(),
            example_values: vec!["3".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "standard_fsbp_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether AWS Foundational Security Best Practices standard is enabled and READY".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived by matching StandardsArn containing 'aws-foundational-security-best-practices'"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "standard_nist_800_53_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether NIST SP 800-53 standard is enabled and READY".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived by matching StandardsArn containing 'nist-800-53'".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "standard_cis_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether CIS AWS Foundations Benchmark standard is enabled and READY"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived by matching StandardsArn containing 'cis-aws-foundations-benchmark'"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_finding_aggregator".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a finding aggregator is configured".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Derived from list-finding-aggregators response".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "finding_aggregation_region".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Region where findings are aggregated".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some("Only present when has_finding_aggregator is true".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "finding_aggregator_region_linking_mode".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Region linking mode for the finding aggregator".to_string(),
            example_values: vec!["ALL_REGIONS".to_string(), "SPECIFIED_REGIONS".to_string()],
            validation_notes: Some("Only present when has_finding_aggregator is true".to_string()),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Merged hub + standards + aggregator config as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Hub, Standards, FindingAggregator (when aggregator exists)".to_string(),
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
        "hub_arn".to_string(),
        "auto_enable_controls".to_string(),
        "control_finding_generator".to_string(),
        "standards_count".to_string(),
        "standard_fsbp_enabled".to_string(),
        "standard_nist_800_53_enabled".to_string(),
        "standard_cis_enabled".to_string(),
        "has_finding_aggregator".to_string(),
        "finding_aggregation_region".to_string(),
        "finding_aggregator_region_linking_mode".to_string(),
    ];

    for field in &[
        "found",
        "hub_arn",
        "auto_enable_controls",
        "control_finding_generator",
        "standards_count",
        "standard_fsbp_enabled",
        "standard_nist_800_53_enabled",
        "standard_cis_enabled",
        "has_finding_aggregator",
        "finding_aggregation_region",
        "finding_aggregator_region_linking_mode",
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
        collector_type: "aws_securityhub_account".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "securityhub_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(5000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
