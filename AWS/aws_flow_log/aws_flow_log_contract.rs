//! AWS VPC Flow Log CTN Contract
//!
//! Validates AWS EC2 VPC Flow Log configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE flow_log_active
//!     found boolean = true
//!     flow_log_status string = `ACTIVE`
//!     traffic_type string = `ALL`
//!     log_destination_type string = `cloud-watch-logs`
//!     deliver_logs_status string = `SUCCESS`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_flow_log_contracts;
//  pub use aws_flow_log_contracts::create_aws_flow_log_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_flow_log CTN type
pub fn create_aws_flow_log_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_flow_log".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "flow_log_id".to_string(),
            data_type: DataType::String,
            description: "Flow Log ID for direct lookup".to_string(),
            example_values: vec!["fl-0123456789abcdef0".to_string()],
            validation_notes: Some("Takes precedence over resource_id lookup".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "resource_id".to_string(),
            data_type: DataType::String,
            description: "VPC or subnet ID to find flow logs for".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("Filters by resource-id (typically a VPC ID)".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in Key=Value format".to_string(),
            example_values: vec!["Name=example-vpc-flow-logs".to_string()],
            validation_notes: Some("Used for tag-based lookup".to_string()),
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a flow log was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "flow_log_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Flow Log ID".to_string(),
            example_values: vec!["fl-0123456789abcdef0".to_string()],
            validation_notes: Some("Validate the resolved flow log ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "flow_log_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Flow log operational status".to_string(),
            example_values: vec!["ACTIVE".to_string()],
            validation_notes: Some("'ACTIVE' means flow log is collecting".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "resource_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Resource ID the flow log is attached to".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("VPC or subnet ID".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "traffic_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Type of traffic captured".to_string(),
            example_values: vec![
                "ALL".to_string(),
                "ACCEPT".to_string(),
                "REJECT".to_string(),
            ],
            validation_notes: Some("'ALL' captures both accepted and rejected traffic".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_destination_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Destination type for flow log data".to_string(),
            example_values: vec!["cloud-watch-logs".to_string(), "s3".to_string()],
            validation_notes: Some("Where flow log data is delivered".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_destination".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "ARN of the log destination".to_string(),
            example_values: vec![
                "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/example-flow-logs"
                    .to_string(),
            ],
            validation_notes: Some("CloudWatch log group ARN or S3 bucket ARN".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "log_group_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "CloudWatch log group name (if destination is cloud-watch-logs)"
                .to_string(),
            example_values: vec!["/aws/vpc/example-flow-logs".to_string()],
            validation_notes: Some("Only present for cloud-watch-logs destination".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "deliver_logs_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Status of log delivery".to_string(),
            example_values: vec!["SUCCESS".to_string()],
            validation_notes: Some("'SUCCESS' means logs are being delivered".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of the Name tag".to_string(),
            example_values: vec!["example-vpc-flow-logs".to_string()],
            validation_notes: Some("Extracted from Tags array".to_string()),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData for record check validation".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Field paths use AWS API PascalCase names (e.g., MaxAggregationInterval)"
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
        .insert("flow_log_id".to_string(), "flow_log_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("resource_id".to_string(), "resource_id".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("tags".to_string(), "tags".to_string());
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
        "flow_log_id".to_string(),
        "flow_log_status".to_string(),
        "resource_id".to_string(),
        "traffic_type".to_string(),
        "log_destination_type".to_string(),
        "log_destination".to_string(),
        "log_group_name".to_string(),
        "deliver_logs_status".to_string(),
        "tag_name".to_string(),
    ];

    for field in &[
        "found",
        "flow_log_id",
        "flow_log_status",
        "resource_id",
        "traffic_type",
        "log_destination_type",
        "log_destination",
        "log_group_name",
        "deliver_logs_status",
        "tag_name",
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
        collector_type: "aws_flow_log".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "ec2_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
