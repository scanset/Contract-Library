//! AWS Network Load Balancer (NLB) CTN Contract
//!
//! Validates AWS NLB configurations via the AWS CLI (elbv2 API).
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## Design
//!
//! Follows the hybrid pattern:
//! - Scalar fields (`found`, `dns_name`, `scheme`, etc.) for quick property checks
//! - RecordData (`record` -> `resource`) for deep inspection of listeners and attributes
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE nlb_check
//!     found boolean = true
//!     scheme string = `internal`
//!     deletion_protection boolean = true
//!     cross_zone_enabled boolean = true
//!     has_tls_listener boolean = true
//!     record
//!         field Listeners.0.Protocol string = `TLS`
//!         field Listeners.0.SslPolicy string = `ELBSecurityPolicy-TLS13-1-2-2021-06`
//!     record_end
//! STATE_END
//! ```
//!
//! ## mod.rs additions
//!
//! ```rust
//! pub mod aws_nlb;
//! pub use aws_nlb::create_aws_nlb_contract;
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_nlb CTN type
pub fn create_aws_nlb_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_nlb".to_string());

    // ========================================================================
    // Object requirements (input fields for lookup)
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "load_balancer_arn".to_string(),
            data_type: DataType::String,
            description: "NLB ARN for direct lookup".to_string(),
            example_values: vec![
                "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1234567890abcdef"
                    .to_string(),
            ],
            validation_notes: Some(
                "Takes precedence over load_balancer_name if both specified".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "load_balancer_name".to_string(),
            data_type: DataType::String,
            description: "NLB name for filter-based lookup".to_string(),
            example_values: vec!["my-nlb".to_string()],
            validation_notes: Some(
                "Used with --names flag if load_balancer_arn not specified".to_string(),
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the NLB was found".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "load_balancer_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "NLB name".to_string(),
            example_values: vec!["my-nlb".to_string()],
            validation_notes: Some("Validate the NLB name".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "dns_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "NLB DNS name".to_string(),
            example_values: vec![
                "my-nlb-123456789.elb.us-east-1.amazonaws.com".to_string(),
            ],
            validation_notes: Some("Validate NLB DNS hostname".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "scheme".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "NLB scheme (internet-facing or internal)".to_string(),
            example_values: vec![
                "internet-facing".to_string(),
                "internal".to_string(),
            ],
            validation_notes: Some("Validate exposure model".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "NLB state (active, provisioning, failed)".to_string(),
            example_values: vec!["active".to_string()],
            validation_notes: Some("Validate NLB operational state".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the NLB resides in".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: Some("Validate VPC association".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ip_address_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "IP address type (ipv4, dualstack)".to_string(),
            example_values: vec!["ipv4".to_string(), "dualstack".to_string()],
            validation_notes: Some("Validate IP addressing mode".to_string()),
        });

    // Attributes (from describe-load-balancer-attributes)
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "deletion_protection".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether deletion protection is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Validate deletion protection".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cross_zone_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether cross-zone load balancing is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Validate cross-AZ distribution".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "access_logging_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether access logging is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Validate access log configuration".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "access_log_s3_bucket".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "S3 bucket for access logs".to_string(),
            example_values: vec!["my-nlb-logs-bucket".to_string()],
            validation_notes: Some("Validate log destination bucket".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "listener_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Number of listeners configured".to_string(),
            example_values: vec!["1".to_string(), "2".to_string()],
            validation_notes: Some("Validate listener count".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_tls_listener".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether at least one TLS listener exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Validate TLS is configured".to_string()),
        });

    // Connection logging
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "connection_logging_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether connection logging to S3 is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Validate connection log configuration".to_string()),
        });

    // Target groups (from describe-target-groups)
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "target_group_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Number of target groups attached".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some("Validate target group count".to_string()),
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
                "Field paths use AWS API PascalCase names (e.g., Listeners.0.Protocol)".to_string(),
            ),
        });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert(
            "load_balancer_arn".to_string(),
            "load_balancer_arn".to_string(),
        );
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert(
            "load_balancer_name".to_string(),
            "load_balancer_name".to_string(),
        );
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
        "load_balancer_name".to_string(),
        "dns_name".to_string(),
        "scheme".to_string(),
        "state".to_string(),
        "vpc_id".to_string(),
        "ip_address_type".to_string(),
        "deletion_protection".to_string(),
        "cross_zone_enabled".to_string(),
        "access_logging_enabled".to_string(),
        "access_log_s3_bucket".to_string(),
        "listener_count".to_string(),
        "has_tls_listener".to_string(),
        "connection_logging_enabled".to_string(),
        "target_group_count".to_string(),
    ];

    // State -> Data validation mappings
    for field in &[
        "found",
        "load_balancer_name",
        "dns_name",
        "scheme",
        "state",
        "vpc_id",
        "ip_address_type",
        "deletion_protection",
        "cross_zone_enabled",
        "access_logging_enabled",
        "access_log_s3_bucket",
        "listener_count",
        "has_tls_listener",
        "connection_logging_enabled",
        "target_group_count",
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
        collector_type: "aws_nlb".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "elbv2_read".to_string()],
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
