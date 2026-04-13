//! AWS Network ACL CTN Contract
//!
//! Validates Network ACL configuration via a single AWS CLI call:
//! describe-network-acls with either --network-acl-ids or --filters
//!
//! Entries array contains both ingress (Egress=false) and egress (Egress=true)
//! rules mixed together. Derived scalars split them:
//!   ingress_entry_count → entries where Egress=false
//!   egress_entry_count  → entries where Egress=true
//!   entry_count         → total entries
//!   association_count   → number of associated subnets

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_network_acl;
//  pub use aws_network_acl::create_aws_network_acl_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_network_acl_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_network_acl".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "nacl_id".to_string(),
            data_type: DataType::String,
            description: "Network ACL ID for direct lookup".to_string(),
            example_values: vec!["acl-0123456789abcdef0".to_string()],
            validation_notes: Some(
                "Use nacl_id for direct lookup, or vpc_id + tags for named lookup".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to scope the lookup".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: Some("Used as --filters Name=vpc-id,Values=<vpc_id>".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in Key=Value format".to_string(),
            example_values: vec!["Name=example-org-nacl-private".to_string()],
            validation_notes: Some("Parsed as --filters Name=tag:<Key>,Values=<Value>".to_string()),
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

    // ========================================================================
    // State requirements
    // ========================================================================

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the NACL was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "nacl_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Network ACL ID".to_string(),
            example_values: vec!["acl-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "VPC the NACL belongs to".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_default".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether this is the default NACL for the VPC".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some(
                "Always validate is_default = false for custom NACLs".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "entry_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Total number of NACL entries (ingress + egress)".to_string(),
            example_values: vec!["10".to_string()],
            validation_notes: Some(
                "Includes the implicit deny-all rule 32767 for each direction".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ingress_entry_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of ingress entries (Egress=false)".to_string(),
            example_values: vec!["5".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "egress_entry_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of egress entries (Egress=true)".to_string(),
            example_values: vec!["5".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "association_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of subnets associated with this NACL".to_string(),
            example_values: vec!["2".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Full NACL object as RecordData for deep rule inspection".to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "Entries array contains both ingress (Egress=false) and egress (Egress=true) rules. Use record checks to inspect specific rules by index."
                .to_string(),
        ),
    });

    // ========================================================================
    // Field mappings
    // ========================================================================

    for field in &["nacl_id", "vpc_id", "tags", "region"] {
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
        "nacl_id".to_string(),
        "vpc_id".to_string(),
        "is_default".to_string(),
        "entry_count".to_string(),
        "ingress_entry_count".to_string(),
        "egress_entry_count".to_string(),
        "association_count".to_string(),
    ];

    for field in &[
        "found",
        "nacl_id",
        "vpc_id",
        "is_default",
        "entry_count",
        "ingress_entry_count",
        "egress_entry_count",
        "association_count",
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
        collector_type: "aws_network_acl".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "ec2_read".to_string()],
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
