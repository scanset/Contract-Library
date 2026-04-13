//! AWS Config Rule CTN Contract
//!
//! Validates AWS Config rule configuration and compliance via two calls:
//! 1. configservice describe-config-rules --config-rule-names <name>
//! 2. configservice describe-compliance-by-config-rule --config-rule-names <name>
//!
//! compliance_type: COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE | INSUFFICIENT_DATA

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_config_rule;
//  pub use aws_config_rule::create_aws_config_rule_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_config_rule_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_config_rule".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "rule_name".to_string(),
            data_type: DataType::String,
            description: "Config rule name".to_string(),
            example_values: vec!["example-org-ebs-encrypted".to_string()],
            validation_notes: Some("Required; exact rule name".to_string()),
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

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the rule was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rule_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Config rule name".to_string(),
            example_values: vec!["example-org-ebs-encrypted".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rule_state".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Rule state".to_string(),
            example_values: vec!["ACTIVE".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "source_identifier".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "AWS managed rule identifier".to_string(),
            example_values: vec!["ENCRYPTED_VOLUMES".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "source_owner".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Rule owner: AWS or CUSTOM_LAMBDA".to_string(),
            example_values: vec!["AWS".to_string()],
            validation_notes: None,
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "compliance_type".to_string(),
        data_type: DataType::String,
        allowed_operations: str_eq.clone(),
        description: "Compliance result for this rule".to_string(),
        example_values: vec![
            "COMPLIANT".to_string(),
            "NON_COMPLIANT".to_string(),
            "NOT_APPLICABLE".to_string(),
            "INSUFFICIENT_DATA".to_string(),
        ],
        validation_notes: Some(
            "From describe-compliance-by-config-rule. INSUFFICIENT_DATA means rule has not yet evaluated.".to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Rule description".to_string(),
            example_values: vec!["EBS volumes must be encrypted - KSI-SVC-VRI".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Merged rule config + compliance as RecordData".to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "Keys: Rule (describe-config-rules), Compliance (describe-compliance-by-config-rule)"
                .to_string(),
        ),
    });

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
        "rule_state".to_string(),
        "source_identifier".to_string(),
        "source_owner".to_string(),
        "compliance_type".to_string(),
        "description".to_string(),
    ];

    for field in &[
        "found",
        "rule_name",
        "rule_state",
        "source_identifier",
        "source_owner",
        "compliance_type",
        "description",
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
        collector_type: "aws_config_rule".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "config_read".to_string()],
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
