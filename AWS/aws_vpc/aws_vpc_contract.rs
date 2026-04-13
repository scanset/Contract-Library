//! AWS VPC CTN contract
//!
//! Validates AWS VPC configuration including CIDR, DNS settings, and tags.
//! Used for validating VPC infrastructure compliance.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_vpc_contracts;
//  pub use aws_vpc_contracts::create_aws_vpc_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_vpc CTN type
///
/// Validates VPC configuration by querying the AWS EC2 API.
pub fn create_aws_vpc_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_vpc".to_string());

    // ========================================================================
    // Object Requirements
    // ========================================================================

    // At least one of vpc_id or tags is required (enforced by collector)
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to query".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: Some("Specify either vpc_id or tags filter".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in key=value format".to_string(),
            example_values: vec![
                "Name=my-vpc".to_string(),
                "Environment=production".to_string(),
            ],
            validation_notes: Some("Filters VPCs by tag. Format: Key=Value".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region (defaults to CLI configured region)".to_string(),
            example_values: vec!["us-east-1".to_string(), "eu-west-1".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // State Requirements
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the VPC exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::PatternMatch,
            ],
            description: "VPC identifier".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cidr_block".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
                Operation::PatternMatch,
            ],
            description: "Primary CIDR block".to_string(),
            example_values: vec!["10.0.0.0/16".to_string(), "172.16.0.0/16".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC state".to_string(),
            example_values: vec!["available".to_string(), "pending".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "is_default".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether this is the default VPC".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enable_dns_support".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether DNS resolution is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enable_dns_hostnames".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether DNS hostnames are enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::PatternMatch,
            ],
            description: "Value of the Name tag".to_string(),
            example_values: vec!["my-production-vpc".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // Field Mappings
    // ========================================================================

    // Object to collection mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("vpc_id".to_string(), "vpc_id".to_string());
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

    // Required data fields from collection
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];

    // Optional data fields
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "vpc_id".to_string(),
        "cidr_block".to_string(),
        "state".to_string(),
        "is_default".to_string(),
        "enable_dns_support".to_string(),
        "enable_dns_hostnames".to_string(),
        "tag_name".to_string(),
    ];

    // State to data mappings for validation
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("vpc_id".to_string(), "vpc_id".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("cidr_block".to_string(), "cidr_block".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("state".to_string(), "state".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("is_default".to_string(), "is_default".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "enable_dns_support".to_string(),
            "enable_dns_support".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert(
            "enable_dns_hostnames".to_string(),
            "enable_dns_hostnames".to_string(),
        );
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("tag_name".to_string(), "tag_name".to_string());

    // ========================================================================
    // Collection Strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_vpc".to_string(),
        collection_mode: CollectionMode::Custom("api".to_string()),
        required_capabilities: vec!["aws_api".to_string(), "ec2_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let contract = create_aws_vpc_contract();
        assert_eq!(contract.ctn_type, "aws_vpc");
    }

    #[test]
    fn test_object_fields() {
        let contract = create_aws_vpc_contract();

        // vpc_id should be optional
        assert!(contract
            .object_requirements
            .optional_fields
            .iter()
            .any(|f| f.name == "vpc_id"));

        // tags should be optional
        assert!(contract
            .object_requirements
            .optional_fields
            .iter()
            .any(|f| f.name == "tags"));

        // region should be optional
        assert!(contract
            .object_requirements
            .optional_fields
            .iter()
            .any(|f| f.name == "region"));
    }

    #[test]
    fn test_state_fields() {
        let contract = create_aws_vpc_contract();

        let state_field_names: Vec<&str> = contract
            .state_requirements
            .optional_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        assert!(state_field_names.contains(&"exists"));
        assert!(state_field_names.contains(&"vpc_id"));
        assert!(state_field_names.contains(&"cidr_block"));
        assert!(state_field_names.contains(&"enable_dns_support"));
        assert!(state_field_names.contains(&"enable_dns_hostnames"));
        assert!(state_field_names.contains(&"is_default"));
    }

    #[test]
    fn test_collection_strategy() {
        let contract = create_aws_vpc_contract();
        assert_eq!(contract.collection_strategy.collector_type, "aws_vpc");
        assert!(
            contract
                .collection_strategy
                .performance_hints
                .network_intensive
        );
    }
}
