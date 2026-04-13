//! AWS Subnet CTN contract
//!
//! Validates AWS Subnet configuration including CIDR, availability zone,
//! and public IP settings. Used for validating subnet infrastructure compliance.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_subnet_contracts;
//  pub use aws_subnet_contracts::create_aws_subnet_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_subnet CTN type
///
/// Validates subnet configuration by querying the AWS EC2 API.
pub fn create_aws_subnet_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_subnet".to_string());

    // ========================================================================
    // Object Requirements
    // ========================================================================

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subnet_id".to_string(),
            data_type: DataType::String,
            description: "Subnet ID to query".to_string(),
            example_values: vec!["subnet-0123456789abcdef0".to_string()],
            validation_notes: Some("Specify subnet_id, vpc_id, or tags filter".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            description: "VPC ID to filter subnets".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: Some("Returns all subnets in the specified VPC".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "tags".to_string(),
            data_type: DataType::String,
            description: "Tag filter in key=value format".to_string(),
            example_values: vec![
                "Name=my-subnet".to_string(),
                "Environment=production".to_string(),
            ],
            validation_notes: Some("Filters subnets by tag. Format: Key=Value".to_string()),
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
            description: "Whether the subnet exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subnet_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::PatternMatch,
            ],
            description: "Subnet identifier".to_string(),
            example_values: vec!["subnet-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC that contains this subnet".to_string(),
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
            description: "Subnet CIDR block".to_string(),
            example_values: vec!["10.0.1.0/24".to_string(), "172.16.0.0/24".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "availability_zone".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::PatternMatch,
            ],
            description: "Availability zone for the subnet".to_string(),
            example_values: vec!["us-east-1a".to_string(), "us-east-1b".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Subnet state".to_string(),
            example_values: vec!["available".to_string(), "pending".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "map_public_ip_on_launch".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether instances get public IPs by default".to_string(),
            example_values: vec!["false".to_string(), "true".to_string()],
            validation_notes: Some("Should be false for private/isolated subnets".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "available_ip_address_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
            ],
            description: "Number of available IP addresses".to_string(),
            example_values: vec!["251".to_string(), "123".to_string()],
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
            example_values: vec!["my-private-subnet".to_string()],
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
        .insert("subnet_id".to_string(), "subnet_id".to_string());
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
        "subnet_id".to_string(),
        "vpc_id".to_string(),
        "cidr_block".to_string(),
        "availability_zone".to_string(),
        "state".to_string(),
        "map_public_ip_on_launch".to_string(),
        "available_ip_address_count".to_string(),
        "tag_name".to_string(),
    ];

    // State to data mappings for validation
    let mappings = [
        "exists",
        "subnet_id",
        "vpc_id",
        "cidr_block",
        "availability_zone",
        "state",
        "map_public_ip_on_launch",
        "available_ip_address_count",
        "tag_name",
    ];

    for field in mappings {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // ========================================================================
    // Collection Strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_subnet".to_string(),
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
        let contract = create_aws_subnet_contract();
        assert_eq!(contract.ctn_type, "aws_subnet");
    }

    #[test]
    fn test_object_fields() {
        let contract = create_aws_subnet_contract();

        let optional_names: Vec<&str> = contract
            .object_requirements
            .optional_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        assert!(optional_names.contains(&"subnet_id"));
        assert!(optional_names.contains(&"vpc_id"));
        assert!(optional_names.contains(&"tags"));
        assert!(optional_names.contains(&"region"));
    }

    #[test]
    fn test_state_fields() {
        let contract = create_aws_subnet_contract();

        let state_field_names: Vec<&str> = contract
            .state_requirements
            .optional_fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        assert!(state_field_names.contains(&"exists"));
        assert!(state_field_names.contains(&"subnet_id"));
        assert!(state_field_names.contains(&"vpc_id"));
        assert!(state_field_names.contains(&"cidr_block"));
        assert!(state_field_names.contains(&"availability_zone"));
        assert!(state_field_names.contains(&"map_public_ip_on_launch"));
    }

    #[test]
    fn test_collection_strategy() {
        let contract = create_aws_subnet_contract();
        assert_eq!(contract.collection_strategy.collector_type, "aws_subnet");
        assert!(
            contract
                .collection_strategy
                .performance_hints
                .network_intensive
        );
    }
}
