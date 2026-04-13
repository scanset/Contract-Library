//! AWS EKS Cluster CTN Contract
//!
//! Validates AWS EKS cluster configurations via the AWS CLI.
//! Returns scalar fields for common security checks and the full API
//! response as RecordData for deep inspection of networking, logging,
//! OIDC, and access configuration.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_eks_cluster_contracts;
//  pub use aws_eks_cluster_contracts::create_aws_eks_cluster_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_eks_cluster_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_eks_cluster".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "cluster_name".to_string(),
            data_type: DataType::String,
            description: "EKS cluster name".to_string(),
            example_values: vec!["scanset".to_string()],
            validation_notes: Some("Required; exact cluster name".to_string()),
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

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the cluster was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cluster_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Cluster name".to_string(),
            example_values: vec!["scanset".to_string()],
            validation_notes: Some("name from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Cluster status".to_string(),
            example_values: vec!["ACTIVE".to_string()],
            validation_notes: Some("'ACTIVE' means operational".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "version".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Kubernetes version".to_string(),
            example_values: vec!["1.32".to_string()],
            validation_notes: Some("version from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the cluster runs in".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("resourcesVpcConfig.vpcId from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "endpoint_public_access".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the API server endpoint is publicly accessible".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("resourcesVpcConfig.endpointPublicAccess from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "endpoint_private_access".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the API server endpoint is privately accessible".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("resourcesVpcConfig.endpointPrivateAccess from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cluster_security_group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Cluster security group ID".to_string(),
            example_values: vec!["sg-0cccccccccccccccc0".to_string()],
            validation_notes: Some(
                "resourcesVpcConfig.clusterSecurityGroupId from API".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "role_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "IAM role ARN for the cluster".to_string(),
            example_values: vec!["arn:aws:iam::123456789012:role/example-cluster-role".to_string()],
            validation_notes: Some("roleArn from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "authentication_mode".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Authentication mode".to_string(),
            example_values: vec!["API_AND_CONFIG_MAP".to_string(), "API".to_string()],
            validation_notes: Some("accessConfig.authenticationMode from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some("Field paths use camelCase as returned by EKS API".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("cluster_name".to_string(), "cluster_name".to_string());
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
        "cluster_name".to_string(),
        "status".to_string(),
        "version".to_string(),
        "vpc_id".to_string(),
        "endpoint_public_access".to_string(),
        "endpoint_private_access".to_string(),
        "cluster_security_group_id".to_string(),
        "role_arn".to_string(),
        "authentication_mode".to_string(),
    ];

    for field in &[
        "found",
        "cluster_name",
        "status",
        "version",
        "vpc_id",
        "endpoint_public_access",
        "endpoint_private_access",
        "cluster_security_group_id",
        "role_arn",
        "authentication_mode",
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
        collector_type: "aws_eks_cluster".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "eks_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(10),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
