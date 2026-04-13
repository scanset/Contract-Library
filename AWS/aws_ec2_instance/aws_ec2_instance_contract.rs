//! AWS EC2 Instance CTN Contract
//!
//! Validates EC2 instance configuration via a single AWS CLI call:
//! describe-instances --instance-ids <instance_id>
//!
//! Key compliance scalars:
//!   imdsv2_required  → MetadataOptions.HttpTokens == "required"
//!   has_public_ip    → derived false when PublicIpAddress is absent/empty
//!   state            → State.Name (running, stopped, etc.)
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE instance_hardened
//!     found boolean = true
//!     state string = `running`
//!     imdsv2_required boolean = true
//!     has_public_ip boolean = false
//!     root_volume_encrypted boolean = true
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ec2_instance_contracts;
//  pub use aws_ec2_instance_contracts::create_aws_ec2_instance_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_ec2_instance_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_ec2_instance".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "instance_id".to_string(),
            data_type: DataType::String,
            description: "EC2 instance ID".to_string(),
            example_values: vec!["i-0123456789abcdef0".to_string()],
            validation_notes: Some("Required; exact instance ID".to_string()),
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

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];
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
            description: "Whether the instance was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "instance_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "EC2 instance ID".to_string(),
            example_values: vec!["i-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "instance_type".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "EC2 instance type".to_string(),
            example_values: vec!["t3.large".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Instance state name".to_string(),
            example_values: vec!["running".to_string(), "stopped".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "image_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "AMI ID used to launch the instance".to_string(),
            example_values: vec!["ami-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "imdsv2_required".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether IMDSv2 is required (MetadataOptions.HttpTokens == required)"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Derived: true when HttpTokens = required".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "metadata_hop_limit".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "IMDSv2 hop limit (HttpPutResponseHopLimit)".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: Some("Should be 1 to prevent SSRF token theft".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_public_ip".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the instance has a public IP address".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some(
                "Derived: false when PublicIpAddress is absent or empty string".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "root_volume_encrypted".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the root EBS volume is encrypted".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived by looking up the root volume ID from BlockDeviceMappings".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "VPC ID the instance is in".to_string(),
            example_values: vec!["vpc-0123456789abcdef0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subnet_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Subnet ID the instance is in".to_string(),
            example_values: vec!["subnet-0aaaaaaaaaaaaaaaa".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "iam_instance_profile_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "IAM instance profile ARN".to_string(),
            example_values: vec![
                "arn:aws:iam::123456789012:instance-profile/example-org-ec2-profile"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "security_group_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "First security group ID attached to the instance".to_string(),
            example_values: vec!["sg-0123456789abcdef0".to_string()],
            validation_notes: Some("First entry from SecurityGroups array".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "monitoring_state".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Detailed monitoring state (disabled or enabled)".to_string(),
            example_values: vec!["disabled".to_string(), "enabled".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "boot_mode".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Current instance boot mode".to_string(),
            example_values: vec!["uefi".to_string(), "legacy-bios".to_string()],
            validation_notes: Some("CurrentInstanceBootMode field".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ebs_optimized".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the instance is EBS-optimized".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    // tag_key dynamic fields
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>".to_string(),
            example_values: vec![
                "tag_key:Name → `example-org-vm`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full instance object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Full Instances[0] object including MetadataOptions, BlockDeviceMappings, etc."
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
        .insert("instance_id".to_string(), "instance_id".to_string());
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
        "instance_id".to_string(),
        "instance_type".to_string(),
        "state".to_string(),
        "image_id".to_string(),
        "imdsv2_required".to_string(),
        "metadata_hop_limit".to_string(),
        "has_public_ip".to_string(),
        "root_volume_encrypted".to_string(),
        "vpc_id".to_string(),
        "subnet_id".to_string(),
        "iam_instance_profile_arn".to_string(),
        "security_group_id".to_string(),
        "monitoring_state".to_string(),
        "boot_mode".to_string(),
        "ebs_optimized".to_string(),
    ];

    for field in &[
        "found",
        "instance_id",
        "instance_type",
        "state",
        "image_id",
        "imdsv2_required",
        "metadata_hop_limit",
        "has_public_ip",
        "root_volume_encrypted",
        "vpc_id",
        "subnet_id",
        "iam_instance_profile_arn",
        "security_group_id",
        "monitoring_state",
        "boot_mode",
        "ebs_optimized",
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
        collector_type: "aws_ec2_instance".to_string(),
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
