//! AWS EBS Volume CTN Contract
//!
//! Validates EBS volume configuration via a single AWS CLI call:
//! describe-volumes --volume-ids <volume_id>

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ebs_volume;
//  pub use aws_ebs_volume::create_aws_ebs_volume_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_ebs_volume_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_ebs_volume".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "volume_id".to_string(),
            data_type: DataType::String,
            description: "EBS volume ID".to_string(),
            example_values: vec!["vol-0fedcba9876543210".to_string()],
            validation_notes: Some("Required; exact volume ID".to_string()),
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
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    for (name, dt, ops, desc, example, notes) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the volume was found",
            "true",
            None,
        ),
        (
            "state",
            DataType::String,
            str_eq.clone(),
            "Volume state",
            "in-use",
            None,
        ),
        (
            "volume_type",
            DataType::String,
            str_eq.clone(),
            "Volume type",
            "gp3",
            None,
        ),
        (
            "availability_zone",
            DataType::String,
            str_eq.clone(),
            "Availability zone",
            "us-east-1a",
            None,
        ),
        (
            "encrypted",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the volume is encrypted",
            "true",
            None,
        ),
        (
            "multi_attach_enabled",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether multi-attach is enabled",
            "false",
            None,
        ),
        (
            "delete_on_termination",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the volume deletes on instance termination",
            "false",
            Some("From first attachment"),
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: dt.clone(),
                allowed_operations: ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(|s: &str| s.to_string()),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "volume_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Volume ID".to_string(),
            example_values: vec!["vol-0fedcba9876543210".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "kms_key_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "KMS key ARN used to encrypt the volume".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: Some("Only present when encrypted = true".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "size".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Volume size in GiB".to_string(),
            example_values: vec!["50".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "iops".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Provisioned IOPS".to_string(),
            example_values: vec!["3000".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "throughput".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Throughput in MiB/s".to_string(),
            example_values: vec!["125".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attached_instance_id".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Instance ID the volume is attached to".to_string(),
            example_values: vec!["i-0123456789abcdef0".to_string()],
            validation_notes: Some("From first attachment".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "attached_device".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Device name the volume is attached to".to_string(),
            example_values: vec!["/dev/xvdf".to_string()],
            validation_notes: Some("From first attachment".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of a specific tag. Field name format: tag_key:<TagKey>".to_string(),
            example_values: vec!["tag_key:Name → `example-org-data-volume`".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full volume object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("volume_id".to_string(), "volume_id".to_string());
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
        "volume_id".to_string(),
        "state".to_string(),
        "volume_type".to_string(),
        "availability_zone".to_string(),
        "encrypted".to_string(),
        "kms_key_id".to_string(),
        "size".to_string(),
        "iops".to_string(),
        "throughput".to_string(),
        "multi_attach_enabled".to_string(),
        "attached_instance_id".to_string(),
        "attached_device".to_string(),
        "delete_on_termination".to_string(),
    ];

    for field in &[
        "found",
        "volume_id",
        "state",
        "volume_type",
        "availability_zone",
        "encrypted",
        "kms_key_id",
        "size",
        "iops",
        "throughput",
        "multi_attach_enabled",
        "attached_instance_id",
        "attached_device",
        "delete_on_termination",
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
        collector_type: "aws_ebs_volume".to_string(),
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
