//! AWS RDS Instance CTN Contract
//!
//! Validates AWS RDS database instance configurations via the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData
//! for detailed inspection of security groups, subnet groups, encryption, etc.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE rds_hardened
//!     found boolean = true
//!     storage_encrypted boolean = true
//!     publicly_accessible boolean = false
//!     deletion_protection boolean = true
//!     multi_az boolean = true
//!     backup_retention_period int >= 7
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_rds_instance_contracts;
//  pub use aws_rds_instance_contracts::create_aws_rds_instance_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_rds_instance CTN type
pub fn create_aws_rds_instance_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_rds_instance".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "db_instance_identifier".to_string(),
            data_type: DataType::String,
            description: "RDS DB instance identifier".to_string(),
            example_values: vec!["example-transparency-log".to_string()],
            validation_notes: Some("Required; exact instance identifier".to_string()),
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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the DB instance was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "db_instance_identifier".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "DB instance identifier".to_string(),
            example_values: vec!["example-transparency-log".to_string()],
            validation_notes: Some("DBInstanceIdentifier from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "db_instance_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Instance operational status".to_string(),
            example_values: vec!["available".to_string()],
            validation_notes: Some("'available' means operational".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "engine".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Database engine".to_string(),
            example_values: vec!["postgres".to_string(), "mysql".to_string()],
            validation_notes: Some("Engine from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "engine_version".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::StartsWith,
            ],
            description: "Engine version".to_string(),
            example_values: vec!["16.4".to_string()],
            validation_notes: Some("EngineVersion from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "storage_encrypted".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether storage is encrypted at rest".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("StorageEncrypted from API; critical for FedRAMP".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "publicly_accessible".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the instance is publicly accessible".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("Must be false for FedRAMP boundary control".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "multi_az".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether Multi-AZ deployment is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("MultiAZ from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "deletion_protection".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether deletion protection is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("DeletionProtection from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "auto_minor_version_upgrade".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether auto minor version upgrade is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("AutoMinorVersionUpgrade from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "backup_retention_period".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Backup retention period in days".to_string(),
            example_values: vec!["7".to_string()],
            validation_notes: Some("BackupRetentionPeriod from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vpc_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "VPC the DB instance resides in".to_string(),
            example_values: vec!["vpc-0fedcba9876543210".to_string()],
            validation_notes: Some("From DBSubnetGroup.VpcId".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "db_subnet_group_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "DB subnet group name".to_string(),
            example_values: vec!["example-db-subnets".to_string()],
            validation_notes: Some("DBSubnetGroup.DBSubnetGroupName from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "iam_auth_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether IAM database authentication is enabled".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("IAMDatabaseAuthenticationEnabled from API".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "kms_key_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "KMS key ARN used for encryption".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/b2c3d4e5-f678-9012-abcd-ef3456789012"
                    .to_string(),
            ],
            validation_notes: Some("KmsKeyId from API; only present if encrypted".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual, Operation::Contains],
            description: "Value of the Name tag".to_string(),
            example_values: vec!["example-transparency-log".to_string()],
            validation_notes: Some("Extracted from TagList array".to_string()),
        });

    // RecordData
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full API response as RecordData for record check validation".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Field paths use AWS API PascalCase names (e.g., VpcSecurityGroups.0.VpcSecurityGroupId)"
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
        .insert(
            "db_instance_identifier".to_string(),
            "db_instance_identifier".to_string(),
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
        "db_instance_identifier".to_string(),
        "db_instance_status".to_string(),
        "engine".to_string(),
        "engine_version".to_string(),
        "storage_encrypted".to_string(),
        "publicly_accessible".to_string(),
        "multi_az".to_string(),
        "deletion_protection".to_string(),
        "auto_minor_version_upgrade".to_string(),
        "backup_retention_period".to_string(),
        "vpc_id".to_string(),
        "db_subnet_group_name".to_string(),
        "iam_auth_enabled".to_string(),
        "kms_key_id".to_string(),
        "tag_name".to_string(),
    ];

    for field in &[
        "found",
        "db_instance_identifier",
        "db_instance_status",
        "engine",
        "engine_version",
        "storage_encrypted",
        "publicly_accessible",
        "multi_az",
        "deletion_protection",
        "auto_minor_version_upgrade",
        "backup_retention_period",
        "vpc_id",
        "db_subnet_group_name",
        "iam_auth_enabled",
        "kms_key_id",
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
        collector_type: "aws_rds_instance".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "rds_read".to_string()],
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
