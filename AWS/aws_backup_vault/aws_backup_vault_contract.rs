//! AWS Backup Vault CTN Contract
//!
//! Validates AWS Backup vault configuration via a single AWS CLI call:
//! 1. describe-backup-vault → encryption, lock status, retention bounds
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE vault_compliant
//!     found boolean = true
//!     locked boolean = true
//!     min_retention_days int >= 7
//!     max_retention_days int >= 365
//!     encryption_key_arn string starts `arn:aws:kms:`
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_backup_vault;
//  pub use aws_backup_vault::create_aws_backup_vault_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_backup_vault_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_backup_vault".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "vault_name".to_string(),
            data_type: DataType::String,
            description: "Backup vault name (exact match)".to_string(),
            example_values: vec!["example-org-backup-vault".to_string()],
            validation_notes: Some("Required; exact vault name".to_string()),
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

    // State fields
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the backup vault was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vault_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Vault name".to_string(),
            example_values: vec!["example-org-backup-vault".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vault_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Vault ARN".to_string(),
            example_values: vec![
                "arn:aws:backup:us-east-1:123456789012:backup-vault:example-org-backup-vault"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "encryption_key_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "KMS key ARN used to encrypt the vault".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "locked".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether vault lock (WORM) is enabled".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "true when vault lock configuration has been applied and is active".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "min_retention_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Minimum retention days enforced by vault lock".to_string(),
            example_values: vec!["7".to_string()],
            validation_notes: Some("Only present when vault is locked".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "max_retention_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Maximum retention days enforced by vault lock".to_string(),
            example_values: vec!["2555".to_string()],
            validation_notes: Some("Only present when vault is locked".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "number_of_recovery_points".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::GreaterThanOrEqual,
            ],
            description: "Number of recovery points stored in the vault".to_string(),
            example_values: vec!["4".to_string()],
            validation_notes: Some("Use >= 1 to confirm backup jobs have run".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "vault_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Vault type".to_string(),
            example_values: vec!["BACKUP_VAULT".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full vault object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("vault_name".to_string(), "vault_name".to_string());
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
        "vault_name".to_string(),
        "vault_arn".to_string(),
        "encryption_key_arn".to_string(),
        "locked".to_string(),
        "min_retention_days".to_string(),
        "max_retention_days".to_string(),
        "number_of_recovery_points".to_string(),
        "vault_type".to_string(),
    ];

    for field in &[
        "found",
        "vault_name",
        "vault_arn",
        "encryption_key_arn",
        "locked",
        "min_retention_days",
        "max_retention_days",
        "number_of_recovery_points",
        "vault_type",
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
        collector_type: "aws_backup_vault".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "backup_read".to_string()],
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
