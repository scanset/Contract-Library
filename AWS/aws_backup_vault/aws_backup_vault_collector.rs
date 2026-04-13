//! AWS Backup Vault Collector
//!
//! Single API call: describe-backup-vault --backup-vault-name <name>
//!
//! Lock configuration (Locked, MinRetentionDays, MaxRetentionDays, LockDate)
//! is returned inline — no separate lock API call needed.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_backup_vault;
//  pub use aws_backup_vault::AwsBackupVaultCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsBackupVaultCollector {
    id: String,
}

impl AwsBackupVaultCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_backup_vault_collector".to_string(),
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    fn is_not_found_error(err_str: &str) -> bool {
        err_str.contains("ResourceNotFoundException")
    }
}

impl Default for AwsBackupVaultCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsBackupVaultCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let vault_name = self
            .extract_string_field(object, "vault_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'vault_name' is required for aws_backup_vault".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_backup_vault".to_string(),
            self.id.clone(),
        );

        let target = format!("backup-vault:{}", vault_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query AWS Backup vault configuration via AWS CLI")
            .target(&target)
            .command("aws backup describe-backup-vault")
            .input("vault_name", &vault_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--backup-vault-name", vault_name.as_str()];

        match client.execute("backup", "describe-backup-vault", &args) {
            Ok(resp) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(v) = resp
                    .get("BackupVaultName")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "vault_name".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("BackupVaultArn")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "vault_arn".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("EncryptionKeyArn")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "encryption_key_arn".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("VaultType")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "vault_type".to_string(),
                        ResolvedValue::String(v.to_string()),
                    );
                }
                if let Some(v) = resp
                    .get("Locked")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("locked".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = resp
                    .get("MinRetentionDays")
                    .and_then(|v: &serde_json::Value| v.as_i64())
                {
                    data.add_field("min_retention_days".to_string(), ResolvedValue::Integer(v));
                }
                if let Some(v) = resp
                    .get("MaxRetentionDays")
                    .and_then(|v: &serde_json::Value| v.as_i64())
                {
                    data.add_field("max_retention_days".to_string(), ResolvedValue::Integer(v));
                }
                if let Some(v) = resp
                    .get("NumberOfRecoveryPoints")
                    .and_then(|v: &serde_json::Value| v.as_i64())
                {
                    data.add_field(
                        "number_of_recovery_points".to_string(),
                        ResolvedValue::Integer(v),
                    );
                }

                let record_data = RecordData::from_json_value(resp.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_found_error(&err_str) {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                    let empty = RecordData::from_json_value(serde_json::json!({}));
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(empty)),
                    );
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (describe-backup-vault): {}", e),
                    });
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_backup_vault".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_backup_vault" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_backup_vault', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }
    fn supports_batch_collection(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_id() {
        assert_eq!(
            AwsBackupVaultCollector::new().collector_id(),
            "aws_backup_vault_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsBackupVaultCollector::new().supported_ctn_types(),
            vec!["aws_backup_vault"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsBackupVaultCollector::is_not_found_error(
            "ResourceNotFoundException"
        ));
        assert!(!AwsBackupVaultCollector::is_not_found_error("AccessDenied"));
    }
}
