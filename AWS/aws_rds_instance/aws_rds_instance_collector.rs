//! AWS RDS Instance Collector
//!
//! Collects RDS DB instance configuration from AWS CLI.
//! Returns scalar fields for common security checks and the full API
//! response as RecordData for deep inspection.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! DBInstanceIdentifier                          → "example-transparency-log"
//! DBInstanceStatus                              → "available"
//! Engine                                        → "postgres"
//! EngineVersion                                 → "16.4"
//! StorageEncrypted                              → true
//! PubliclyAccessible                            → false
//! MultiAZ                                       → false
//! DeletionProtection                            → false
//! BackupRetentionPeriod                         → 7
//! KmsKeyId                                      → "arn:aws:kms:..."
//! Endpoint.Address                              → "example-transparency-log.cmp6mwcmerdo.us-east-1.rds.amazonaws.com"
//! Endpoint.Port                                 → 5432
//! VpcSecurityGroups.0.VpcSecurityGroupId        → "sg-0bbbbbbbbbbbbbbbb0"
//! DBSubnetGroup.VpcId                           → "vpc-0fedcba9876543210"
//! DBSubnetGroup.Subnets.0.SubnetIdentifier      → "subnet-0eeeeeeeeeeeeeeee"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_rds_instance;
//  pub use aws_rds_instance::AwsRdsInstanceCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS RDS Instance information
pub struct AwsRdsInstanceCollector {
    id: String,
}

impl AwsRdsInstanceCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_rds_instance_collector".to_string(),
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
}

impl Default for AwsRdsInstanceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsRdsInstanceCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let db_id = self
            .extract_string_field(object, "db_instance_identifier")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'db_instance_identifier' is required for aws_rds_instance".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_rds_instance".to_string(),
            self.id.clone(),
        );

        let target = format!("rds:{}", db_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query RDS instance configuration via AWS CLI")
            .target(&target)
            .command("aws rds describe-db-instances")
            .input("db_instance_identifier", &db_id);

        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        let args = vec!["--db-instance-identifier", db_id.as_str()];
        let response = client.execute("rds", "describe-db-instances", &args);

        let db_instance = match response {
            Ok(resp) => resp
                .get("DBInstances")
                .and_then(|v: &serde_json::Value| v.as_array())
                .and_then(|a: &Vec<serde_json::Value>| a.first())
                .cloned(),
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("DBInstanceNotFound") {
                    None
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error: {}", e),
                    });
                }
            }
        };

        if let Some(db) = db_instance {
            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // String fields
            for (field_name, json_key) in &[
                ("db_instance_identifier", "DBInstanceIdentifier"),
                ("db_instance_status", "DBInstanceStatus"),
                ("engine", "Engine"),
                ("engine_version", "EngineVersion"),
                ("kms_key_id", "KmsKeyId"),
            ] {
                if let Some(val) = db
                    .get(*json_key)
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        field_name.to_string(),
                        ResolvedValue::String(val.to_string()),
                    );
                }
            }

            // Boolean fields
            for (field_name, json_key) in &[
                ("storage_encrypted", "StorageEncrypted"),
                ("publicly_accessible", "PubliclyAccessible"),
                ("multi_az", "MultiAZ"),
                ("deletion_protection", "DeletionProtection"),
                ("auto_minor_version_upgrade", "AutoMinorVersionUpgrade"),
                ("iam_auth_enabled", "IAMDatabaseAuthenticationEnabled"),
            ] {
                if let Some(val) = db
                    .get(*json_key)
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(field_name.to_string(), ResolvedValue::Boolean(val));
                }
            }

            // Backup retention period
            if let Some(brp) = db
                .get("BackupRetentionPeriod")
                .and_then(|v: &serde_json::Value| v.as_i64())
            {
                data.add_field(
                    "backup_retention_period".to_string(),
                    ResolvedValue::Integer(brp),
                );
            }

            // VPC ID from subnet group
            if let Some(vpc_id) = db
                .get("DBSubnetGroup")
                .and_then(|sg: &serde_json::Value| sg.get("VpcId"))
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "vpc_id".to_string(),
                    ResolvedValue::String(vpc_id.to_string()),
                );
            }

            // DB subnet group name
            if let Some(sgn) = db
                .get("DBSubnetGroup")
                .and_then(|sg: &serde_json::Value| sg.get("DBSubnetGroupName"))
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "db_subnet_group_name".to_string(),
                    ResolvedValue::String(sgn.to_string()),
                );
            }

            // Extract Name tag from TagList
            if let Some(tags) = db
                .get("TagList")
                .and_then(|v: &serde_json::Value| v.as_array())
            {
                for tag in tags {
                    if tag.get("Key").and_then(|v: &serde_json::Value| v.as_str()) == Some("Name") {
                        if let Some(name) = tag
                            .get("Value")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "tag_name".to_string(),
                                ResolvedValue::String(name.to_string()),
                            );
                        }
                    }
                }
            }

            // Full API response as RecordData
            let record_data = RecordData::from_json_value(db.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );
        } else {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_rds_instance".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_rds_instance" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_rds_instance', got '{}'",
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
        let collector = AwsRdsInstanceCollector::new();
        assert_eq!(collector.collector_id(), "aws_rds_instance_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsRdsInstanceCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_rds_instance"]);
    }
}
