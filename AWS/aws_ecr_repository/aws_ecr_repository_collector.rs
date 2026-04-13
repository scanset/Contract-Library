//! AWS ECR Repository Collector
//!
//! Collects ECR repository configuration from AWS CLI.
//! Note: ECR API uses **camelCase** field names (unlike EC2/IAM PascalCase).
//!
//! ## RecordData Field Paths
//!
//! ```text
//! repositoryName                            → "scanset/transparency-log"
//! repositoryArn                             → "arn:aws:ecr:..."
//! repositoryUri                             → "123456789012.dkr.ecr.us-east-1.amazonaws.com/scanset/transparency-log"
//! imageTagMutability                        → "IMMUTABLE"
//! imageScanningConfiguration.scanOnPush     → true
//! encryptionConfiguration.encryptionType    → "AES256"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ecr_repository;
//  pub use aws_ecr_repository::AwsEcrRepositoryCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsEcrRepositoryCollector {
    id: String,
}

impl AwsEcrRepositoryCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_ecr_repository_collector".to_string(),
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

impl Default for AwsEcrRepositoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsEcrRepositoryCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let repo_name = self
            .extract_string_field(object, "repository_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'repository_name' is required for aws_ecr_repository".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_ecr_repository".to_string(),
            self.id.clone(),
        );

        let target = format!("ecr:{}", repo_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query ECR repository configuration via AWS CLI")
            .target(&target)
            .command("aws ecr describe-repositories")
            .input("repository_name", &repo_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = vec!["--repository-names", repo_name.as_str()];
        let response = client.execute("ecr", "describe-repositories", &args);

        let repo = match response {
            Ok(resp) => resp
                .get("repositories")
                .and_then(|v: &serde_json::Value| v.as_array())
                .and_then(|a: &Vec<serde_json::Value>| a.first())
                .cloned(),
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("RepositoryNotFoundException") {
                    None
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error: {}", e),
                    });
                }
            }
        };

        if let Some(repo) = repo {
            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            if let Some(name) = repo
                .get("repositoryName")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "repository_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }
            if let Some(arn) = repo
                .get("repositoryArn")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "repository_arn".to_string(),
                    ResolvedValue::String(arn.to_string()),
                );
            }
            if let Some(itm) = repo
                .get("imageTagMutability")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "image_tag_mutability".to_string(),
                    ResolvedValue::String(itm.to_string()),
                );
            }
            if let Some(sop) = repo
                .get("imageScanningConfiguration")
                .and_then(|c: &serde_json::Value| c.get("scanOnPush"))
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field("scan_on_push".to_string(), ResolvedValue::Boolean(sop));
            }
            if let Some(et) = repo
                .get("encryptionConfiguration")
                .and_then(|c: &serde_json::Value| c.get("encryptionType"))
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "encryption_type".to_string(),
                    ResolvedValue::String(et.to_string()),
                );
            }

            let record_data = RecordData::from_json_value(repo.clone());
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
        vec!["aws_ecr_repository".to_string()]
    }
    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_ecr_repository" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_ecr_repository', got '{}'",
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
            AwsEcrRepositoryCollector::new().collector_id(),
            "aws_ecr_repository_collector"
        );
    }
    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsEcrRepositoryCollector::new().supported_ctn_types(),
            vec!["aws_ecr_repository"]
        );
    }
}
