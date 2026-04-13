//! AWS Macie2 Account Collector
//!
//! Collects Macie2 session and classification job configuration via two or three
//! AWS CLI calls:
//! 1. get-macie-session           → session status, finding_publishing_frequency
//! 2. list-classification-jobs    → find job by bucket_name or use first job
//! 3. describe-classification-job → full job detail (when job exists)
//!
//! If `bucket_name` is provided in the object, the collector finds the first job
//! whose s3JobDefinition.bucketDefinitions[*].buckets contains that bucket.
//!
//! Tags on the classification job are a flat { "Key": "Value" } map — always
//! collected and flattened to tag_key:<Key> scalar fields when a job is found.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Session.status                                                       → "ENABLED"
//! Session.findingPublishingFrequency                                   → "FIFTEEN_MINUTES"
//! ClassificationJob.jobStatus                                          → "IDLE"
//! ClassificationJob.jobType                                            → "SCHEDULED"
//! ClassificationJob.managedDataIdentifierSelector                      → "RECOMMENDED"
//! ClassificationJob.samplingPercentage                                 → 100
//! ClassificationJob.lastRunErrorStatus.code                            → "NONE"
//! ClassificationJob.scheduleFrequency.weeklySchedule.dayOfWeek         → "MONDAY"
//! ClassificationJob.s3JobDefinition.bucketDefinitions.0.buckets.0      → "example-org-security-findings"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_macie2_account;
//  pub use aws_macie2_account::AwsMacie2AccountCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS Macie2 account and classification job configuration
pub struct AwsMacie2AccountCollector {
    id: String,
}

impl AwsMacie2AccountCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_macie2_account_collector".to_string(),
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

    fn is_not_enabled_error(err_str: &str) -> bool {
        err_str.contains("ResourceNotFoundException")
    }

    /// Returns true if the job's bucketDefinitions contain the specified bucket name
    fn job_targets_bucket(job: &serde_json::Value, bucket_name: &str) -> bool {
        job.get("bucketDefinitions")
            .and_then(|v: &serde_json::Value| v.as_array())
            .map(|defs| {
                defs.iter().any(|def| {
                    def.get("buckets")
                        .and_then(|b: &serde_json::Value| b.as_array())
                        .map(|buckets| buckets.iter().any(|b| b.as_str() == Some(bucket_name)))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }
}

impl Default for AwsMacie2AccountCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsMacie2AccountCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let region = self.extract_string_field(object, "region");
        let bucket_name = self.extract_string_field(object, "bucket_name");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_macie2_account".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = bucket_name
            .as_ref()
            .map(|b| format!("macie2:bucket:{}", b))
            .unwrap_or_else(|| "macie2:account".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description(
                "Query Macie2 session status and classification job configuration via AWS CLI",
            )
            .target(&target)
            .command("aws macie2 get-macie-session + list-classification-jobs + describe-classification-job");
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        if let Some(ref b) = bucket_name {
            method_builder = method_builder.input("bucket_name", b);
        }
        data.set_method(method_builder.build());

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut session_val = serde_json::json!({});
        let mut job_val = serde_json::json!({});

        // ====================================================================
        // Command 1: get-macie-session
        // ====================================================================
        match client.execute("macie2", "get-macie-session", &[]) {
            Ok(resp) => {
                session_val = resp.clone();

                if let Some(s) = resp
                    .get("status")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "session_status".to_string(),
                        ResolvedValue::String(s.to_string()),
                    );
                }

                if let Some(f) = resp
                    .get("findingPublishingFrequency")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "finding_publishing_frequency".to_string(),
                        ResolvedValue::String(f.to_string()),
                    );
                }

                data.add_field("found".to_string(), ResolvedValue::Boolean(true));
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_enabled_error(&err_str) {
                    data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                    let empty = RecordData::from_json_value(serde_json::json!({}));
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(empty)),
                    );
                    return Ok(data);
                }
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-macie-session): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: list-classification-jobs
        // ====================================================================
        let job_id = match client.execute("macie2", "list-classification-jobs", &[]) {
            Ok(resp) => {
                let items = resp
                    .get("items")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Find matching job — by bucket if specified, else first job
                let matched = if let Some(ref bucket) = bucket_name {
                    items
                        .iter()
                        .find(|job| Self::job_targets_bucket(job, bucket))
                } else {
                    items.first()
                };

                if let Some(job) = matched {
                    data.add_field(
                        "has_classification_job".to_string(),
                        ResolvedValue::Boolean(true),
                    );
                    job.get("jobId")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    data.add_field(
                        "has_classification_job".to_string(),
                        ResolvedValue::Boolean(false),
                    );
                    None
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-classification-jobs): {}", e),
                });
            }
        };

        // ====================================================================
        // Command 3: describe-classification-job (only when job exists)
        // ====================================================================
        if let Some(ref id) = job_id {
            let job_args = ["--job-id", id.as_str()];

            match client.execute("macie2", "describe-classification-job", &job_args) {
                Ok(resp) => {
                    job_val = resp.clone();

                    if let Some(s) = resp
                        .get("jobStatus")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "job_status".to_string(),
                            ResolvedValue::String(s.to_string()),
                        );
                    }

                    if let Some(t) = resp
                        .get("jobType")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "job_type".to_string(),
                            ResolvedValue::String(t.to_string()),
                        );
                    }

                    if let Some(n) = resp
                        .get("name")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "job_name".to_string(),
                            ResolvedValue::String(n.to_string()),
                        );
                    }

                    if let Some(m) = resp
                        .get("managedDataIdentifierSelector")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "managed_data_identifier_selector".to_string(),
                            ResolvedValue::String(m.to_string()),
                        );
                    }

                    if let Some(sp) = resp
                        .get("samplingPercentage")
                        .and_then(|v: &serde_json::Value| v.as_i64())
                    {
                        data.add_field(
                            "sampling_percentage".to_string(),
                            ResolvedValue::Integer(sp),
                        );
                    }

                    if let Some(code) = resp
                        .get("lastRunErrorStatus")
                        .and_then(|s: &serde_json::Value| s.get("code"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "last_run_error_code".to_string(),
                            ResolvedValue::String(code.to_string()),
                        );
                    }

                    if let Some(day) = resp
                        .get("scheduleFrequency")
                        .and_then(|f: &serde_json::Value| f.get("weeklySchedule"))
                        .and_then(|w: &serde_json::Value| w.get("dayOfWeek"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "schedule_day_of_week".to_string(),
                            ResolvedValue::String(day.to_string()),
                        );
                    }

                    // Tags — flat { "Key": "Value" } map on the job
                    if let Some(tags_obj) = resp
                        .get("tags")
                        .and_then(|v: &serde_json::Value| v.as_object())
                    {
                        for (key, value) in tags_obj {
                            if let Some(val_str) = value.as_str() {
                                let field_name = format!("tag_key:{}", key);
                                data.add_field(
                                    field_name,
                                    ResolvedValue::String(val_str.to_string()),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (describe-classification-job): {}", e),
                    });
                }
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Session": session_val,
            "ClassificationJob": job_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_macie2_account".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_macie2_account" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_macie2_account', got '{}'",
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
            AwsMacie2AccountCollector::new().collector_id(),
            "aws_macie2_account_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsMacie2AccountCollector::new().supported_ctn_types(),
            vec!["aws_macie2_account"]
        );
    }

    #[test]
    fn test_default() {
        let c = AwsMacie2AccountCollector::default();
        assert_eq!(c.collector_id(), "aws_macie2_account_collector");
    }

    #[test]
    fn test_is_not_enabled_error() {
        assert!(AwsMacie2AccountCollector::is_not_enabled_error(
            "ResourceNotFoundException"
        ));
        assert!(!AwsMacie2AccountCollector::is_not_enabled_error(
            "AccessDenied"
        ));
    }

    #[test]
    fn test_job_targets_bucket() {
        let job = serde_json::json!({
            "bucketDefinitions": [
                {
                    "accountId": "123456789012",
                    "buckets": ["my-security-bucket", "other-bucket"]
                }
            ]
        });
        assert!(AwsMacie2AccountCollector::job_targets_bucket(
            &job,
            "my-security-bucket"
        ));
        assert!(!AwsMacie2AccountCollector::job_targets_bucket(
            &job,
            "nonexistent-bucket"
        ));
    }
}
