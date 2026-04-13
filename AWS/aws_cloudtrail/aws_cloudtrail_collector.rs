//! AWS CloudTrail Collector
//!
//! Collects CloudTrail trail configuration and operational status from AWS CLI.
//! Makes two API calls:
//! 1. `cloudtrail describe-trails` — trail configuration
//! 2. `cloudtrail get-trail-status` — operational state (is_logging)
//!
//! The RecordData merges both responses: trail config fields at top level,
//! plus a `Status` sub-object containing get-trail-status fields.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Name                              → "example-trail"
//! TrailARN                          → "arn:aws:cloudtrail:..."
//! S3BucketName                      → "example-org-cloudtrail-123456789012"
//! IsMultiRegionTrail                → true
//! LogFileValidationEnabled          → true
//! IncludeGlobalServiceEvents        → true
//! HomeRegion                        → "us-east-1"
//! Status.IsLogging                  → true
//! Status.StartLoggingTime           → "2026-02-23T12:56:59.288000-07:00"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_cloudtrail;
//  pub use aws_cloudtrail::AwsCloudtrailCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS CloudTrail information
pub struct AwsCloudtrailCollector {
    id: String,
}

impl AwsCloudtrailCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_cloudtrail_collector".to_string(),
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

impl Default for AwsCloudtrailCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsCloudtrailCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let trail_name = self.extract_string_field(object, "trail_name");
        let region = self.extract_string_field(object, "region");

        let client = AwsClient::new(region.clone());

        // Step 1: describe-trails
        let args: Vec<&str> = vec![];
        let response = client
            .execute("cloudtrail", "describe-trails", &args)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("AWS API error (describe-trails): {}", e),
            })?;

        let trails = response
            .get("trailList")
            .and_then(|v: &serde_json::Value| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Find matching trail
        let trail = if let Some(ref name) = trail_name {
            trails.iter().find(|t| {
                t.get("Name").and_then(|v: &serde_json::Value| v.as_str()) == Some(name.as_str())
                    || t.get("TrailARN")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        == Some(name.as_str())
            })
        } else {
            trails.first()
        };

        // Build collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_cloudtrail".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = trail_name
            .as_ref()
            .map(|n| format!("trail:{}", n))
            .unwrap_or_else(|| "trail:default".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query CloudTrail configuration and status via AWS CLI")
            .target(&target)
            .command("aws cloudtrail describe-trails + get-trail-status");

        if let Some(ref name) = trail_name {
            method_builder = method_builder.input("trail_name", name);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        if let Some(trail) = trail {
            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // Extract scalar fields from describe-trails
            if let Some(name) = trail
                .get("Name")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "trail_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }

            if let Some(arn) = trail
                .get("TrailARN")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "trail_arn".to_string(),
                    ResolvedValue::String(arn.to_string()),
                );
            }

            if let Some(bucket) = trail
                .get("S3BucketName")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "s3_bucket_name".to_string(),
                    ResolvedValue::String(bucket.to_string()),
                );
            }

            if let Some(mr) = trail
                .get("IsMultiRegionTrail")
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field("is_multi_region".to_string(), ResolvedValue::Boolean(mr));
            }

            if let Some(gse) = trail
                .get("IncludeGlobalServiceEvents")
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field(
                    "include_global_service_events".to_string(),
                    ResolvedValue::Boolean(gse),
                );
            }

            if let Some(lfv) = trail
                .get("LogFileValidationEnabled")
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field(
                    "log_file_validation_enabled".to_string(),
                    ResolvedValue::Boolean(lfv),
                );
            }

            if let Some(org) = trail
                .get("IsOrganizationTrail")
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field(
                    "is_organization_trail".to_string(),
                    ResolvedValue::Boolean(org),
                );
            }

            if let Some(hr) = trail
                .get("HomeRegion")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "home_region".to_string(),
                    ResolvedValue::String(hr.to_string()),
                );
            }

            // Step 2: get-trail-status
            // Use the trail name or ARN for the status call
            let status_name = trail
                .get("Name")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("unknown");

            let status_args = vec!["--name", status_name];
            let status_response = client
                .execute("cloudtrail", "get-trail-status", &status_args)
                .map_err(|e| CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-trail-status): {}", e),
                })?;

            // Extract is_logging from status
            if let Some(logging) = status_response
                .get("IsLogging")
                .and_then(|v: &serde_json::Value| v.as_bool())
            {
                data.add_field("is_logging".to_string(), ResolvedValue::Boolean(logging));
            }

            // Build merged RecordData: trail config + Status sub-object
            let mut merged = trail.clone();
            if let serde_json::Value::Object(ref mut map) = merged {
                map.insert("Status".to_string(), status_response);
            }

            let record_data = RecordData::from_json_value(merged);
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );

            if trails.len() > 1 && trail_name.is_none() {
                log::warn!(
                    "Multiple trails ({}) found, using first result for object '{}'",
                    trails.len(),
                    object.identifier
                );
            }
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
        vec!["aws_cloudtrail".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_cloudtrail" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_cloudtrail', got '{}'",
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
        let collector = AwsCloudtrailCollector::new();
        assert_eq!(collector.collector_id(), "aws_cloudtrail_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsCloudtrailCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_cloudtrail"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsCloudtrailCollector::default();
        assert_eq!(collector.collector_id(), "aws_cloudtrail_collector");
    }
}
