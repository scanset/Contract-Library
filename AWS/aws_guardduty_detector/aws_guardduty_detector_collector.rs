//! AWS GuardDuty Detector Collector
//!
//! Collects GuardDuty detector configuration via two or three AWS CLI calls:
//! 1. get-detector                    → status, features, data sources, tags (always)
//! 2. list-publishing-destinations    → destination existence + type (always)
//! 3. describe-publishing-destination → destination ARN + KMS key (only when destination exists)
//!
//! Tags from get-detector are a flat { "Key": "Value" } map (not a TagSet array).
//! They are always collected and flattened to tag_key:<Key> scalar fields.
//!
//! Features are indexed by Name into scalar fields: CLOUD_TRAIL → feature_cloud_trail, etc.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Detector.Status                                                                    → "ENABLED"
//! Detector.FindingPublishingFrequency                                                → "FIFTEEN_MINUTES"
//! Detector.DataSources.CloudTrail.Status                                             → "ENABLED"
//! Detector.DataSources.S3Logs.Status                                                 → "ENABLED"
//! Detector.DataSources.MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes.Status → "ENABLED"
//! Detector.Features.0.Name                                                           → "CLOUD_TRAIL"
//! Detector.Features.0.Status                                                         → "ENABLED"
//! Detector.Tags.Environment                                                          → "demo"
//! PublishingDestination.Status                                                       → "PUBLISHING"
//! PublishingDestination.DestinationProperties.DestinationArn                        → "arn:aws:s3:::..."
//! PublishingDestination.DestinationProperties.KmsKeyArn                             → "arn:aws:kms:..."
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_guardduty_detector;
//  pub use aws_guardduty_detector::AwsGuardDutyDetectorCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Maps a GuardDuty feature Name string to a snake_case scalar field name
fn feature_name_to_field(name: &str) -> String {
    format!("feature_{}", name.to_lowercase().replace('-', "_"))
}

/// Collector for AWS GuardDuty detector configuration
pub struct AwsGuardDutyDetectorCollector {
    id: String,
}

impl AwsGuardDutyDetectorCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_guardduty_detector_collector".to_string(),
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
        err_str.contains("ResourceNotFoundException") || err_str.contains("BadRequestException")
    }
}

impl Default for AwsGuardDutyDetectorCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsGuardDutyDetectorCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let detector_id = self
            .extract_string_field(object, "detector_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'detector_id' is required for aws_guardduty_detector".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_guardduty_detector".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = format!("guardduty:{}", detector_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description(
                "Query GuardDuty detector configuration and publishing destination via AWS CLI",
            )
            .target(&target)
            .command("aws guardduty get-detector + list-publishing-destinations + describe-publishing-destination")
            .input("detector_id", &detector_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let detector_args = ["--detector-id", detector_id.as_str()];

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut detector_val = serde_json::json!({});
        let mut destination_val = serde_json::json!({});

        // ====================================================================
        // Command 1: get-detector
        // ====================================================================
        match client.execute("guardduty", "get-detector", &detector_args) {
            Ok(resp) => {
                detector_val = resp.clone();

                // status
                if let Some(s) = resp
                    .get("Status")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field("status".to_string(), ResolvedValue::String(s.to_string()));
                }

                // finding_publishing_frequency
                if let Some(f) = resp
                    .get("FindingPublishingFrequency")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "finding_publishing_frequency".to_string(),
                        ResolvedValue::String(f.to_string()),
                    );
                }

                // Features array → scalar per feature
                if let Some(features) = resp
                    .get("Features")
                    .and_then(|v: &serde_json::Value| v.as_array())
                {
                    for feature in features {
                        if let (Some(name), Some(status)) = (
                            feature
                                .get("Name")
                                .and_then(|v: &serde_json::Value| v.as_str()),
                            feature
                                .get("Status")
                                .and_then(|v: &serde_json::Value| v.as_str()),
                        ) {
                            let field_name = feature_name_to_field(name);
                            data.add_field(field_name, ResolvedValue::String(status.to_string()));
                        }
                    }
                }

                // Tags — flat { "Key": "Value" } map, always present in response
                if let Some(tags_obj) = resp
                    .get("Tags")
                    .and_then(|v: &serde_json::Value| v.as_object())
                {
                    for (key, value) in tags_obj {
                        if let Some(val_str) = value.as_str() {
                            let field_name = format!("tag_key:{}", key);
                            data.add_field(field_name, ResolvedValue::String(val_str.to_string()));
                        }
                    }
                }

                data.add_field("found".to_string(), ResolvedValue::Boolean(true));
                data.add_field(
                    "detector_id".to_string(),
                    ResolvedValue::String(detector_id.clone()),
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
                    return Ok(data);
                }
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-detector): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: list-publishing-destinations
        // ====================================================================
        let destination_id =
            match client.execute("guardduty", "list-publishing-destinations", &detector_args) {
                Ok(resp) => {
                    let destinations = resp
                        .get("Destinations")
                        .and_then(|v: &serde_json::Value| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    if let Some(dest) = destinations.first() {
                        // Scalar fields from list response
                        if let Some(dt) = dest
                            .get("DestinationType")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "publishing_destination_type".to_string(),
                                ResolvedValue::String(dt.to_string()),
                            );
                        }
                        if let Some(ds) = dest
                            .get("Status")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "publishing_destination_status".to_string(),
                                ResolvedValue::String(ds.to_string()),
                            );
                        }

                        data.add_field(
                            "has_publishing_destination".to_string(),
                            ResolvedValue::Boolean(true),
                        );

                        // Return destination ID for Command 3
                        dest.get("DestinationId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .map(|s| s.to_string())
                    } else {
                        data.add_field(
                            "has_publishing_destination".to_string(),
                            ResolvedValue::Boolean(false),
                        );
                        None
                    }
                }
                Err(e) => {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (list-publishing-destinations): {}", e),
                    });
                }
            };

        // ====================================================================
        // Command 3: describe-publishing-destination (only when dest exists)
        // ====================================================================
        if let Some(dest_id) = destination_id {
            let describe_args = [
                "--detector-id",
                detector_id.as_str(),
                "--destination-id",
                dest_id.as_str(),
            ];

            match client.execute(
                "guardduty",
                "describe-publishing-destination",
                &describe_args,
            ) {
                Ok(resp) => {
                    destination_val = resp.clone();

                    if let Some(arn) = resp
                        .get("DestinationProperties")
                        .and_then(|p: &serde_json::Value| p.get("DestinationArn"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "publishing_destination_arn".to_string(),
                            ResolvedValue::String(arn.to_string()),
                        );
                    }

                    if let Some(kms) = resp
                        .get("DestinationProperties")
                        .and_then(|p: &serde_json::Value| p.get("KmsKeyArn"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "publishing_destination_kms_key_arn".to_string(),
                            ResolvedValue::String(kms.to_string()),
                        );
                    }
                }
                Err(e) => {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (describe-publishing-destination): {}", e),
                    });
                }
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Detector": detector_val,
            "PublishingDestination": destination_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_guardduty_detector".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_guardduty_detector" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_guardduty_detector', got '{}'",
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
            AwsGuardDutyDetectorCollector::new().collector_id(),
            "aws_guardduty_detector_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsGuardDutyDetectorCollector::new().supported_ctn_types(),
            vec!["aws_guardduty_detector"]
        );
    }

    #[test]
    fn test_default() {
        let c = AwsGuardDutyDetectorCollector::default();
        assert_eq!(c.collector_id(), "aws_guardduty_detector_collector");
    }

    #[test]
    fn test_feature_name_to_field() {
        assert_eq!(feature_name_to_field("CLOUD_TRAIL"), "feature_cloud_trail");
        assert_eq!(
            feature_name_to_field("EBS_MALWARE_PROTECTION"),
            "feature_ebs_malware_protection"
        );
        assert_eq!(
            feature_name_to_field("S3_DATA_EVENTS"),
            "feature_s3_data_events"
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsGuardDutyDetectorCollector::is_not_found_error(
            "ResourceNotFoundException"
        ));
        assert!(AwsGuardDutyDetectorCollector::is_not_found_error(
            "BadRequestException"
        ));
        assert!(!AwsGuardDutyDetectorCollector::is_not_found_error(
            "AccessDenied"
        ));
    }
}
