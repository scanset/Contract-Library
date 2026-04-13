//! AWS EBS Volume Collector
//!
//! Single API call: describe-volumes --volume-ids <volume_id>
//! Returns Volumes[0].

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ebs_volume;
//  pub use aws_ebs_volume::AwsEbsVolumeCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsEbsVolumeCollector {
    id: String,
}

impl AwsEbsVolumeCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_ebs_volume_collector".to_string(),
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
        err_str.contains("InvalidVolume.NotFound")
    }
}

impl Default for AwsEbsVolumeCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsEbsVolumeCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let volume_id = self
            .extract_string_field(object, "volume_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'volume_id' is required for aws_ebs_volume".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_ebs_volume".to_string(),
            self.id.clone(),
        );

        let target = format!("ebs:{}", volume_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query EBS volume configuration via AWS CLI")
            .target(&target)
            .command("aws ec2 describe-volumes")
            .input("volume_id", &volume_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--volume-ids", volume_id.as_str()];

        match client.execute("ec2", "describe-volumes", &args) {
            Ok(resp) => {
                let volume = resp
                    .get("Volumes")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|vols| vols.first())
                    .cloned();

                match volume {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                    }
                    Some(vol) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = vol
                            .get("VolumeId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "volume_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = vol
                            .get("State")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "state".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = vol
                            .get("VolumeType")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "volume_type".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = vol
                            .get("AvailabilityZone")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "availability_zone".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = vol
                            .get("Encrypted")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field("encrypted".to_string(), ResolvedValue::Boolean(v));
                        }
                        if let Some(v) = vol
                            .get("KmsKeyId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "kms_key_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) =
                            vol.get("Size").and_then(|v: &serde_json::Value| v.as_i64())
                        {
                            data.add_field("size".to_string(), ResolvedValue::Integer(v));
                        }
                        if let Some(v) =
                            vol.get("Iops").and_then(|v: &serde_json::Value| v.as_i64())
                        {
                            data.add_field("iops".to_string(), ResolvedValue::Integer(v));
                        }
                        if let Some(v) = vol
                            .get("Throughput")
                            .and_then(|v: &serde_json::Value| v.as_i64())
                        {
                            data.add_field("throughput".to_string(), ResolvedValue::Integer(v));
                        }
                        if let Some(v) = vol
                            .get("MultiAttachEnabled")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field(
                                "multi_attach_enabled".to_string(),
                                ResolvedValue::Boolean(v),
                            );
                        }

                        // First attachment
                        if let Some(attachment) = vol
                            .get("Attachments")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .and_then(|a| a.first())
                        {
                            if let Some(v) = attachment
                                .get("InstanceId")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "attached_instance_id".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                            if let Some(v) = attachment
                                .get("Device")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "attached_device".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                            if let Some(v) = attachment
                                .get("DeleteOnTermination")
                                .and_then(|v: &serde_json::Value| v.as_bool())
                            {
                                data.add_field(
                                    "delete_on_termination".to_string(),
                                    ResolvedValue::Boolean(v),
                                );
                            }
                        }

                        // Tags
                        if let Some(tags) = vol
                            .get("Tags")
                            .and_then(|v: &serde_json::Value| v.as_array())
                        {
                            for tag in tags {
                                let key = tag
                                    .get("Key")
                                    .and_then(|v: &serde_json::Value| v.as_str())
                                    .unwrap_or("");
                                let val = tag
                                    .get("Value")
                                    .and_then(|v: &serde_json::Value| v.as_str())
                                    .unwrap_or("");
                                if !key.is_empty() {
                                    data.add_field(
                                        format!("tag_key:{}", key),
                                        ResolvedValue::String(val.to_string()),
                                    );
                                }
                            }
                        }

                        let record_data = RecordData::from_json_value(vol.clone());
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(record_data)),
                        );
                    }
                }
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
                        reason: format!("AWS API error (describe-volumes): {}", e),
                    });
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_ebs_volume".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_ebs_volume" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_ebs_volume', got '{}'",
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
            AwsEbsVolumeCollector::new().collector_id(),
            "aws_ebs_volume_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsEbsVolumeCollector::new().supported_ctn_types(),
            vec!["aws_ebs_volume"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsEbsVolumeCollector::is_not_found_error(
            "InvalidVolume.NotFound"
        ));
        assert!(!AwsEbsVolumeCollector::is_not_found_error("AccessDenied"));
    }
}
