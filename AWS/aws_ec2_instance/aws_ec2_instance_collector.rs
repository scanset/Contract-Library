//! AWS EC2 Instance Collector
//!
//! Single API call: describe-instances --instance-ids <instance_id>
//!
//! Response shape: Reservations[0].Instances[0]
//!
//! Key derived scalars:
//!   imdsv2_required      → MetadataOptions.HttpTokens == "required"
//!   has_public_ip        → PublicIpAddress present and non-empty
//!   root_volume_encrypted → looked up from describe-volumes for root device
//!                           NOTE: encryption is NOT in describe-instances response.
//!                           We derive root_volume_encrypted by checking
//!                           BlockDeviceMappings for the root device name,
//!                           then calling describe-volumes for that volume ID.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ec2_instance;
//  pub use aws_ec2_instance::AwsEc2InstanceCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsEc2InstanceCollector {
    id: String,
}

impl AwsEc2InstanceCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_ec2_instance_collector".to_string(),
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
        err_str.contains("InvalidInstanceID.NotFound")
            || err_str.contains("InvalidInstanceID.Malformed")
    }
}

impl Default for AwsEc2InstanceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsEc2InstanceCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let instance_id = self
            .extract_string_field(object, "instance_id")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'instance_id' is required for aws_ec2_instance".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_ec2_instance".to_string(),
            self.id.clone(),
        );

        let target = format!("ec2:{}", instance_id);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query EC2 instance configuration via AWS CLI")
            .target(&target)
            .command("aws ec2 describe-instances + describe-volumes")
            .input("instance_id", &instance_id);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--instance-ids", instance_id.as_str()];

        match client.execute("ec2", "describe-instances", &args) {
            Ok(resp) => {
                let instance = resp
                    .get("Reservations")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|r| r.first())
                    .and_then(|r: &serde_json::Value| r.get("Instances"))
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|i| i.first())
                    .cloned();

                match instance {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                        return Ok(data);
                    }
                    Some(inst) => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        // Basic scalars
                        if let Some(v) = inst
                            .get("InstanceId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "instance_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = inst
                            .get("InstanceType")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "instance_type".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = inst
                            .get("ImageId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "image_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = inst
                            .get("VpcId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "vpc_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = inst
                            .get("SubnetId")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "subnet_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = inst
                            .get("EbsOptimized")
                            .and_then(|v: &serde_json::Value| v.as_bool())
                        {
                            data.add_field("ebs_optimized".to_string(), ResolvedValue::Boolean(v));
                        }

                        // State
                        if let Some(v) = inst
                            .get("State")
                            .and_then(|s: &serde_json::Value| s.get("Name"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "state".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // IMDSv2
                        let http_tokens = inst
                            .get("MetadataOptions")
                            .and_then(|m: &serde_json::Value| m.get("HttpTokens"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("optional");
                        data.add_field(
                            "imdsv2_required".to_string(),
                            ResolvedValue::Boolean(http_tokens == "required"),
                        );

                        if let Some(v) = inst
                            .get("MetadataOptions")
                            .and_then(|m: &serde_json::Value| m.get("HttpPutResponseHopLimit"))
                            .and_then(|v: &serde_json::Value| v.as_i64())
                        {
                            data.add_field(
                                "metadata_hop_limit".to_string(),
                                ResolvedValue::Integer(v),
                            );
                        }

                        // Public IP
                        let has_public_ip = inst
                            .get("PublicIpAddress")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .map(|s| !s.is_empty())
                            .unwrap_or(false);
                        data.add_field(
                            "has_public_ip".to_string(),
                            ResolvedValue::Boolean(has_public_ip),
                        );

                        // IAM instance profile
                        if let Some(v) = inst
                            .get("IamInstanceProfile")
                            .and_then(|p: &serde_json::Value| p.get("Arn"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "iam_instance_profile_arn".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // First security group
                        if let Some(v) = inst
                            .get("SecurityGroups")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .and_then(|sgs| sgs.first())
                            .and_then(|sg: &serde_json::Value| sg.get("GroupId"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "security_group_id".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // Monitoring
                        if let Some(v) = inst
                            .get("Monitoring")
                            .and_then(|m: &serde_json::Value| m.get("State"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "monitoring_state".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // Boot mode
                        if let Some(v) = inst
                            .get("CurrentInstanceBootMode")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "boot_mode".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        // Tags
                        if let Some(tags) = inst
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

                        // Root volume ID from BlockDeviceMappings
                        let root_device_name = inst
                            .get("RootDeviceName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .unwrap_or("/dev/sda1");

                        let root_volume_id = inst
                            .get("BlockDeviceMappings")
                            .and_then(|v: &serde_json::Value| v.as_array())
                            .and_then(|bdms| {
                                bdms.iter().find(|bdm| {
                                    bdm.get("DeviceName")
                                        .and_then(|v: &serde_json::Value| v.as_str())
                                        == Some(root_device_name)
                                })
                            })
                            .and_then(|bdm: &serde_json::Value| bdm.get("Ebs"))
                            .and_then(|ebs: &serde_json::Value| ebs.get("VolumeId"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                            .map(|s| s.to_string());

                        // Look up root volume encryption via describe-volumes
                        if let Some(vol_id) = root_volume_id {
                            let vol_args = ["--volume-ids", vol_id.as_str()];
                            match client.execute("ec2", "describe-volumes", &vol_args) {
                                Ok(vol_resp) => {
                                    let encrypted = vol_resp
                                        .get("Volumes")
                                        .and_then(|v: &serde_json::Value| v.as_array())
                                        .and_then(|vols| vols.first())
                                        .and_then(|vol: &serde_json::Value| vol.get("Encrypted"))
                                        .and_then(|v: &serde_json::Value| v.as_bool())
                                        .unwrap_or(false);
                                    data.add_field(
                                        "root_volume_encrypted".to_string(),
                                        ResolvedValue::Boolean(encrypted),
                                    );
                                }
                                Err(_) => {
                                    // Non-fatal — don't fail collection if volume lookup fails
                                    data.add_field(
                                        "root_volume_encrypted".to_string(),
                                        ResolvedValue::Boolean(false),
                                    );
                                }
                            }
                        }

                        let record_data = RecordData::from_json_value(inst.clone());
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
                        reason: format!("AWS API error (describe-instances): {}", e),
                    });
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_ec2_instance".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_ec2_instance" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_ec2_instance', got '{}'",
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
            AwsEc2InstanceCollector::new().collector_id(),
            "aws_ec2_instance_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsEc2InstanceCollector::new().supported_ctn_types(),
            vec!["aws_ec2_instance"]
        );
    }

    #[test]
    fn test_is_not_found_error() {
        assert!(AwsEc2InstanceCollector::is_not_found_error(
            "InvalidInstanceID.NotFound"
        ));
        assert!(AwsEc2InstanceCollector::is_not_found_error(
            "InvalidInstanceID.Malformed"
        ));
        assert!(!AwsEc2InstanceCollector::is_not_found_error("AccessDenied"));
    }
}
