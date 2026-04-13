//! AWS Config Configuration Recorder Collector
//!
//! Two API calls:
//! 1. configservice describe-configuration-recorders → recorder config
//! 2. configservice describe-configuration-recorder-status → active status

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_config_recorder;
//  pub use aws_config_recorder::AwsConfigRecorderCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsConfigRecorderCollector {
    id: String,
}

impl AwsConfigRecorderCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_config_recorder_collector".to_string(),
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

impl Default for AwsConfigRecorderCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsConfigRecorderCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let recorder_name = self
            .extract_string_field(object, "recorder_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'recorder_name' is required for aws_config_recorder".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_config_recorder".to_string(),
            self.id.clone(),
        );

        let target = format!("config-recorder:{}", recorder_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query AWS Config recorder configuration and status via AWS CLI")
            .target(&target)
            .command("aws configservice describe-configuration-recorders + describe-configuration-recorder-status")
            .input("recorder_name", &recorder_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let mut recorder_val = serde_json::json!({});
        let mut status_val = serde_json::json!({});

        // Command 1: describe-configuration-recorders
        let args = ["--configuration-recorder-names", recorder_name.as_str()];
        match client.execute("configservice", "describe-configuration-recorders", &args) {
            Ok(resp) => {
                let recorder = resp
                    .get("ConfigurationRecorders")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|a| a.first())
                    .cloned();

                match recorder {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                        return Ok(data);
                    }
                    Some(rec) => {
                        recorder_val = rec.clone();
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) =
                            rec.get("name").and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "recorder_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }

                        if let Some(rg) = rec.get("recordingGroup") {
                            if let Some(v) = rg
                                .get("allSupported")
                                .and_then(|v: &serde_json::Value| v.as_bool())
                            {
                                data.add_field(
                                    "all_supported".to_string(),
                                    ResolvedValue::Boolean(v),
                                );
                            }
                            if let Some(v) = rg
                                .get("includeGlobalResourceTypes")
                                .and_then(|v: &serde_json::Value| v.as_bool())
                            {
                                data.add_field(
                                    "include_global_resource_types".to_string(),
                                    ResolvedValue::Boolean(v),
                                );
                            }
                        }

                        if let Some(freq) = rec
                            .get("recordingMode")
                            .and_then(|m: &serde_json::Value| m.get("recordingFrequency"))
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "recording_frequency".to_string(),
                                ResolvedValue::String(freq.to_string()),
                            );
                        }
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-configuration-recorders): {}", e),
                });
            }
        }

        // Command 2: describe-configuration-recorder-status
        match client.execute(
            "configservice",
            "describe-configuration-recorder-status",
            &args,
        ) {
            Ok(resp) => {
                let status = resp
                    .get("ConfigurationRecordersStatus")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|a| a.first())
                    .cloned();

                if let Some(s) = status {
                    status_val = s.clone();

                    if let Some(v) = s
                        .get("recording")
                        .and_then(|v: &serde_json::Value| v.as_bool())
                    {
                        data.add_field("recording".to_string(), ResolvedValue::Boolean(v));
                    }
                    if let Some(v) = s
                        .get("lastStatus")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "last_status".to_string(),
                            ResolvedValue::String(v.to_string()),
                        );
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!(
                        "AWS API error (describe-configuration-recorder-status): {}",
                        e
                    ),
                });
            }
        }

        let merged = serde_json::json!({
            "Recorder": recorder_val,
            "Status": status_val,
        });
        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_config_recorder".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_config_recorder" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_config_recorder', got '{}'",
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
            AwsConfigRecorderCollector::new().collector_id(),
            "aws_config_recorder_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsConfigRecorderCollector::new().supported_ctn_types(),
            vec!["aws_config_recorder"]
        );
    }
}
