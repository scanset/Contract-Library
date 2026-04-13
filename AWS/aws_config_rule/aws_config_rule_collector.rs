//! AWS Config Rule Collector
//!
//! Two API calls:
//! 1. configservice describe-config-rules --config-rule-names <name>
//! 2. configservice describe-compliance-by-config-rule --config-rule-names <name>
//!
//! RecordData merge:
//!   Rule       → describe-config-rules ConfigRules[0]
//!   Compliance → describe-compliance-by-config-rule ComplianceByConfigRules[0]
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Rule.ConfigRuleName          → "example-org-ebs-encrypted"
//! Rule.ConfigRuleState         → "ACTIVE"
//! Rule.Source.Owner            → "AWS"
//! Rule.Source.SourceIdentifier → "ENCRYPTED_VOLUMES"
//! Compliance.ComplianceType    → "COMPLIANT"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_config_rule;
//  pub use aws_config_rule::AwsConfigRuleCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsConfigRuleCollector {
    id: String,
}

impl AwsConfigRuleCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_config_rule_collector".to_string(),
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
        err_str.contains("NoSuchConfigRuleException") || err_str.contains("not found")
    }
}

impl Default for AwsConfigRuleCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsConfigRuleCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let rule_name = self
            .extract_string_field(object, "rule_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'rule_name' is required for aws_config_rule".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_config_rule".to_string(),
            self.id.clone(),
        );

        let target = format!("config-rule:{}", rule_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query AWS Config rule configuration and compliance via AWS CLI")
            .target(&target)
            .command("aws configservice describe-config-rules + describe-compliance-by-config-rule")
            .input("rule_name", &rule_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = ["--config-rule-names", rule_name.as_str()];

        let mut rule_val = serde_json::json!({});
        let mut compliance_val = serde_json::json!({});

        // Command 1: describe-config-rules
        match client.execute("configservice", "describe-config-rules", &args) {
            Ok(resp) => {
                let rule = resp
                    .get("ConfigRules")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|a| a.first())
                    .cloned();

                match rule {
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                        return Ok(data);
                    }
                    Some(r) => {
                        rule_val = r.clone();
                        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                        if let Some(v) = r
                            .get("ConfigRuleName")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "rule_name".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = r
                            .get("ConfigRuleState")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "rule_state".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(v) = r
                            .get("Description")
                            .and_then(|v: &serde_json::Value| v.as_str())
                        {
                            data.add_field(
                                "description".to_string(),
                                ResolvedValue::String(v.to_string()),
                            );
                        }
                        if let Some(src) = r.get("Source") {
                            if let Some(v) = src
                                .get("Owner")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "source_owner".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                            if let Some(v) = src
                                .get("SourceIdentifier")
                                .and_then(|v: &serde_json::Value| v.as_str())
                            {
                                data.add_field(
                                    "source_identifier".to_string(),
                                    ResolvedValue::String(v.to_string()),
                                );
                            }
                        }
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
                    return Ok(data);
                }
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-config-rules): {}", e),
                });
            }
        }

        // Command 2: describe-compliance-by-config-rule
        match client.execute("configservice", "describe-compliance-by-config-rule", &args) {
            Ok(resp) => {
                let compliance = resp
                    .get("ComplianceByConfigRules")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .and_then(|a| a.first())
                    .cloned();

                if let Some(c) = compliance {
                    if let Some(ct) = c
                        .get("Compliance")
                        .and_then(|v: &serde_json::Value| v.get("ComplianceType"))
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "compliance_type".to_string(),
                            ResolvedValue::String(ct.to_string()),
                        );
                        compliance_val = c.clone();
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (describe-compliance-by-config-rule): {}", e),
                });
            }
        }

        let merged = serde_json::json!({
            "Rule": rule_val,
            "Compliance": compliance_val,
        });
        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_config_rule".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_config_rule" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_config_rule', got '{}'",
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
            AwsConfigRuleCollector::new().collector_id(),
            "aws_config_rule_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsConfigRuleCollector::new().supported_ctn_types(),
            vec!["aws_config_rule"]
        );
    }
}
