//! AWS Security Hub Account Collector
//!
//! Collects Security Hub account configuration via three or four AWS CLI calls:
//! 1. describe-hub              → hub ARN, auto_enable_controls, control_finding_generator
//! 2. get-enabled-standards     → per-standard booleans, standards_count
//! 3. list-finding-aggregators  → has_finding_aggregator, aggregator ARN
//! 4. get-finding-aggregator    → finding_aggregation_region, region_linking_mode (when aggregator exists)
//!
//! Standards are derived into boolean scalars by matching StandardsArn substrings:
//!   - "aws-foundational-security-best-practices" → standard_fsbp_enabled
//!   - "nist-800-53"                              → standard_nist_800_53_enabled
//!   - "cis-aws-foundations-benchmark"            → standard_cis_enabled
//!
//! A standard is only considered enabled when StandardsStatus == "READY".
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Hub.HubArn                                              → "arn:aws:securityhub:..."
//! Hub.AutoEnableControls                                  → true
//! Hub.ControlFindingGenerator                             → "SECURITY_CONTROL"
//! Standards.StandardsSubscriptions.0.StandardsArn         → "arn:aws:securityhub:::ruleset/cis-..."
//! Standards.StandardsSubscriptions.0.StandardsStatus      → "READY"
//! Standards.StandardsSubscriptions.1.StandardsArn         → "arn:aws:securityhub:...:standards/aws-foundational-..."
//! Standards.StandardsSubscriptions.2.StandardsArn         → "arn:aws:securityhub:...:standards/nist-800-53/..."
//! FindingAggregator.FindingAggregationRegion              → "us-east-1"
//! FindingAggregator.RegionLinkingMode                     → "ALL_REGIONS"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_securityhub_account;
//  pub use aws_securityhub_account::AwsSecurityHubAccountCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Matches a StandardsArn to a known standard and returns the scalar field name
fn standards_arn_to_field(arn: &str) -> Option<&'static str> {
    if arn.contains("aws-foundational-security-best-practices") {
        Some("standard_fsbp_enabled")
    } else if arn.contains("nist-800-53") {
        Some("standard_nist_800_53_enabled")
    } else if arn.contains("cis-aws-foundations-benchmark") {
        Some("standard_cis_enabled")
    } else {
        None
    }
}

/// Collector for AWS Security Hub account configuration
pub struct AwsSecurityHubAccountCollector {
    id: String,
}

impl AwsSecurityHubAccountCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_securityhub_account_collector".to_string(),
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
        err_str.contains("InvalidAccessException")
    }
}

impl Default for AwsSecurityHubAccountCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsSecurityHubAccountCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_securityhub_account".to_string(),
            self.id.clone(),
        );

        // Traceability
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description(
                "Query Security Hub account configuration, standards, and aggregator via AWS CLI",
            )
            .target("securityhub:account")
            .command("aws securityhub describe-hub + get-enabled-standards + list-finding-aggregators + get-finding-aggregator");
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut hub_val = serde_json::json!({});
        let mut standards_val = serde_json::json!({});
        let mut aggregator_val = serde_json::json!({});

        // ====================================================================
        // Command 1: describe-hub
        // ====================================================================
        match client.execute("securityhub", "describe-hub", &[]) {
            Ok(resp) => {
                hub_val = resp.clone();

                if let Some(arn) = resp
                    .get("HubArn")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "hub_arn".to_string(),
                        ResolvedValue::String(arn.to_string()),
                    );
                }

                if let Some(aec) = resp
                    .get("AutoEnableControls")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "auto_enable_controls".to_string(),
                        ResolvedValue::Boolean(aec),
                    );
                }

                if let Some(cfg) = resp
                    .get("ControlFindingGenerator")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "control_finding_generator".to_string(),
                        ResolvedValue::String(cfg.to_string()),
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
                    reason: format!("AWS API error (describe-hub): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: get-enabled-standards
        // ====================================================================
        match client.execute("securityhub", "get-enabled-standards", &[]) {
            Ok(resp) => {
                standards_val = resp.clone();

                let subscriptions = resp
                    .get("StandardsSubscriptions")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Initialize known standard fields to false
                data.add_field(
                    "standard_fsbp_enabled".to_string(),
                    ResolvedValue::Boolean(false),
                );
                data.add_field(
                    "standard_nist_800_53_enabled".to_string(),
                    ResolvedValue::Boolean(false),
                );
                data.add_field(
                    "standard_cis_enabled".to_string(),
                    ResolvedValue::Boolean(false),
                );

                let mut ready_count: i64 = 0;

                for sub in &subscriptions {
                    let arn = sub
                        .get("StandardsArn")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .unwrap_or("");
                    let status = sub
                        .get("StandardsStatus")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .unwrap_or("");

                    if status == "READY" {
                        ready_count += 1;

                        // Overwrite to true for any matched standard
                        if let Some(field_name) = standards_arn_to_field(arn) {
                            data.add_field(field_name.to_string(), ResolvedValue::Boolean(true));
                        }
                    }
                }

                data.add_field(
                    "standards_count".to_string(),
                    ResolvedValue::Integer(ready_count),
                );
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-enabled-standards): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 3: list-finding-aggregators
        // ====================================================================
        let aggregator_arn = match client.execute("securityhub", "list-finding-aggregators", &[]) {
            Ok(resp) => {
                let aggregators = resp
                    .get("FindingAggregators")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                if let Some(agg) = aggregators.first() {
                    data.add_field(
                        "has_finding_aggregator".to_string(),
                        ResolvedValue::Boolean(true),
                    );
                    agg.get("FindingAggregatorArn")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    data.add_field(
                        "has_finding_aggregator".to_string(),
                        ResolvedValue::Boolean(false),
                    );
                    None
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-finding-aggregators): {}", e),
                });
            }
        };

        // ====================================================================
        // Command 4: get-finding-aggregator (only when aggregator exists)
        // ====================================================================
        if let Some(arn) = aggregator_arn {
            let agg_args = ["--finding-aggregator-arn", arn.as_str()];

            match client.execute("securityhub", "get-finding-aggregator", &agg_args) {
                Ok(resp) => {
                    aggregator_val = resp.clone();

                    if let Some(region_str) = resp
                        .get("FindingAggregationRegion")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "finding_aggregation_region".to_string(),
                            ResolvedValue::String(region_str.to_string()),
                        );
                    }

                    if let Some(mode) = resp
                        .get("RegionLinkingMode")
                        .and_then(|v: &serde_json::Value| v.as_str())
                    {
                        data.add_field(
                            "finding_aggregator_region_linking_mode".to_string(),
                            ResolvedValue::String(mode.to_string()),
                        );
                    }
                }
                Err(e) => {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (get-finding-aggregator): {}", e),
                    });
                }
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Hub": hub_val,
            "Standards": standards_val,
            "FindingAggregator": aggregator_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_securityhub_account".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_securityhub_account" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_securityhub_account', got '{}'",
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
            AwsSecurityHubAccountCollector::new().collector_id(),
            "aws_securityhub_account_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsSecurityHubAccountCollector::new().supported_ctn_types(),
            vec!["aws_securityhub_account"]
        );
    }

    #[test]
    fn test_default() {
        let c = AwsSecurityHubAccountCollector::default();
        assert_eq!(c.collector_id(), "aws_securityhub_account_collector");
    }

    #[test]
    fn test_standards_arn_to_field() {
        assert_eq!(
            standards_arn_to_field(
                "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
            ),
            Some("standard_fsbp_enabled")
        );
        assert_eq!(
            standards_arn_to_field("arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"),
            Some("standard_nist_800_53_enabled")
        );
        assert_eq!(
            standards_arn_to_field(
                "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
            ),
            Some("standard_cis_enabled")
        );
        assert_eq!(
            standards_arn_to_field("arn:aws:securityhub:::unknown/standard"),
            None
        );
    }

    #[test]
    fn test_is_not_enabled_error() {
        assert!(AwsSecurityHubAccountCollector::is_not_enabled_error(
            "InvalidAccessException"
        ));
        assert!(!AwsSecurityHubAccountCollector::is_not_enabled_error(
            "AccessDenied"
        ));
    }
}
