//! AWS Inspector2 Account Collector
//!
//! Collects Inspector2 scan configuration and coverage via two AWS CLI calls:
//! 1. get-configuration → ECR rescan duration, EC2 scan mode and status
//! 2. list-coverage     → derive coverage booleans by scanning coveredResources array
//!
//! Coverage scalars derived from list-coverage:
//!   ec2_scan_active     → any AWS_EC2_INSTANCE with scanStatus.statusCode=ACTIVE
//!   ecr_scan_active     → any AWS_ECR_REPOSITORY with scanStatus.statusCode=ACTIVE
//!   network_scan_active → AWS_ACCOUNT with scanType=NETWORK and statusCode=ACTIVE
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Configuration.ecrConfiguration.rescanDurationState.rescanDuration       → "DAYS_14"
//! Configuration.ecrConfiguration.rescanDurationState.pullDateRescanMode    → "LAST_IN_USE_AT"
//! Configuration.ec2Configuration.scanModeState.scanMode                    → "EC2_HYBRID"
//! Configuration.ec2Configuration.scanModeState.scanModeStatus              → "SUCCESS"
//! Coverage.coveredResources.0.resourceType                                 → "AWS_ACCOUNT"
//! Coverage.coveredResources.0.scanType                                     → "NETWORK"
//! Coverage.coveredResources.0.scanStatus.statusCode                        → "ACTIVE"
//! Coverage.coveredResources.1.resourceType                                 → "AWS_EC2_INSTANCE"
//! Coverage.coveredResources.1.scanStatus.statusCode                        → "ACTIVE"
//! Coverage.coveredResources.1.resourceMetadata.ec2.platform                → "LINUX"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_inspector2_account;
//  pub use aws_inspector2_account::AwsInspector2AccountCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS Inspector2 account configuration and coverage
pub struct AwsInspector2AccountCollector {
    id: String,
}

impl AwsInspector2AccountCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_inspector2_account_collector".to_string(),
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
        err_str.contains("AccessDeniedException") || err_str.contains("ValidationException")
    }

    /// Derive coverage booleans from the coveredResources array
    fn derive_coverage(resources: &[serde_json::Value]) -> (bool, bool, bool) {
        let mut ec2_active = false;
        let mut ecr_active = false;
        let mut network_active = false;

        for r in resources {
            let resource_type = r
                .get("resourceType")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");
            let status_code = r
                .get("scanStatus")
                .and_then(|s: &serde_json::Value| s.get("statusCode"))
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");
            let scan_type = r
                .get("scanType")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");

            let active = status_code == "ACTIVE";

            match resource_type {
                "AWS_EC2_INSTANCE" if active => ec2_active = true,
                "AWS_ECR_REPOSITORY" if active => ecr_active = true,
                "AWS_ACCOUNT" if scan_type == "NETWORK" && active => network_active = true,
                _ => {}
            }
        }

        (ec2_active, ecr_active, network_active)
    }
}

impl Default for AwsInspector2AccountCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsInspector2AccountCollector {
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
            "aws_inspector2_account".to_string(),
            self.id.clone(),
        );

        // Traceability
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Inspector2 scan configuration and coverage status via AWS CLI")
            .target("inspector2:account")
            .command("aws inspector2 get-configuration + list-coverage");
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut configuration_val = serde_json::json!({});
        let mut coverage_val = serde_json::json!({});

        // ====================================================================
        // Command 1: get-configuration
        // ====================================================================
        match client.execute("inspector2", "get-configuration", &[]) {
            Ok(resp) => {
                configuration_val = resp.clone();

                // ECR configuration
                if let Some(ecr_duration) = resp
                    .get("ecrConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("rescanDurationState"))
                    .and_then(|s: &serde_json::Value| s.get("rescanDuration"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "ecr_rescan_duration".to_string(),
                        ResolvedValue::String(ecr_duration.to_string()),
                    );
                }

                if let Some(pull_duration) = resp
                    .get("ecrConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("rescanDurationState"))
                    .and_then(|s: &serde_json::Value| s.get("pullDateRescanDuration"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "ecr_pull_date_rescan_duration".to_string(),
                        ResolvedValue::String(pull_duration.to_string()),
                    );
                }

                if let Some(pull_mode) = resp
                    .get("ecrConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("rescanDurationState"))
                    .and_then(|s: &serde_json::Value| s.get("pullDateRescanMode"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "ecr_pull_date_rescan_mode".to_string(),
                        ResolvedValue::String(pull_mode.to_string()),
                    );
                }

                // EC2 configuration
                if let Some(scan_mode) = resp
                    .get("ec2Configuration")
                    .and_then(|c: &serde_json::Value| c.get("scanModeState"))
                    .and_then(|s: &serde_json::Value| s.get("scanMode"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "ec2_scan_mode".to_string(),
                        ResolvedValue::String(scan_mode.to_string()),
                    );
                }

                if let Some(scan_mode_status) = resp
                    .get("ec2Configuration")
                    .and_then(|c: &serde_json::Value| c.get("scanModeState"))
                    .and_then(|s: &serde_json::Value| s.get("scanModeStatus"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "ec2_scan_mode_status".to_string(),
                        ResolvedValue::String(scan_mode_status.to_string()),
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
                    reason: format!("AWS API error (get-configuration): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 2: list-coverage
        // ====================================================================
        match client.execute("inspector2", "list-coverage", &[]) {
            Ok(resp) => {
                coverage_val = resp.clone();

                let resources = resp
                    .get("coveredResources")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let count = resources.len() as i64;
                data.add_field(
                    "covered_resource_count".to_string(),
                    ResolvedValue::Integer(count),
                );

                let (ec2_active, ecr_active, network_active) = Self::derive_coverage(&resources);

                data.add_field(
                    "ec2_scan_active".to_string(),
                    ResolvedValue::Boolean(ec2_active),
                );
                data.add_field(
                    "ecr_scan_active".to_string(),
                    ResolvedValue::Boolean(ecr_active),
                );
                data.add_field(
                    "network_scan_active".to_string(),
                    ResolvedValue::Boolean(network_active),
                );
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-coverage): {}", e),
                });
            }
        }

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Configuration": configuration_val,
            "Coverage": coverage_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_inspector2_account".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_inspector2_account" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_inspector2_account', got '{}'",
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
            AwsInspector2AccountCollector::new().collector_id(),
            "aws_inspector2_account_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsInspector2AccountCollector::new().supported_ctn_types(),
            vec!["aws_inspector2_account"]
        );
    }

    #[test]
    fn test_default() {
        let c = AwsInspector2AccountCollector::default();
        assert_eq!(c.collector_id(), "aws_inspector2_account_collector");
    }

    #[test]
    fn test_is_not_enabled_error() {
        assert!(AwsInspector2AccountCollector::is_not_enabled_error(
            "AccessDeniedException"
        ));
        assert!(AwsInspector2AccountCollector::is_not_enabled_error(
            "ValidationException"
        ));
        assert!(!AwsInspector2AccountCollector::is_not_enabled_error(
            "ResourceNotFoundException"
        ));
    }

    #[test]
    fn test_derive_coverage() {
        let resources = vec![
            serde_json::json!({
                "resourceType": "AWS_ACCOUNT",
                "scanType": "NETWORK",
                "scanStatus": { "statusCode": "ACTIVE" }
            }),
            serde_json::json!({
                "resourceType": "AWS_EC2_INSTANCE",
                "scanType": "PACKAGE",
                "scanStatus": { "statusCode": "ACTIVE" }
            }),
            serde_json::json!({
                "resourceType": "AWS_ECR_REPOSITORY",
                "scanType": "PACKAGE",
                "scanStatus": { "statusCode": "INACTIVE" }
            }),
        ];

        let (ec2, ecr, network) = AwsInspector2AccountCollector::derive_coverage(&resources);
        assert!(ec2);
        assert!(!ecr); // INACTIVE
        assert!(network);
    }

    #[test]
    fn test_derive_coverage_empty() {
        let (ec2, ecr, network) = AwsInspector2AccountCollector::derive_coverage(&[]);
        assert!(!ec2);
        assert!(!ecr);
        assert!(!network);
    }
}
