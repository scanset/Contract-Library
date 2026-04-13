//! AWS Backup Plan Collector
//!
//! Two API calls:
//! 1. list-backup-plans  → find plan by BackupPlanName (no Python, pure AWS CLI)
//! 2. get-backup-plan    → full plan detail
//!
//! Rule-level scalars derived in-process from the Rules array.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_backup_plan;
//  pub use aws_backup_plan::AwsBackupPlanCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsBackupPlanCollector {
    id: String,
}

impl AwsBackupPlanCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_backup_plan_collector".to_string(),
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

    /// Derive rule-level scalars from the Rules array
    fn derive_rule_scalars(rules: &[serde_json::Value]) -> (bool, bool, bool, bool, i64) {
        let mut has_daily = false;
        let mut has_weekly = false;
        let mut has_monthly = false;
        let mut has_cross_region = false;
        let mut max_delete: i64 = 0;

        for rule in rules {
            let schedule = rule
                .get("ScheduleExpression")
                .and_then(|v: &serde_json::Value| v.as_str())
                .unwrap_or("");

            // Daily: runs every day — pattern has * in day-of-month and no SUN/MON etc
            // cron(0 3 * * ? *) — day-of-month is *, no specific day-of-week
            if schedule.contains("* * ? *") || schedule.contains("* * * *") {
                if !schedule.contains("SUN")
                    && !schedule.contains("MON")
                    && !schedule.contains("TUE")
                    && !schedule.contains("WED")
                    && !schedule.contains("THU")
                    && !schedule.contains("FRI")
                    && !schedule.contains("SAT")
                    && !schedule.contains("1 *")
                {
                    has_daily = true;
                }
            }

            // Weekly: contains a day-of-week abbreviation
            if schedule.contains("SUN")
                || schedule.contains("MON")
                || schedule.contains("TUE")
                || schedule.contains("WED")
                || schedule.contains("THU")
                || schedule.contains("FRI")
                || schedule.contains("SAT")
            {
                has_weekly = true;
            }

            // Monthly: day-of-month is 1 — cron(0 5 1 * ? *)
            if schedule.contains(" 1 * ? ") || schedule.contains(" 1 * ? *") {
                has_monthly = true;
            }

            // Cross-region copy
            if let Some(copies) = rule
                .get("CopyActions")
                .and_then(|v: &serde_json::Value| v.as_array())
            {
                if !copies.is_empty() {
                    has_cross_region = true;
                }
            }

            // Max delete after days
            if let Some(days) = rule
                .get("Lifecycle")
                .and_then(|lc: &serde_json::Value| lc.get("DeleteAfterDays"))
                .and_then(|v: &serde_json::Value| v.as_i64())
            {
                if days > max_delete {
                    max_delete = days;
                }
            }
        }

        (
            has_daily,
            has_weekly,
            has_monthly,
            has_cross_region,
            max_delete,
        )
    }
}

impl Default for AwsBackupPlanCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsBackupPlanCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let plan_name = self
            .extract_string_field(object, "plan_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'plan_name' is required for aws_backup_plan".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_backup_plan".to_string(),
            self.id.clone(),
        );

        let target = format!("backup-plan:{}", plan_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query AWS Backup plan configuration via AWS CLI")
            .target(&target)
            .command("aws backup list-backup-plans + get-backup-plan")
            .input("plan_name", &plan_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        // ====================================================================
        // Command 1: list-backup-plans — find plan ID by name
        // ====================================================================
        let plan_id = match client.execute("backup", "list-backup-plans", &[]) {
            Ok(resp) => {
                let plans = resp
                    .get("BackupPlansList")
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let matched = plans.iter().find(|p| {
                    p.get("BackupPlanName")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        == Some(plan_name.as_str())
                });

                match matched {
                    Some(p) => p
                        .get("BackupPlanId")
                        .and_then(|v: &serde_json::Value| v.as_str())
                        .map(|s| s.to_string()),
                    None => {
                        data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                        let empty = RecordData::from_json_value(serde_json::json!({}));
                        data.add_field(
                            "resource".to_string(),
                            ResolvedValue::RecordData(Box::new(empty)),
                        );
                        return Ok(data);
                    }
                }
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (list-backup-plans): {}", e),
                });
            }
        };

        let plan_id = match plan_id {
            Some(id) => id,
            None => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
                return Ok(data);
            }
        };

        // ====================================================================
        // Command 2: get-backup-plan
        // ====================================================================
        let plan_args = ["--backup-plan-id", plan_id.as_str()];
        match client.execute("backup", "get-backup-plan", &plan_args) {
            Ok(resp) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                if let Some(arn) = resp
                    .get("BackupPlanArn")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "plan_arn".to_string(),
                        ResolvedValue::String(arn.to_string()),
                    );
                }

                let rules = resp
                    .get("BackupPlan")
                    .and_then(|bp: &serde_json::Value| bp.get("Rules"))
                    .and_then(|v: &serde_json::Value| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                data.add_field(
                    "plan_name".to_string(),
                    ResolvedValue::String(plan_name.clone()),
                );
                data.add_field(
                    "rule_count".to_string(),
                    ResolvedValue::Integer(rules.len() as i64),
                );

                let (has_daily, has_weekly, has_monthly, has_cross_region, max_delete) =
                    Self::derive_rule_scalars(&rules);

                data.add_field(
                    "has_daily_rule".to_string(),
                    ResolvedValue::Boolean(has_daily),
                );
                data.add_field(
                    "has_weekly_rule".to_string(),
                    ResolvedValue::Boolean(has_weekly),
                );
                data.add_field(
                    "has_monthly_rule".to_string(),
                    ResolvedValue::Boolean(has_monthly),
                );
                data.add_field(
                    "has_cross_region_copy".to_string(),
                    ResolvedValue::Boolean(has_cross_region),
                );
                data.add_field(
                    "max_delete_after_days".to_string(),
                    ResolvedValue::Integer(max_delete),
                );

                let record_data = RecordData::from_json_value(resp.clone());
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(record_data)),
                );
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-backup-plan): {}", e),
                });
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_backup_plan".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_backup_plan" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_backup_plan', got '{}'",
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
            AwsBackupPlanCollector::new().collector_id(),
            "aws_backup_plan_collector"
        );
    }

    #[test]
    fn test_derive_rule_scalars_full() {
        let rules = vec![
            serde_json::json!({
                "RuleName": "daily-backup",
                "ScheduleExpression": "cron(0 3 * * ? *)",
                "Lifecycle": { "DeleteAfterDays": 30 },
                "CopyActions": [{ "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:..." }]
            }),
            serde_json::json!({
                "RuleName": "weekly-backup",
                "ScheduleExpression": "cron(0 4 ? * SUN *)",
                "Lifecycle": { "MoveToColdStorageAfterDays": 90, "DeleteAfterDays": 365 },
                "CopyActions": []
            }),
            serde_json::json!({
                "RuleName": "monthly-backup",
                "ScheduleExpression": "cron(0 5 1 * ? *)",
                "Lifecycle": { "MoveToColdStorageAfterDays": 30, "DeleteAfterDays": 2555 },
                "CopyActions": []
            }),
        ];

        let (daily, weekly, monthly, cross_region, max_delete) =
            AwsBackupPlanCollector::derive_rule_scalars(&rules);

        assert!(daily, "daily rule should be detected");
        assert!(weekly, "weekly rule should be detected");
        assert!(monthly, "monthly rule should be detected");
        assert!(cross_region, "cross-region copy should be detected");
        assert_eq!(max_delete, 2555, "max delete should be 2555");
    }

    #[test]
    fn test_derive_rule_scalars_empty() {
        let (daily, weekly, monthly, cross, max) = AwsBackupPlanCollector::derive_rule_scalars(&[]);
        assert!(!daily);
        assert!(!weekly);
        assert!(!monthly);
        assert!(!cross);
        assert_eq!(max, 0);
    }
}
