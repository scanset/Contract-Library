//! AWS Security Hub Account Executor
//!
//! Validates Security Hub account configurations using both scalar field checks
//! and record check validation on the merged hub + standards + aggregator response.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_securityhub_account;
//  pub use aws_securityhub_account::AwsSecurityHubAccountExecutor;
//
//////////////////////////////////////////////////////

use common::results::Outcome;
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
    record_validation::validate_record_checks,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

/// Executor for aws_securityhub_account validation
pub struct AwsSecurityHubAccountExecutor {
    contract: CtnContract,
}

impl AwsSecurityHubAccountExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual, operation) {
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::NotEqual) => {
                exp != act
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::NotEqual) => {
                exp != act
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::Contains) => {
                act.contains(exp.as_str())
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::StartsWith) => {
                act.starts_with(exp.as_str())
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::NotContains) => {
                !act.contains(exp.as_str())
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::NotEqual) => {
                exp != act
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::GreaterThan) => {
                act > exp
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::LessThan) => {
                act < exp
            }
            (
                ResolvedValue::Integer(exp),
                ResolvedValue::Integer(act),
                Operation::GreaterThanOrEqual,
            ) => act >= exp,
            (
                ResolvedValue::Integer(exp),
                ResolvedValue::Integer(act),
                Operation::LessThanOrEqual,
            ) => act <= exp,
            _ => false,
        }
    }
}

impl CtnExecutor for AwsSecurityHubAccountExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        let objects_expected = criterion.expected_object_count();
        let objects_found = collected_data.len();

        let existence_passed =
            evaluate_existence_check(test_spec.existence_check, objects_found, objects_expected);

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!(
                    "Existence check failed: expected {} Security Hub accounts, found {}",
                    objects_expected, objects_found
                ),
            )
            .with_collected_data(collected_data));
        }

        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            let resource_found = data
                .get_field("found")
                .and_then(|v| match v {
                    ResolvedValue::Boolean(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(false);

            for state in &criterion.states {
                // ============================================================
                // Record checks
                // ============================================================
                if !state.record_checks.is_empty() {
                    if !resource_found {
                        let msg =
                            "Security Hub not enabled, cannot validate record checks".to_string();
                        all_field_results.push(FieldValidationResult {
                            field_name: "record".to_string(),
                            expected_value: ResolvedValue::String("resource".to_string()),
                            actual_value: ResolvedValue::String("not found".to_string()),
                            operation: Operation::Equals,
                            passed: false,
                            message: msg.clone(),
                        });
                        failure_messages.push(format!("Hub '{}': {}", object_id, msg));
                        continue;
                    }

                    let record_data = match data.get_field("resource") {
                        Some(ResolvedValue::RecordData(rd)) => rd,
                        _ => {
                            let msg = "Resource field is not RecordData".to_string();
                            all_field_results.push(FieldValidationResult {
                                field_name: "record".to_string(),
                                expected_value: ResolvedValue::String("RecordData".to_string()),
                                actual_value: ResolvedValue::String("invalid".to_string()),
                                operation: Operation::Equals,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Hub '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    let validation_results =
                        validate_record_checks(record_data, &state.record_checks).map_err(|e| {
                            CtnExecutionError::ExecutionFailed {
                                ctn_type: criterion.criterion_type.clone(),
                                reason: format!("Record validation failed: {}", e),
                            }
                        })?;

                    for result in &validation_results {
                        all_field_results.push(FieldValidationResult {
                            field_name: result.field_path.clone(),
                            expected_value: ResolvedValue::String(
                                result.expected.clone().unwrap_or_default(),
                            ),
                            actual_value: ResolvedValue::String(
                                result.actual.clone().unwrap_or_default(),
                            ),
                            operation: Operation::Equals,
                            passed: result.passed,
                            message: result.message.clone(),
                        });

                        if !result.passed {
                            failure_messages
                                .push(format!("Hub '{}': {}", object_id, result.message));
                        }
                    }
                }

                // ============================================================
                // Scalar field checks
                // ============================================================
                for field in &state.fields {
                    if field.name == "record" {
                        continue;
                    }

                    let data_field_name = self
                        .contract
                        .field_mappings
                        .validation_mappings
                        .state_to_data
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| field.name.clone());

                    let actual_value = match data.get_field(&data_field_name) {
                        Some(v) => v.clone(),
                        None => {
                            let msg = format!("Field '{}' not collected", field.name);
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::Boolean(false),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Hub '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    let passed = self.compare_values(&field.value, &actual_value, field.operation);

                    let msg = if passed {
                        format!("Field '{}' check passed", field.name)
                    } else {
                        format!(
                            "Field '{}' check failed: expected {:?} {:?}, got {:?}",
                            field.name, field.operation, field.value, actual_value
                        )
                    };

                    if !passed {
                        failure_messages.push(format!("Hub '{}': {}", object_id, msg));
                    }

                    all_field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value,
                        operation: field.operation,
                        passed,
                        message: msg,
                    });
                }
            }

            let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
            let combined = evaluate_state_operator(test_spec.state_operator, &state_bools);

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "Security Hub '{}': {}",
                    object_id,
                    if combined { "passed" } else { "failed" }
                ),
            });
        }

        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = if final_status == Outcome::Pass {
            format!(
                "Security Hub validation passed: {} of {} accounts compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Security Hub validation failed:\n  - {}",
                failure_messages.join("\n  - ")
            )
        };

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status: final_status,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results,
            item_check_result: None,
            message,
            details: serde_json::json!({
                "failures": failure_messages,
                "objects_passing": objects_passing,
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "aws_securityhub_account"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for data in collected_data.values() {
            if !data.has_field("found") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "found".to_string(),
                });
            }
        }
        Ok(())
    }
}
