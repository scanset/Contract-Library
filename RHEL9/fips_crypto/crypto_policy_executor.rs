//! CryptoPolicy Executor

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod crypto_policy;
//  pub use crypto_policy::CryptoPolicyExecutor;
//
//////////////////////////////////////////////////////

use common::results::Outcome;
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

pub struct CryptoPolicyExecutor {
    contract: CtnContract,
}

impl CryptoPolicyExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        op: Operation,
    ) -> bool {
        match (expected, actual, op) {
            (ResolvedValue::Boolean(e), ResolvedValue::Boolean(a), Operation::Equals) => e == a,
            (ResolvedValue::Boolean(e), ResolvedValue::Boolean(a), Operation::NotEqual) => e != a,
            (ResolvedValue::String(e), ResolvedValue::String(a), Operation::Equals) => e == a,
            (ResolvedValue::String(e), ResolvedValue::String(a), Operation::NotEqual) => e != a,
            (ResolvedValue::String(e), ResolvedValue::String(a), Operation::Contains) => {
                a.contains(e.as_str())
            }
            (ResolvedValue::String(e), ResolvedValue::String(a), Operation::StartsWith) => {
                a.starts_with(e.as_str())
            }
            (ResolvedValue::Integer(e), ResolvedValue::Integer(a), Operation::Equals) => e == a,
            (ResolvedValue::Integer(e), ResolvedValue::Integer(a), Operation::NotEqual) => e != a,
            (ResolvedValue::Integer(e), ResolvedValue::Integer(a), Operation::GreaterThan) => a > e,
            (ResolvedValue::Integer(e), ResolvedValue::Integer(a), Operation::LessThan) => a < e,
            (
                ResolvedValue::Integer(e),
                ResolvedValue::Integer(a),
                Operation::GreaterThanOrEqual,
            ) => a >= e,
            (ResolvedValue::Integer(e), ResolvedValue::Integer(a), Operation::LessThanOrEqual) => {
                a <= e
            }
            _ => false,
        }
    }
}

impl CtnExecutor for CryptoPolicyExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;
        let existence_passed = evaluate_existence_check(
            test_spec.existence_check,
            collected_data.len(),
            criterion.expected_object_count(),
        );
        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!(
                    "Existence check failed: expected {}, found {}",
                    criterion.expected_object_count(),
                    collected_data.len()
                ),
            )
            .with_collected_data(collected_data));
        }

        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            for state in &criterion.states {
                for field in &state.fields {
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
                            failure_messages.push(format!("'{}': {}", object_id, msg));
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
                        failure_messages.push(format!("'{}': {}", object_id, msg));
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
                    "'{}': {}",
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
                "crypto_policy validation passed: {} of {} compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "crypto_policy validation failed:\n  - {}",
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
            details: serde_json::json!({ "failures": failure_messages, "objects_passing": objects_passing }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }
    fn ctn_type(&self) -> &str {
        "crypto_policy"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for data in collected_data.values() {
            if !data.has_field("found")
                && !data.has_field("installed")
                && !data.has_field("enabled")
                && !data.has_field("policy_matches")
                && !data.has_field("id")
            {
                return Err(CtnExecutionError::MissingDataField {
                    field: "required field".to_string(),
                });
            }
        }
        Ok(())
    }
}
