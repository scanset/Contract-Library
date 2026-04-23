//! Windows Feature Executor
//!
//! Validates collected Windows-feature state against criterion
//! expectations. Handles the `exists` + `enabled` bools and the
//! `state` / `display_name` / `feature_type` strings.

use common::results::Outcome;
use execution_engine::execution::{
    comparisons::string, evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

pub struct WindowsFeatureExecutor {
    contract: CtnContract,
}

impl WindowsFeatureExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual) {
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act)) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                _ => false,
            },
            (ResolvedValue::String(exp), ResolvedValue::String(act)) => {
                string::compare(act, exp, operation).unwrap_or(false)
            }
            _ => false,
        }
    }

    fn format_operation(&self, op: Operation) -> &'static str {
        match op {
            Operation::Equals => "=",
            Operation::NotEqual => "!=",
            Operation::Contains => "contains",
            Operation::NotContains => "not_contains",
            Operation::StartsWith => "starts",
            Operation::EndsWith => "ends",
            Operation::PatternMatch => "pattern_match",
            Operation::CaseInsensitiveEquals => "ieq",
            Operation::CaseInsensitiveNotEqual => "ine",
            _ => "?",
        }
    }
}

impl CtnExecutor for WindowsFeatureExecutor {
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
                    "Existence check failed: expected {} feature objects, found {}",
                    objects_expected, objects_found
                ),
            )
            .with_collected_data(collected_data));
        }

        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            let actual_exists = data
                .get_field("exists")
                .map(|v| matches!(v, ResolvedValue::Boolean(true)))
                .unwrap_or(false);

            let exists_requirement = criterion.states.iter().find_map(|state| {
                state.fields.iter().find_map(|field| {
                    if field.name == "exists" {
                        if let ResolvedValue::Boolean(expected) = &field.value {
                            return Some((*expected, field.operation));
                        }
                    }
                    None
                })
            });

            if let Some((expected_exists, operation)) = exists_requirement {
                let exists_passed = self.compare_values(
                    &ResolvedValue::Boolean(expected_exists),
                    &ResolvedValue::Boolean(actual_exists),
                    operation,
                );

                if !exists_passed {
                    let msg = if expected_exists && !actual_exists {
                        "Windows feature not found on this host (or wrong backend)".to_string()
                    } else if !expected_exists && actual_exists {
                        "Windows feature is present but should not be".to_string()
                    } else {
                        format!(
                            "exists check failed: got {}, expected {} {}",
                            actual_exists,
                            self.format_operation(operation),
                            expected_exists
                        )
                    };

                    all_field_results.push(FieldValidationResult {
                        field_name: "exists".to_string(),
                        expected_value: ResolvedValue::Boolean(expected_exists),
                        actual_value: ResolvedValue::Boolean(actual_exists),
                        operation,
                        passed: false,
                        message: msg.clone(),
                    });
                    failure_messages.push(format!("Feature '{}': {}", object_id, msg));

                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: all_field_results,
                        combined_result: false,
                        state_operator: test_spec.state_operator,
                        message: format!("Feature '{}': failed (existence)", object_id),
                    });
                    continue;
                }
            }

            for state in &criterion.states {
                for field in &state.fields {
                    if field.name == "exists" {
                        all_field_results.push(FieldValidationResult {
                            field_name: "exists".to_string(),
                            expected_value: field.value.clone(),
                            actual_value: ResolvedValue::Boolean(actual_exists),
                            operation: field.operation,
                            passed: true,
                            message: "exists check passed".to_string(),
                        });
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
                            let msg = if !actual_exists {
                                format!(
                                    "Field '{}' not available (feature does not exist)",
                                    field.name
                                )
                            } else {
                                format!(
                                    "Field '{}' not collected (unsupported by active executor \
                                     backend, or source data was null)",
                                    field.name
                                )
                            };
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("missing".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Feature '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    let passed =
                        self.compare_values(&field.value, &actual_value, field.operation);

                    let msg = if passed {
                        format!(
                            "{} check passed: {} {} {}",
                            field.name,
                            actual_value,
                            self.format_operation(field.operation),
                            field.value
                        )
                    } else {
                        format!(
                            "{} check failed: got {}, expected {} {}",
                            field.name,
                            actual_value,
                            self.format_operation(field.operation),
                            field.value
                        )
                    };

                    if !passed {
                        failure_messages.push(format!("Feature '{}': {}", object_id, msg));
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
            let combined = if state_bools.is_empty() {
                true
            } else {
                evaluate_state_operator(test_spec.state_operator, &state_bools)
            };

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "Feature '{}': {}",
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
                "Windows feature validation passed: {} of {} features compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Windows feature validation failed:\n  - {}",
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
                "objects_total": collected_data.len()
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "windows_feature"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for data in collected_data.values() {
            if !data.has_field("exists") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "exists".to_string(),
                });
            }
        }
        Ok(())
    }
}
