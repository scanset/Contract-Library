//! Registry Executor (Windows)

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

pub struct RegistryExecutor {
    contract: CtnContract,
}

impl RegistryExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
        field_name: &str,
    ) -> bool {
        match (expected, actual, field_name) {
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), _) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                _ => false,
            },

            (ResolvedValue::String(exp), ResolvedValue::String(act), "value_version") => {
                self.compare_versions(act, exp, operation)
            }

            (ResolvedValue::Version(exp), ResolvedValue::String(act), _) => {
                self.compare_versions(act, exp, operation)
            }

            (ResolvedValue::String(exp), ResolvedValue::String(act), _) => {
                string::compare(act, exp, operation).unwrap_or(false)
            }

            (ResolvedValue::Integer(exp), ResolvedValue::String(act), "value_int") => {
                if let Ok(act_int) = act.parse::<i64>() {
                    match operation {
                        Operation::Equals => act_int == *exp,
                        Operation::NotEqual => act_int != *exp,
                        Operation::GreaterThan => act_int > *exp,
                        Operation::LessThan => act_int < *exp,
                        Operation::GreaterThanOrEqual => act_int >= *exp,
                        Operation::LessThanOrEqual => act_int <= *exp,
                        _ => false,
                    }
                } else {
                    false
                }
            }

            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), _) => match operation {
                Operation::Equals => act == exp,
                Operation::NotEqual => act != exp,
                Operation::GreaterThan => act > exp,
                Operation::LessThan => act < exp,
                Operation::GreaterThanOrEqual => act >= exp,
                Operation::LessThanOrEqual => act <= exp,
                _ => false,
            },

            _ => false,
        }
    }

    fn compare_versions(&self, actual: &str, expected: &str, operation: Operation) -> bool {
        let parse_version = |s: &str| -> Vec<u64> {
            s.split('.')
                .filter_map(|part| part.parse::<u64>().ok())
                .collect()
        };

        let actual_parts = parse_version(actual);
        let expected_parts = parse_version(expected);
        let cmp = actual_parts.cmp(&expected_parts);

        match operation {
            Operation::Equals => cmp == std::cmp::Ordering::Equal,
            Operation::NotEqual => cmp != std::cmp::Ordering::Equal,
            Operation::GreaterThan => cmp == std::cmp::Ordering::Greater,
            Operation::LessThan => cmp == std::cmp::Ordering::Less,
            Operation::GreaterThanOrEqual => cmp != std::cmp::Ordering::Less,
            Operation::LessThanOrEqual => cmp != std::cmp::Ordering::Greater,
            _ => false,
        }
    }

    fn format_operation(&self, op: Operation) -> &'static str {
        match op {
            Operation::Equals => "=",
            Operation::NotEqual => "!=",
            Operation::GreaterThan => ">",
            Operation::LessThan => "<",
            Operation::GreaterThanOrEqual => ">=",
            Operation::LessThanOrEqual => "<=",
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

impl CtnExecutor for RegistryExecutor {
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
                    "Existence check failed: expected {} registry objects, found {}",
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
                    "exists",
                );

                if !exists_passed {
                    let msg = if expected_exists && !actual_exists {
                        "Registry key/value does not exist".to_string()
                    } else if !expected_exists && actual_exists {
                        "Registry key/value exists but should not".to_string()
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
                    failure_messages.push(format!("Registry '{}': {}", object_id, msg));

                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: all_field_results,
                        combined_result: false,
                        state_operator: test_spec.state_operator,
                        message: format!("Registry '{}': failed (key does not exist)", object_id),
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
                            if !actual_exists {
                                let msg = format!(
                                    "Field '{}' not available (key does not exist)",
                                    field.name
                                );
                                all_field_results.push(FieldValidationResult {
                                    field_name: field.name.clone(),
                                    expected_value: field.value.clone(),
                                    actual_value: ResolvedValue::String("missing".to_string()),
                                    operation: field.operation,
                                    passed: false,
                                    message: msg.clone(),
                                });
                                failure_messages.push(format!("Registry '{}': {}", object_id, msg));
                                continue;
                            }

                            let msg = format!("Field '{}' not collected", field.name);
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("missing".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Registry '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    let passed = self.compare_values(
                        &field.value,
                        &actual_value,
                        field.operation,
                        &field.name,
                    );

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
                        failure_messages.push(format!("Registry '{}': {}", object_id, msg));
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
                    "Registry '{}': {}",
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
                "Registry validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "Registry validation failed:\n  - {}",
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
        "registry"
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
            if !data.has_field("value") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "value".to_string(),
                });
            }
        }
        Ok(())
    }
}
