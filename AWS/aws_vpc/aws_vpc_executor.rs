//! AWS VPC Executor
//!
//! Validates AWS VPC configuration against expected state values.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_vpc;
//  pub use aws_vpc::AwsVpcExecutor;
//
//////////////////////////////////////////////////////

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

/// Executor for aws_vpc validation
pub struct AwsVpcExecutor {
    contract: CtnContract,
}

impl AwsVpcExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    /// Compare values based on type and operation
    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual) {
            // Boolean comparisons
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act)) => match operation {
                Operation::Equals => exp == act,
                Operation::NotEqual => exp != act,
                _ => false,
            },

            // String comparisons - use string::compare for all string operations
            (ResolvedValue::String(exp), ResolvedValue::String(act)) => {
                string::compare(act, exp, operation).unwrap_or(false)
            }

            // Type mismatch
            _ => false,
        }
    }
}

impl CtnExecutor for AwsVpcExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // Phase 1: Existence check
        let objects_expected = criterion.expected_object_count();
        let objects_found = collected_data.len();

        let existence_passed =
            evaluate_existence_check(test_spec.existence_check, objects_found, objects_expected);

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!(
                    "Existence check failed: expected {} VPCs, found {}",
                    objects_expected, objects_found
                ),
            )
            .with_collected_data(collected_data));
        }

        // Phase 2: State validation
        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            for state in &criterion.states {
                for field in &state.fields {
                    // Get the data field name from mapping
                    let data_field_name = self
                        .contract
                        .field_mappings
                        .validation_mappings
                        .state_to_data
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| field.name.clone());

                    // Get actual value from collected data
                    let actual_value = match data.get_field(&data_field_name) {
                        Some(v) => v.clone(),
                        None => {
                            // Field not collected - this is a failure
                            let msg = format!("Field '{}' not collected", field.name);
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("<not collected>".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("VPC '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    // Compare values
                    let passed = self.compare_values(&field.value, &actual_value, field.operation);

                    let msg = if passed {
                        format!(
                            "VPC '{}' field '{}' check passed: {:?} {:?} {:?}",
                            object_id, field.name, actual_value, field.operation, field.value
                        )
                    } else {
                        format!(
                            "VPC '{}' field '{}' check failed: expected {:?} {:?}, got {:?}",
                            object_id, field.name, field.operation, field.value, actual_value
                        )
                    };

                    if !passed {
                        failure_messages.push(msg.clone());
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

            // Combine field results using state operator
            let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
            let combined = if state_bools.is_empty() {
                true // No fields to check = pass
            } else {
                evaluate_state_operator(test_spec.state_operator, &state_bools)
            };

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "VPC '{}': {}",
                    object_id,
                    if combined { "passed" } else { "failed" }
                ),
            });
        }

        // Phase 3: Item check
        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        // Determine final status
        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = if final_status == Outcome::Pass {
            format!(
                "AWS VPC validation passed: {} of {} VPCs compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "AWS VPC validation failed:\n  - {}",
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
                "objects_total": collected_data.len(),
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "aws_vpc"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        // Validate that required fields are present
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::create_aws_vpc_contract;

    #[test]
    fn test_executor_creation() {
        let contract = create_aws_vpc_contract();
        let executor = AwsVpcExecutor::new(contract);
        assert_eq!(executor.ctn_type(), "aws_vpc");
    }

    #[test]
    fn test_compare_booleans() {
        let contract = create_aws_vpc_contract();
        let executor = AwsVpcExecutor::new(contract);

        assert!(executor.compare_values(
            &ResolvedValue::Boolean(true),
            &ResolvedValue::Boolean(true),
            Operation::Equals
        ));

        assert!(!executor.compare_values(
            &ResolvedValue::Boolean(true),
            &ResolvedValue::Boolean(false),
            Operation::Equals
        ));

        assert!(executor.compare_values(
            &ResolvedValue::Boolean(true),
            &ResolvedValue::Boolean(false),
            Operation::NotEqual
        ));
    }

    #[test]
    fn test_compare_strings() {
        let contract = create_aws_vpc_contract();
        let executor = AwsVpcExecutor::new(contract);

        assert!(executor.compare_values(
            &ResolvedValue::String("10.0.0.0/16".to_string()),
            &ResolvedValue::String("10.0.0.0/16".to_string()),
            Operation::Equals
        ));

        assert!(executor.compare_values(
            &ResolvedValue::String("10.".to_string()),
            &ResolvedValue::String("10.0.0.0/16".to_string()),
            Operation::StartsWith
        ));

        assert!(executor.compare_values(
            &ResolvedValue::String("0.0.0".to_string()),
            &ResolvedValue::String("10.0.0.0/16".to_string()),
            Operation::Contains
        ));
    }
}
