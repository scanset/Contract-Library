//! Audit Policy CTN Contract (Windows)
//!
//! Covers Advanced Audit Policy subcategories (one per CTN object).
//! Data source: `auditpol /get /category:* /r`.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_audit_policy` CTN contract.
pub fn create_audit_policy_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_audit_policy".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "subcategory".to_string(),
            data_type: DataType::String,
            description:
                "Advanced Audit Policy subcategory name as shown by auditpol /get /category:*"
                    .to_string(),
            example_values: vec![
                "Credential Validation".to_string(),
                "Security Group Management".to_string(),
                "Sensitive Privilege Use".to_string(),
                "Logon".to_string(),
                "Process Creation".to_string(),
            ],
            validation_notes: Some(
                "Match is case-insensitive. Use the exact subcategory name (not the GUID)."
                    .to_string(),
            ),
        });

    // ---------------------------------------------------------------- STATE
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the subcategory appears in the auditpol output".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "setting".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::CaseInsensitiveEquals,
                Operation::CaseInsensitiveNotEqual,
            ],
            description: "Raw inclusion setting string".to_string(),
            example_values: vec![
                "No Auditing".to_string(),
                "Success".to_string(),
                "Failure".to_string(),
                "Success and Failure".to_string(),
            ],
            validation_notes: Some(
                "Use `contains Success` / `contains Failure` for robust matching when the STIG \
                 allows either \"Success\" or \"Success and Failure\"."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "success_audited".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "True if the subcategory audits Success events".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "failure_audited".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "True if the subcategory audits Failure events".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("subcategory".to_string(), "subcategory".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec![
        "exists".to_string(),
        "setting".to_string(),
        "success_audited".to_string(),
        "failure_audited".to_string(),
    ];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![];

    for f in [
        "exists",
        "setting",
        "success_audited",
        "failure_audited",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_audit_policy".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["auditpol_query".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: true,
        },
    };

    contract
}
