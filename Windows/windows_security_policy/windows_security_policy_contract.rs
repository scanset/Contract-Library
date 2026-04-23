//! Security Policy CTN Contract (Windows)
//!
//! Covers both Security Options (`[System Access]` section in a
//! `secedit /export` INF) and User Rights Assignment (`[Privilege
//! Rights]`). A single OBJECT field — `policy_name` — selects which
//! policy to read; the STATE fields compare the raw string value,
//! integer value, or member list.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_security_policy` CTN contract.
pub fn create_security_policy_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_security_policy".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "policy_name".to_string(),
            data_type: DataType::String,
            description: "Security policy or user-right name as it appears in secedit output"
                .to_string(),
            example_values: vec![
                "EnableGuestAccount".to_string(),
                "MinimumPasswordAge".to_string(),
                "LockoutBadCount".to_string(),
                "SeTrustedCredManAccessPrivilege".to_string(),
                "SeNetworkLogonRight".to_string(),
            ],
            validation_notes: Some(
                "For Security Options use the exact INF key (e.g. EnableGuestAccount). \
                 For User Rights Assignment use the Se... privilege constant name."
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
            description: "Whether the policy appears in the secedit export".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::StartsWith,
                Operation::EndsWith,
                Operation::PatternMatch,
                Operation::CaseInsensitiveEquals,
                Operation::CaseInsensitiveNotEqual,
            ],
            description: "Raw policy value as string. For User Rights this is a comma-separated \
                         list of SIDs/accounts (e.g. *S-1-5-32-544,*S-1-5-19)."
                .to_string(),
            example_values: vec![
                "0".to_string(),
                "1".to_string(),
                "".to_string(),
                "*S-1-5-32-544,*S-1-5-32-545".to_string(),
            ],
            validation_notes: Some(
                "Use `contains`/`not_contains` to check a specific SID is granted/denied a right."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value_int".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Policy value parsed as integer (for numeric Security Options)"
                .to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "15".to_string()],
            validation_notes: Some(
                "Only meaningful for Security Options whose value is a number \
                 (MinimumPasswordAge, LockoutBadCount, ...). Fails if value is non-numeric."
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "member_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of comma-separated members (accounts/SIDs) granted the right"
                .to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some(
                "Use with User Rights Assignment policies. 0 means nobody is granted the right."
                    .to_string(),
            ),
        });

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("policy_name".to_string(), "policy_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string(), "value".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value".to_string(), "value".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value_int".to_string(), "value".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("member_count".to_string(), "value".to_string());

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_security_policy".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["secedit_export".to_string()],
        performance_hints: PerformanceHints {
            // secedit writes to disk + PowerShell spawn — budget generously.
            expected_collection_time_ms: Some(1500),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            // secedit /export requires local administrator.
            requires_elevated_privileges: true,
        },
    };

    contract
}
