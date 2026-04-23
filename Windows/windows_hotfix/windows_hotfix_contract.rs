//! Windows HotFix CTN Contract
//!
//! Covers a single installed Windows Update / hotfix, exposed via
//! `Get-HotFix -Id <KB>`. STIG controls typically assert:
//!   - a specific KB is installed (`exists == true`)
//!   - the KB was installed within some number of days
//!   - the installer identity matches policy

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_hotfix` CTN contract.
pub fn create_hotfix_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_hotfix".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "kb_id".to_string(),
            data_type: DataType::String,
            description: "KB article identifier (e.g. KB5036893). Must start with the \
                          literal prefix 'KB' followed by ASCII digits."
                .to_string(),
            example_values: vec![
                "KB5036893".to_string(),
                "KB5034123".to_string(),
                "KB890830".to_string(),
            ],
            validation_notes: Some(
                "Passed to Get-HotFix -Id verbatim. Regex ^KB\\d+$, max 16 chars."
                    .to_string(),
            ),
        });

    // ---------------------------------------------------------------- STATE
    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::LessThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThanOrEqual,
    ];
    let str_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::NotContains,
        Operation::StartsWith,
        Operation::EndsWith,
        Operation::CaseInsensitiveEquals,
        Operation::CaseInsensitiveNotEqual,
        Operation::PatternMatch,
    ];

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "exists".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: bool_ops.clone(),
        description: "Whether the hotfix is installed. When false, all other fields \
                      are absent."
            .to_string(),
        example_values: vec!["true".to_string(), "false".to_string()],
        validation_notes: None,
    });
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "description".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Free-form description emitted by Get-HotFix (often \
                      \"Security Update\" or \"Update\")."
            .to_string(),
        example_values: vec![
            "Security Update".to_string(),
            "Update".to_string(),
            "Hotfix".to_string(),
        ],
        validation_notes: None,
    });
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "installed_on_days".to_string(),
        data_type: DataType::Int,
        allowed_operations: int_ops.clone(),
        description: "Number of whole days between the hotfix InstalledOn timestamp \
                      and the moment of collection. Positive values mean the hotfix was \
                      installed that many days ago."
            .to_string(),
        example_values: vec!["0".to_string(), "7".to_string(), "30".to_string()],
        validation_notes: None,
    });
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "installed_by".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Identity that installed the hotfix. Typically a SYSTEM or \
                      TrustedInstaller principal."
            .to_string(),
        example_values: vec![
            "NT AUTHORITY\\SYSTEM".to_string(),
            "DOMAIN\\patchadmin".to_string(),
        ],
        validation_notes: None,
    });

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("kb_id".to_string(), "kb_id".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "description".to_string(),
        "installed_on_days".to_string(),
        "installed_by".to_string(),
    ];

    for f in ["exists", "description", "installed_on_days", "installed_by"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_hotfix".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(1_000),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
