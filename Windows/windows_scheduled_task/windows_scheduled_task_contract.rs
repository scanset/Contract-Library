//! Windows Scheduled Task CTN Contract
//!
//! Covers a single scheduled task, exposed via `Get-ScheduledTask`
//! combined with `Get-ScheduledTaskInfo`. STIG controls typically
//! assert things like:
//!   - a specific task exists and is in state `Ready`
//!   - the task last ran within the last N days
//!   - the task's last result is 0 (success)

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_scheduled_task` CTN contract.
pub fn create_scheduled_task_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_scheduled_task".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "Full scheduled task path, starting with '\\'. The last \
                          segment is the task name; everything before becomes the TaskPath."
                .to_string(),
            example_values: vec![
                "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag".to_string(),
                "\\Microsoft\\Windows\\Defender\\Windows Defender Scheduled Scan".to_string(),
                "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan".to_string(),
            ],
            validation_notes: Some(
                "Path is passed to Get-ScheduledTask verbatim after splitting on the last \
                 backslash. Must begin with '\\'. Allowed chars: alphanumerics, path \
                 separators, space, dot, hyphen, underscore, parens, brackets, braces."
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

    let add_bool = |c: &mut CtnContract, name: &str, desc: &str| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: desc.to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });
    };
    let add_int = |c: &mut CtnContract, name: &str, desc: &str| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: desc.to_string(),
            example_values: vec!["0".to_string(), "1".to_string()],
            validation_notes: None,
        });
    };
    let add_str = |c: &mut CtnContract, name: &str, desc: &str, examples: Vec<&str>| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops.clone(),
            description: desc.to_string(),
            example_values: examples.into_iter().map(String::from).collect(),
            validation_notes: None,
        });
    };

    add_bool(
        &mut contract,
        "exists",
        "Whether the task resolves on this host. Missing tasks short-circuit all \
         other fields to absent",
    );
    add_str(
        &mut contract,
        "state",
        "Task state. One of: Unknown, Disabled, Queued, Ready, Running",
        vec!["Ready", "Disabled", "Running"],
    );
    add_str(
        &mut contract,
        "author",
        "Principal that authored the task definition",
        vec!["Microsoft Corporation"],
    );
    add_str(
        &mut contract,
        "description",
        "Free-form task description as stored in the task XML",
        vec!["Runs defrag on a schedule."],
    );
    add_int(
        &mut contract,
        "last_run_time_days",
        "Number of whole days between the task's LastRunTime and the moment of \
         collection. Positive means the last run was that many days ago. Absent \
         when the task has never run",
    );
    add_int(
        &mut contract,
        "next_run_time_days",
        "Number of whole days between the moment of collection and the task's \
         NextRunTime. Positive means the next run is in the past (stale), \
         negative means the next run is scheduled that many days in the future. \
         Absent when the task has no upcoming trigger",
    );
    add_int(
        &mut contract,
        "last_task_result",
        "Win32 HRESULT returned by the most recent run. 0 = success. Absent \
         when the task has never run",
    );

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "state".to_string(),
        "author".to_string(),
        "description".to_string(),
        "last_run_time_days".to_string(),
        "next_run_time_days".to_string(),
        "last_task_result".to_string(),
    ];

    for f in [
        "exists",
        "state",
        "author",
        "description",
        "last_run_time_days",
        "next_run_time_days",
        "last_task_result",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_scheduled_task".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(1_500),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
