//! Service CTN Contract (Windows)

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

pub const VALID_STATES: &[&str] = &[
    "running",
    "stopped",
    "paused",
    "start_pending",
    "stop_pending",
    "continue_pending",
    "pause_pending",
    "unknown",
];

pub const VALID_START_TYPES: &[&str] = &[
    "auto",
    "auto_delayed",
    "manual",
    "disabled",
    "boot",
    "system",
    "unknown",
];

pub const VALID_SERVICE_TYPES: &[&str] = &[
    "own_process",
    "own_process_interactive",
    "share_process",
    "kernel_driver",
    "file_system_driver",
    "win32",
    "unknown",
];

/// Create the service CTN contract.
pub fn create_service_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_service".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Service name (not DisplayName)".to_string(),
            example_values: vec![
                "W32Time".to_string(),
                "Spooler".to_string(),
                "TermService".to_string(),
                "RemoteRegistry".to_string(),
            ],
            validation_notes: Some(
                "Use service name (e.g., 'W32Time') not display name (e.g., 'Windows Time')"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the service exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some(
                "Use 'exists boolean = false' to ensure a service does NOT exist".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "state".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service runtime state".to_string(),
            example_values: vec![
                "running".to_string(),
                "stopped".to_string(),
                "paused".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_STATES.join(", "))),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "start_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service startup type".to_string(),
            example_values: vec![
                "auto".to_string(),
                "auto_delayed".to_string(),
                "manual".to_string(),
                "disabled".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_START_TYPES.join(", "))),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "display_name".to_string(),
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
            description: "Service display name".to_string(),
            example_values: vec![
                "Windows Time".to_string(),
                "Print Spooler".to_string(),
                "Remote Desktop Services".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "path".to_string(),
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
            description: "Service binary path".to_string(),
            example_values: vec![
                r"C:\windows\system32\svchost.exe -k LocalService".to_string(),
                r"C:\windows\System32\spoolsv.exe".to_string(),
            ],
            validation_notes: Some("Can be used to detect service binary tampering".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "service_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Service process type".to_string(),
            example_values: vec![
                "own_process".to_string(),
                "share_process".to_string(),
                "kernel_driver".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_SERVICE_TYPES.join(", "))),
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec![
        "exists".to_string(),
        "state".to_string(),
        "start_type".to_string(),
    ];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "display_name".to_string(),
        "path".to_string(),
        "service_type".to_string(),
    ];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("state".to_string(), "state".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("start_type".to_string(), "start_type".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("display_name".to_string(), "display_name".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("path".to_string(), "path".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("service_type".to_string(), "service_type".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_service".to_string(),
        collection_mode: CollectionMode::Status,
        required_capabilities: vec!["service_query".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(200),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract.add_supported_behavior(SupportedBehavior {
        name: "executor".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "executor".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("sc".to_string()),
            description: "Collection method: sc (default) or powershell".to_string(),
        }],
        description: "Select the service collection executor".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    contract
}
