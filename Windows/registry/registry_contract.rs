//! Registry CTN Contract (Windows)

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

pub const VALID_HIVES: &[&str] = &[
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
    "HKLM",
    "HKCU",
    "HKCR",
    "HKU",
    "HKCC",
];

pub const REGISTRY_TYPES: &[&str] = &[
    "reg_sz",
    "reg_expand_sz",
    "reg_binary",
    "reg_dword",
    "reg_dword_big_endian",
    "reg_link",
    "reg_multi_sz",
    "reg_resource_list",
    "reg_full_resource_descriptor",
    "reg_resource_requirements_list",
    "reg_qword",
    "reg_none",
];

/// Create the registry CTN contract.
pub fn create_registry_contract() -> CtnContract {
    let mut contract = CtnContract::new("registry".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "hive".to_string(),
            data_type: DataType::String,
            description: "Registry hive (HKEY_LOCAL_MACHINE, HKLM, etc.)".to_string(),
            example_values: vec![
                "HKEY_LOCAL_MACHINE".to_string(),
                "HKLM".to_string(),
                "HKEY_CURRENT_USER".to_string(),
            ],
            validation_notes: Some(format!("Valid values: {}", VALID_HIVES.join(", "))),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "key".to_string(),
            data_type: DataType::String,
            description: "Registry key path (without hive prefix)".to_string(),
            example_values: vec![
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".to_string(),
                "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection".to_string(),
            ],
            validation_notes: Some("Use backslashes as path separators".to_string()),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Registry value name".to_string(),
            example_values: vec![
                "CurrentBuildNumber".to_string(),
                "AllowTelemetry".to_string(),
                "EditionId".to_string(),
            ],
            validation_notes: None,
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the registry key/value exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::CaseInsensitiveEquals,
            ],
            description: "Registry value type (only available with reg executor)".to_string(),
            example_values: vec![
                "reg_sz".to_string(),
                "reg_dword".to_string(),
                "reg_qword".to_string(),
            ],
            validation_notes: Some(format!("Valid types: {}", REGISTRY_TYPES.join(", "))),
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
            description: "Registry value as string".to_string(),
            example_values: vec!["EnterpriseS".to_string(), "26100".to_string()],
            validation_notes: Some("For string comparisons".to_string()),
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
            description: "Registry value as integer (for DWORD/QWORD)".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some("Parses string value to integer".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value_version".to_string(),
            data_type: DataType::Version,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Registry value as version (semver comparison)".to_string(),
            example_values: vec!["6.3".to_string(), "19045".to_string(), "10240".to_string()],
            validation_notes: Some("Uses semantic version comparison rules".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("hive".to_string(), "hive".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("key".to_string(), "key".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string(), "value".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["type".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("type".to_string(), "type".to_string());
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
        .insert("value_version".to_string(), "value".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_registry".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["registry_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // Behaviors
    contract.add_supported_behavior(SupportedBehavior {
        name: "executor".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "executor".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("reg".to_string()),
            description: "Collection method: reg (default) or powershell".to_string(),
        }],
        description: "Select the registry collection executor".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    // `behavior executor powershell` parses as flags=["executor","powershell"] due to
    // behavior parser treating single-word identifiers as flags. Accept both flag forms.
    contract.add_supported_behavior(SupportedBehavior {
        name: "powershell".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Parsed flag form of 'behavior executor powershell'".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    contract
}
