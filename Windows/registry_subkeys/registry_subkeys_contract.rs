//! Registry Subkeys CTN Contract (Windows)

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

/// Create the registry_subkeys CTN contract.
pub fn create_registry_subkeys_contract() -> CtnContract {
    let mut contract = CtnContract::new("registry_subkeys".to_string());

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
                "SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers".to_string(),
                "SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards".to_string(),
            ],
            validation_notes: Some("Use backslashes as path separators".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the registry key exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subkey_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of child subkeys under this key".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "5".to_string()],
            validation_notes: Some("Use >= 1 to verify at least one subkey exists".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subkeys".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Contains,
                Operation::NotContains,
                Operation::PatternMatch,
            ],
            description: "Check if a specific subkey name exists in the list".to_string(),
            example_values: vec![
                "Microsoft Usbccid Smartcard Reader".to_string(),
                "Identity Device".to_string(),
            ],
            validation_notes: Some(
                "Uses contains to check if subkey name is in the enumerated list".to_string(),
            ),
        });

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
        .required_data_fields = vec!["exists".to_string(), "subkey_count".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["subkeys".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("subkey_count".to_string(), "subkey_count".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("subkeys".to_string(), "subkeys".to_string());

    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_registry_subkeys".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["registry_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(150),
            memory_usage_mb: Some(2),
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
            default_value: Some("reg".to_string()),
            description: "Collection method: reg (default) or powershell".to_string(),
        }],
        description: "Select the registry collection executor".to_string(),
        example: "behavior executor powershell".to_string(),
    });

    contract
}
