//! GNOME/dconf Setting CTN Contract
//!
//! Validates GNOME desktop settings via `gsettings get <schema> <key>`.
//! Handles both boolean and integer value types, stripping GVariant type
//! prefixes (e.g., "uint32 300" -> "300"). Reports `applicable: false`
//! when gsettings is not available (GNOME not installed).

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod dconf_setting;
//  pub use dconf_setting::create_dconf_setting_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_dconf_setting_contract() -> CtnContract {
    let mut contract = CtnContract::new("dconf_setting".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "schema".to_string(),
            data_type: DataType::String,
            description: "GSettings schema name".to_string(),
            example_values: vec![
                "org.gnome.desktop.screensaver".to_string(),
                "org.gnome.desktop.session".to_string(),
                "org.gnome.desktop.media-handling".to_string(),
            ],
            validation_notes: Some(
                "Full dotted schema name as listed by gsettings list-schemas".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "key".to_string(),
            data_type: DataType::String,
            description: "Setting key within the schema".to_string(),
            example_values: vec![
                "lock-enabled".to_string(),
                "idle-delay".to_string(),
                "automount".to_string(),
            ],
            validation_notes: Some(
                "Key name as listed by gsettings list-keys <schema>".to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "applicable".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether GNOME/gsettings is installed and the schema exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some(
                "False if gsettings is not installed or schema is not found. Policies can treat applicable=false as N/A (pass).".to_string(),
            ),
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
            ],
            description: "Current value of the setting, with GVariant type prefix stripped"
                .to_string(),
            example_values: vec![
                "true".to_string(),
                "false".to_string(),
                "300".to_string(),
                "0".to_string(),
            ],
            validation_notes: Some(
                "Type prefixes like 'uint32' are stripped. Boolean returns 'true'/'false'."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for field in &["schema", "key"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["applicable".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["value".to_string()];

    for field in &["applicable", "value"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "dconf_setting".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["gsettings_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
