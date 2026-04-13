//! Apache Module CTN Contract
//!
//! Checks whether a specific Apache module is loaded via `httpd -M`.
//! Returns module presence, type (static/shared), and the full module list.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod apache_module;
//  pub use apache_module::create_apache_module_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_apache_module_contract() -> CtnContract {
    let mut contract = CtnContract::new("apache_module".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "module".to_string(),
            data_type: DataType::String,
            description: "Apache module name to check".to_string(),
            example_values: vec![
                "ssl_module".to_string(),
                "log_config_module".to_string(),
                "session_module".to_string(),
                "rewrite_module".to_string(),
            ],
            validation_notes: Some(
                "Module name as shown by httpd -M (e.g., ssl_module, not mod_ssl)".to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "loaded".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the module is currently loaded".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "module_type".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
            ],
            description: "Module type: static or shared".to_string(),
            example_values: vec!["shared".to_string(), "static".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "module_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Total number of loaded modules".to_string(),
            example_values: vec!["50".to_string()],
            validation_notes: Some(
                "Use to verify module count is within expected range".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "modules_list".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Contains,
                Operation::Equals,
                Operation::NotEqual,
            ],
            description: "Full list of loaded module names, comma-separated".to_string(),
            example_values: vec![],
            validation_notes: Some(
                "Use contains to check for specific modules in the full list".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("module".to_string(), "module".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["loaded".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "module_type".to_string(),
        "module_count".to_string(),
        "modules_list".to_string(),
    ];

    for field in &["loaded", "module_type", "module_count", "modules_list"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "apache_module".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["httpd_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(200),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
