//! PostgreSQL Configuration Parameter CTN Contract
//!
//! Validates PostgreSQL runtime configuration parameters via `psql -c "SHOW <param>"`.
//! Platform-agnostic: works on any OS where psql is in PATH.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod pg_config_param;
//  pub use pg_config_param::create_pg_config_param_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_pg_config_param_contract() -> CtnContract {
    let mut contract = CtnContract::new("pg_config_param".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "parameter".to_string(),
            data_type: DataType::String,
            description: "PostgreSQL configuration parameter name".to_string(),
            example_values: vec![
                "max_connections".to_string(),
                "shared_preload_libraries".to_string(),
                "log_line_prefix".to_string(),
            ],
            validation_notes: Some("Parameter name as accepted by SHOW command".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "host".to_string(),
            data_type: DataType::String,
            description: "PostgreSQL host to connect to".to_string(),
            example_values: vec![
                "127.0.0.1".to_string(),
                "db.example.com".to_string(),
            ],
            validation_notes: Some(
                "Defaults to 127.0.0.1 (TCP loopback). Use TCP to avoid peer auth OS user mismatch.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "username".to_string(),
            data_type: DataType::String,
            description: "PostgreSQL role to connect as".to_string(),
            example_values: vec!["postgres".to_string()],
            validation_notes: Some(
                "Defaults to 'postgres'. Auth via pg_hba.conf peer auth.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "connection".to_string(),
            data_type: DataType::String,
            description: "psql connection URI for remote or non-default setups".to_string(),
            example_values: vec![
                "postgresql://localhost/postgres".to_string(),
                "postgres".to_string(),
            ],
            validation_notes: Some(
                "Only needed for remote connections. Do not embed credentials.".to_string(),
            ),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the parameter exists in this PostgreSQL build".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("False if parameter is unrecognized".to_string()),
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
            description: "Current runtime value of the parameter".to_string(),
            example_values: vec![
                "100".to_string(),
                "pgaudit".to_string(),
                "scram-sha-256".to_string(),
            ],
            validation_notes: Some(
                "Raw string value as returned by SHOW; compare as string".to_string(),
            ),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("parameter".to_string(), "parameter".to_string());

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("host".to_string(), "host".to_string());

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("username".to_string(), "username".to_string());

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("connection".to_string(), "connection".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["value".to_string()];

    for field in &["found", "value"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "pg_config_param".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["psql_access".to_string()],
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
