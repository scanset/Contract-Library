//! PostgreSQL Catalog Query CTN Contract
//!
//! Runs predefined queries against PostgreSQL system catalogs and returns
//! results as RecordData for field-level validation. Queries are identified
//! by name from a built-in library - arbitrary SQL is not accepted.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod pg_catalog_query;
//  pub use pg_catalog_query::create_pg_catalog_query_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_pg_catalog_query_contract() -> CtnContract {
    let mut contract = CtnContract::new("pg_catalog_query".to_string());

    // -- Object requirements ------------------------------------------

    // Required: predefined query name from the built-in library
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "query".to_string(),
            data_type: DataType::String,
            description: "Predefined query name from the built-in catalog query library".to_string(),
            example_values: vec![
                "password_hashes".to_string(),
                "installed_extensions".to_string(),
                "role_connection_limits".to_string(),
                "security_definer_functions".to_string(),
            ],
            validation_notes: Some(
                "Must match a key in the query library. Arbitrary SQL is not accepted.".to_string(),
            ),
        });

    // Optional: filter parameter passed to the query (e.g., extension name)
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "filter".to_string(),
            data_type: DataType::String,
            description: "Optional filter value for parameterized queries".to_string(),
            example_values: vec![
                "pgcrypto".to_string(),
                "pgaudit".to_string(),
            ],
            validation_notes: Some(
                "Passed as a parameter to the query. Usage depends on the query name.".to_string(),
            ),
        });

    // Optional: target database (defaults to postgres)
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "database".to_string(),
            data_type: DataType::String,
            description: "Target database name for database-scoped queries".to_string(),
            example_values: vec![
                "postgres".to_string(),
                "my_app_db".to_string(),
            ],
            validation_notes: Some(
                "Defaults to 'postgres'. Extensions and schemas are per-database.".to_string(),
            ),
        });

    // Optional: host override (defaults to 127.0.0.1)
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "host".to_string(),
            data_type: DataType::String,
            description: "PostgreSQL host".to_string(),
            example_values: vec!["127.0.0.1".to_string()],
            validation_notes: Some(
                "Defaults to 127.0.0.1 (TCP loopback).".to_string(),
            ),
        });

    // Optional: username override (defaults to postgres)
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "username".to_string(),
            data_type: DataType::String,
            description: "PostgreSQL role to connect as".to_string(),
            example_values: vec!["postgres".to_string()],
            validation_notes: Some(
                "Defaults to 'postgres'.".to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the query returned any rows".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("False if query returned zero rows or failed".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "row_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of rows returned by the query".to_string(),
            example_values: vec!["0".to_string(), "1".to_string()],
            validation_notes: Some("Use row_count = 0 to assert no findings".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![],
            description: "Query results as RecordData for field-level validation".to_string(),
            example_values: vec![],
            validation_notes: Some(
                "Use record checks to validate individual fields in query results".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for field in &["query", "filter", "database", "host", "username"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["row_count".to_string(), "record".to_string()];

    for field in &["found", "row_count", "record"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "pg_catalog_query".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["psql_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
