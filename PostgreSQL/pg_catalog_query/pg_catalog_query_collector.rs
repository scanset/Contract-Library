//! PostgreSQL Catalog Query Collector
//!
//! Runs predefined SQL queries against PostgreSQL system catalogs.
//! Results are returned as JSON (via psql -At with field separators)
//! and parsed into RecordData for field-level validation.
//!
//! Authentication: same model as pg_config_param - TCP loopback with
//! ESP_PG_PASS -> PGPASSWORD dynamic env injection. Uses the shared
//! create_psql_executor() from commands/pg.rs.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod pg_catalog_query;
//  pub use pg_catalog_query::PgCatalogQueryCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

const DEFAULT_PG_USER: &str = "postgres";
const DEFAULT_PG_HOST: &str = "127.0.0.1";
const DEFAULT_PG_DATABASE: &str = "postgres";

/// Built-in query library. Maps query names to SQL strings.
/// All queries output JSON via psql's -At flags for machine parsing.
fn get_query_sql(query_name: &str, filter: Option<&str>) -> Option<String> {
    match query_name {
        // V-261891: Check for weak/missing password hashes
        "password_hashes" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT usename, \
             CASE WHEN passwd IS NULL THEN 'null' \
             WHEN passwd NOT LIKE 'SCRAM-SHA-256%' THEN 'weak' \
             ELSE 'scram-sha-256' END AS hash_type \
             FROM pg_shadow\
             ) t".to_string()
        ),

        // V-261857: Role connection limits
        "role_connection_limits" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT rolname, rolconnlimit FROM pg_roles \
             WHERE rolname NOT IN (\
             'pg_database_owner','pg_read_all_data','pg_write_all_data',\
             'pg_monitor','pg_read_all_settings','pg_read_all_stats',\
             'pg_stat_scan_tables','pg_read_server_files','pg_write_server_files',\
             'pg_execute_server_program','pg_signal_backend','pg_checkpoint',\
             'pg_use_reserved_connections','pg_create_subscription')\
             ) t".to_string()
        ),

        // V-261888, V-261901, V-261930, V-261931: Check installed extensions
        "installed_extensions" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT extname, extversion FROM pg_extension \
             WHERE extname != 'plpgsql'\
             ) t".to_string()
        ),

        // V-261901, V-261930, V-261931: Check if specific extension is available
        "extension_available" => {
            let ext = filter.unwrap_or("pgcrypto");
            Some(format!(
                "SELECT json_agg(row_to_json(t)) FROM (\
                 SELECT name, default_version, installed_version \
                 FROM pg_available_extensions WHERE name='{}'\
                 ) t", ext
            ))
        },

        // V-261916: Security definer functions
        "security_definer_functions" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT n.nspname, p.proname, p.prosecdef, a.rolname \
             FROM pg_proc p \
             JOIN pg_namespace n ON p.pronamespace = n.oid \
             JOIN pg_authid a ON p.proowner = a.oid \
             WHERE p.prosecdef = true \
             AND n.nspname NOT IN ('pg_catalog','information_schema')\
             ) t".to_string()
        ),

        // V-261859, V-261862, V-261890, V-261897: Role attributes
        "role_attributes" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT rolname, rolsuper, rolinherit, rolcreaterole, \
             rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit \
             FROM pg_roles \
             WHERE rolname NOT LIKE 'pg_%'\
             ) t".to_string()
        ),

        // V-261893: SSL settings from pg_settings
        "ssl_settings" => Some(
            "SELECT json_agg(row_to_json(t)) FROM (\
             SELECT name, setting FROM pg_settings \
             WHERE name IN ('ssl_ca_file','ssl_cert_file','ssl_crl_file','ssl_key_file')\
             ) t".to_string()
        ),

        _ => None,
    }
}

#[derive(Clone)]
pub struct PgCatalogQueryCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl PgCatalogQueryCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    /// Parse JSON array output from psql into RecordData
    fn parse_json_result(&self, raw: &str) -> (bool, i64, serde_json::Value) {
        let trimmed = raw.trim();

        // Empty or null result = no rows
        if trimmed.is_empty() || trimmed == "" || trimmed == "null" {
            return (false, 0, serde_json::Value::Array(vec![]));
        }

        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(serde_json::Value::Array(arr)) => {
                let count = arr.len() as i64;
                (count > 0, count, serde_json::Value::Array(arr))
            }
            Ok(val) => (true, 1, serde_json::Value::Array(vec![val])),
            Err(_) => (false, 0, serde_json::Value::Array(vec![])),
        }
    }
}

impl CtnDataCollector for PgCatalogQueryCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let query_name = self
            .extract_string_field(object, "query")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'query'".to_string(),
            })?;

        let filter = self.extract_string_field(object, "filter");
        let database = self
            .extract_string_field(object, "database")
            .unwrap_or_else(|| DEFAULT_PG_DATABASE.to_string());
        let username = self
            .extract_string_field(object, "username")
            .unwrap_or_else(|| DEFAULT_PG_USER.to_string());
        let host = self
            .extract_string_field(object, "host")
            .unwrap_or_else(|| DEFAULT_PG_HOST.to_string());

        // Look up the SQL from the query library
        let sql = get_query_sql(&query_name, filter.as_deref())
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!("Unknown query name: '{}'. Must be one of: password_hashes, \
                    role_connection_limits, installed_extensions, extension_available, \
                    security_definer_functions, role_attributes, ssl_settings", query_name),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "pg_catalog_query".to_string(),
            self.id.clone(),
        );

        let command_str = format!("psql -U {} -h {} -d {} -At -c \"{}\"", username, host, database, sql);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query PostgreSQL system catalog")
            .target(&query_name)
            .command(&command_str)
            .input("query", &query_name)
            .input("database", &database)
            .input("username", &username)
            .input("host", &host)
            .build();
        data.set_method(method);

        let args: Vec<String> = vec![
            "-U".to_string(),
            username,
            "-h".to_string(),
            host,
            "-d".to_string(),
            database,
            "-At".to_string(),
            "-c".to_string(),
            sql,
        ];

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self
            .executor
            .execute("psql", &arg_refs, Some(Duration::from_secs(15)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute psql: {}", e),
            })?;

        if output.exit_code != 0 {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            data.add_field("row_count".to_string(), ResolvedValue::Integer(0));
            return Ok(data);
        }

        let (found, row_count, json_val) = self.parse_json_result(&output.stdout);

        data.add_field("found".to_string(), ResolvedValue::Boolean(found));
        data.add_field("row_count".to_string(), ResolvedValue::Integer(row_count));

        // Store raw JSON as record data for field-level checks
        if found {
            data.add_field(
                "record".to_string(),
                ResolvedValue::String(json_val.to_string()),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["pg_catalog_query".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "pg_catalog_query" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'pg_catalog_query', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}
