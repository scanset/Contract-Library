//! PostgreSQL Configuration Parameter Collector
//!
//! Collects runtime parameter values via `psql -U <user> -At -c "SHOW <parameter>"`.
//!
//! Authentication model:
//!   - Defaults to `-U postgres` (configurable via OBJECT `username` field)
//!   - Relies on pg_hba.conf `peer` auth for local Unix socket connections
//!   - `SystemCommandExecutor` clears ALL inherited env vars via env_clear().
//!     Only PATH and explicitly injected vars reach the spawned psql.
//!   - Password auth: if ESP_PG_PASS is set in the agent's environment,
//!     create_psql_executor() injects it as PGPASSWORD into the spawned
//!     process. The password never appears in policy files or evidence.
//!   - For K8s deployments, inject ESP_PG_PASS via Secret -> env var.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod pg_config_param;
//  pub use pg_config_param::PgConfigParamCollector;
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

/// Default PostgreSQL username
const DEFAULT_PG_USER: &str = "postgres";
/// Default host - use TCP loopback to avoid peer auth OS user mismatch
const DEFAULT_PG_HOST: &str = "127.0.0.1";

#[derive(Clone)]
pub struct PgConfigParamCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl PgConfigParamCollector {
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
}

impl CtnDataCollector for PgConfigParamCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let parameter = self
            .extract_string_field(object, "parameter")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'parameter'".to_string(),
            })?;

        let connection = self.extract_string_field(object, "connection");
        let username = self
            .extract_string_field(object, "username")
            .unwrap_or_else(|| DEFAULT_PG_USER.to_string());
        let host = self
            .extract_string_field(object, "host")
            .unwrap_or_else(|| DEFAULT_PG_HOST.to_string());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "pg_config_param".to_string(),
            self.id.clone(),
        );

        let show_sql = format!("SHOW {}", parameter);

        // Build the display command string for evidence/reproducibility
        let command_str = match &connection {
            Some(conn) => format!("psql -U {} -h {} -At -d {} -c \"{}\"", username, host, conn, show_sql),
            None => format!("psql -U {} -h {} -At -c \"{}\"", username, host, show_sql),
        };

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query PostgreSQL configuration parameter via SHOW")
            .target(&parameter)
            .command(&command_str)
            .input("parameter", &parameter)
            .input("username", &username)
            .input("host", &host)
            .build();
        data.set_method(method);

        // Build args: psql -U <user> -h <host> -At [-d <connection>] -c "SHOW <param>"
        let mut args: Vec<String> = vec![
            "-U".to_string(),
            username,
            "-h".to_string(),
            host,
            "-At".to_string(),
        ];
        if let Some(conn) = &connection {
            args.push("-d".to_string());
            args.push(conn.clone());
        }
        args.push("-c".to_string());
        args.push(show_sql);

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self
            .executor
            .execute("psql", &arg_refs, Some(Duration::from_secs(10)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute psql: {}", e),
            })?;

        if output.exit_code != 0 {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        let value = output.stdout.trim().to_string();

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("value".to_string(), ResolvedValue::String(value));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["pg_config_param".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "pg_config_param" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'pg_config_param', got '{}'",
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
