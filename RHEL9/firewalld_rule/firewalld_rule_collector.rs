//! Firewalld Rule Collector
//!
//! Runs multiple firewall-cmd subcommands:
//!   - `--state`             -> running boolean
//!   - `--query-panic`       -> panic_mode boolean
//!   - `--list-all --zone=X` -> parses key:value zone info
//!
//! If firewalld is not running, all zone fields are skipped and found=false.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod firewalld_rule;
//  pub use firewalld_rule::FirewalldRuleCollector;
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

const DEFAULT_ZONE: &str = "public";

#[derive(Clone)]
pub struct FirewalldRuleCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl FirewalldRuleCollector {
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

    /// Parse `firewall-cmd --list-all` output into key -> value map.
    /// Input format:
    ///   public (active)
    ///     target: default
    ///     services: cockpit dhcpv6-client ssh
    ///     ports:
    ///     masquerade: no
    fn parse_list_all(&self, raw: &str) -> std::collections::HashMap<String, String> {
        let mut fields = std::collections::HashMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().replace('-', "_").to_string();
                let value = line[colon + 1..].trim().to_string();
                fields.insert(key, value);
            }
        }
        fields
    }
}

impl CtnDataCollector for FirewalldRuleCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let zone = self
            .extract_string_field(object, "zone")
            .unwrap_or_else(|| DEFAULT_ZONE.to_string());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "firewalld_rule".to_string(),
            self.id.clone(),
        );

        let command_str = format!("firewall-cmd --list-all --zone={}", zone);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query firewalld zone configuration")
            .target(&zone)
            .command(&command_str)
            .input("zone", &zone)
            .build();
        data.set_method(method);

        // Check if firewalld is running
        let state_output = self
            .executor
            .execute("firewall-cmd", &["--state"], Some(Duration::from_secs(5)));

        let running = match state_output {
            Ok(out) => out.exit_code == 0 && out.stdout.trim() == "running",
            Err(_) => false,
        };

        data.add_field("running".to_string(), ResolvedValue::Boolean(running));

        if !running {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            data.add_field("panic_mode".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        // Check panic mode
        let panic_output = self.executor.execute(
            "firewall-cmd",
            &["--query-panic"],
            Some(Duration::from_secs(5)),
        );

        let panic_mode = match panic_output {
            Ok(out) => out.stdout.trim() == "yes",
            Err(_) => false,
        };
        data.add_field("panic_mode".to_string(), ResolvedValue::Boolean(panic_mode));

        // Get zone config
        let zone_arg = format!("--zone={}", zone);
        let list_output = self
            .executor
            .execute(
                "firewall-cmd",
                &["--list-all", zone_arg.as_str()],
                Some(Duration::from_secs(10)),
            )
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute firewall-cmd --list-all: {}", e),
            })?;

        if list_output.exit_code != 0 {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        let fields = self.parse_list_all(&list_output.stdout);
        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        for key in &[
            "target",
            "services",
            "ports",
            "interfaces",
            "rich_rules",
        ] {
            if let Some(val) = fields.get(*key) {
                data.add_field(key.to_string(), ResolvedValue::String(val.clone()));
            } else {
                data.add_field(key.to_string(), ResolvedValue::String(String::new()));
            }
        }

        // Derive masquerade boolean from "yes"/"no"
        let masquerade = fields
            .get("masquerade")
            .map(|v| v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);
        data.add_field("masquerade".to_string(), ResolvedValue::Boolean(masquerade));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["firewalld_rule".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "firewalld_rule" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'firewalld_rule', got '{}'",
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
