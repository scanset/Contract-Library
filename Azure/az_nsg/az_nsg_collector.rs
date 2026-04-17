//! Azure Network Security Group (NSG) Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_nsg;
//  pub use az_nsg::AzNsgCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzNsgCollector::new(
//          "az-nsg-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzNsgExecutor::new(
//          contracts::create_az_nsg_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az network nsg show --name <name> --resource-group <rg>
//! [--subscription <id>] --output json` call. Returns scalar fields plus the
//! full response as RecordData for tag / per-rule record_checks.
//!
//! ## Behavior Modifiers
//!
//! - `include_flow_log_status true` - triggers a second API call to
//!   `az network watcher flow-log list --location <loc>` to check flow log
//!   status for this NSG. Populates `flow_log_enabled`,
//!   `flow_log_retention_enabled`, `flow_log_retention_days`,
//!   `flow_log_traffic_analytics_enabled`, `flow_log_analytics_interval_minutes`.
//!
//! ## NotFound handling
//!
//! Azure returns TWO distinct error shapes for a non-existent NSG, with TWO
//! different exit codes:
//!
//! 1. **Real RG + missing/malformed name** - exit 3, stderr contains
//!    `(ResourceNotFound)`.
//! 2. **Missing or inaccessible RG** - exit 1, stderr contains
//!    `(AuthorizationFailed)` because RBAC scoping hides the distinction
//!    between "RG does not exist" and "caller has no access to RG".
//!
//! The collector matches on stderr content (not exit code) and treats both
//! as `found=false`. The AuthorizationFailed branch is gated on the
//! `/networkSecurityGroups/` scope substring to avoid swallowing unrelated
//! RBAC failures.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzNsgCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzNsgCollector {
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

    /// Returns true when Azure's error shape matches a genuine NotFound.
    ///
    /// Matches two distinct patterns:
    /// - `(ResourceNotFound)` - real RG with missing/malformed NSG name
    /// - `(AuthorizationFailed)` scoped to `/networkSecurityGroups/` - fake or
    ///   inaccessible RG (Azure RBAC hides "forbidden" vs "missing")
    ///
    /// The AuthorizationFailed branch is additionally gated on the NSG scope
    /// substring to avoid silently swallowing unrelated RBAC failures
    /// elsewhere in the request pipeline.
    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/networksecuritygroups/") {
                return true;
            }
        }
        false
    }

    /// Returns true if any rule in the array matches Inbound + Allow + source
    /// prefix in {Internet, *, 0.0.0.0/0}. Checks both the singular
    /// sourceAddressPrefix and the plural sourceAddressPrefixes array.
    fn has_inbound_internet_allow(rules: &serde_json::Value) -> bool {
        let Some(arr) = rules.as_array() else {
            return false;
        };
        for rule in arr {
            let direction = rule.get("direction").and_then(|v| v.as_str()).unwrap_or("");
            let access = rule.get("access").and_then(|v| v.as_str()).unwrap_or("");
            if direction != "Inbound" || access != "Allow" {
                continue;
            }
            // singular
            if let Some(pfx) = rule.get("sourceAddressPrefix").and_then(|v| v.as_str()) {
                if matches!(pfx, "Internet" | "*" | "0.0.0.0/0") {
                    return true;
                }
            }
            // plural
            if let Some(pfxs) = rule.get("sourceAddressPrefixes").and_then(|v| v.as_array()) {
                for p in pfxs {
                    if let Some(s) = p.as_str() {
                        if matches!(s, "Internet" | "*" | "0.0.0.0/0") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Count rules matching a given direction + access pair.
    fn count_rules(rules: &serde_json::Value, direction: &str, access: &str) -> i64 {
        let Some(arr) = rules.as_array() else {
            return 0;
        };
        arr.iter()
            .filter(|r| {
                r.get("direction").and_then(|v| v.as_str()) == Some(direction)
                    && r.get("access").and_then(|v| v.as_str()) == Some(access)
            })
            .count() as i64
    }

    /// Returns true if a port string matches `target_port`. Handles single
    /// ports ("22"), ranges ("20-25"), and wildcard ("*").
    fn port_matches(port_str: &str, target_port: u16) -> bool {
        let s = port_str.trim();
        if s == "*" {
            return true;
        }
        if let Some((lo, hi)) = s.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                return target_port >= lo && target_port <= hi;
            }
        }
        if let Ok(p) = s.parse::<u16>() {
            return p == target_port;
        }
        false
    }

    /// Returns true if any Inbound Allow rule exposes `target_port` (or all
    /// ports via `*`) from an internet source. Checks both singular and plural
    /// prefix/port fields.
    fn has_internet_inbound_port(rules: &serde_json::Value, target_port: u16) -> bool {
        let Some(arr) = rules.as_array() else {
            return false;
        };
        for rule in arr {
            let direction = rule.get("direction").and_then(|v| v.as_str()).unwrap_or("");
            let access = rule.get("access").and_then(|v| v.as_str()).unwrap_or("");
            if direction != "Inbound" || access != "Allow" {
                continue;
            }

            // Check source is internet
            let mut from_internet = false;
            if let Some(pfx) = rule.get("sourceAddressPrefix").and_then(|v| v.as_str()) {
                if matches!(pfx, "Internet" | "*" | "0.0.0.0/0") {
                    from_internet = true;
                }
            }
            if !from_internet {
                if let Some(pfxs) = rule.get("sourceAddressPrefixes").and_then(|v| v.as_array()) {
                    for p in pfxs {
                        if let Some(s) = p.as_str() {
                            if matches!(s, "Internet" | "*" | "0.0.0.0/0") {
                                from_internet = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !from_internet {
                continue;
            }

            // Check destination port matches target
            if let Some(dp) = rule.get("destinationPortRange").and_then(|v| v.as_str()) {
                if Self::port_matches(dp, target_port) {
                    return true;
                }
            }
            if let Some(dps) = rule.get("destinationPortRanges").and_then(|v| v.as_array()) {
                for dp in dps {
                    if let Some(s) = dp.as_str() {
                        if Self::port_matches(s, target_port) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Returns true if any Inbound Allow rule allows ALL ports from internet.
    fn has_internet_inbound_all_ports(rules: &serde_json::Value) -> bool {
        let Some(arr) = rules.as_array() else {
            return false;
        };
        for rule in arr {
            let direction = rule.get("direction").and_then(|v| v.as_str()).unwrap_or("");
            let access = rule.get("access").and_then(|v| v.as_str()).unwrap_or("");
            if direction != "Inbound" || access != "Allow" {
                continue;
            }

            let mut from_internet = false;
            if let Some(pfx) = rule.get("sourceAddressPrefix").and_then(|v| v.as_str()) {
                if matches!(pfx, "Internet" | "*" | "0.0.0.0/0") {
                    from_internet = true;
                }
            }
            if !from_internet {
                if let Some(pfxs) = rule.get("sourceAddressPrefixes").and_then(|v| v.as_array()) {
                    for p in pfxs {
                        if let Some(s) = p.as_str() {
                            if matches!(s, "Internet" | "*" | "0.0.0.0/0") {
                                from_internet = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !from_internet {
                continue;
            }

            // All ports check: destinationPortRange == "*"
            if let Some(dp) = rule.get("destinationPortRange").and_then(|v| v.as_str()) {
                if dp == "*" {
                    return true;
                }
            }
        }
        false
    }

    /// Extract flow log fields from `az network watcher flow-log list` response.
    /// The response is an array of flow log configs; we look for one whose
    /// targetResourceId matches the NSG id.
    fn extract_flow_log_fields(resp: &serde_json::Value, nsg_id: &str, data: &mut CollectedData) {
        let arr = match resp.as_array() {
            Some(a) => a,
            None => {
                data.add_field(
                    "flow_log_enabled".to_string(),
                    ResolvedValue::Boolean(false),
                );
                return;
            }
        };

        // Find flow log config matching this NSG (case-insensitive compare on ARM IDs)
        let nsg_id_lower = nsg_id.to_lowercase();
        let flow_log = arr.iter().find(|fl| {
            fl.get("targetResourceId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase() == nsg_id_lower)
                .unwrap_or(false)
        });

        match flow_log {
            Some(fl) => {
                let enabled = fl
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                data.add_field(
                    "flow_log_enabled".to_string(),
                    ResolvedValue::Boolean(enabled),
                );

                // Retention policy
                if let Some(ret) = fl.get("retentionPolicy") {
                    let ret_enabled = ret
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    data.add_field(
                        "flow_log_retention_enabled".to_string(),
                        ResolvedValue::Boolean(ret_enabled),
                    );
                    if let Some(days) = ret.get("days").and_then(|v| v.as_i64()) {
                        data.add_field(
                            "flow_log_retention_days".to_string(),
                            ResolvedValue::Integer(days),
                        );
                    }
                }

                // Traffic analytics
                if let Some(fa) = fl.get("flowAnalyticsConfiguration") {
                    if let Some(nwa) = fa.get("networkWatcherFlowAnalyticsConfiguration") {
                        let ta_enabled = nwa
                            .get("enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        data.add_field(
                            "flow_log_traffic_analytics_enabled".to_string(),
                            ResolvedValue::Boolean(ta_enabled),
                        );
                        if let Some(interval) =
                            nwa.get("trafficAnalyticsInterval").and_then(|v| v.as_i64())
                        {
                            data.add_field(
                                "flow_log_analytics_interval_minutes".to_string(),
                                ResolvedValue::Integer(interval),
                            );
                        }
                    }
                }
            }
            None => {
                // No flow log configured for this NSG
                data.add_field(
                    "flow_log_enabled".to_string(),
                    ResolvedValue::Boolean(false),
                );
            }
        }
    }
}

impl CtnDataCollector for AzNsgCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let name = self.extract_string_field(object, "name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'name' is required for az_nsg".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_nsg (az network nsg show \
                            requires -g)"
                        .to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_nsg".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "network".to_string(),
            "nsg".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
            "--resource-group".to_string(),
            resource_group.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));

        let target = format!("nsg:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Network Security Group via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name)
            .input("resource_group", &resource_group);
        if let Some(ref sub) = subscription {
            method_builder = method_builder.input("subscription", sub);
        }
        data.set_method(method_builder.build());

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = self
            .executor
            .execute("az", &arg_refs, Some(Duration::from_secs(30)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute az: {}", e),
            })?;

        if output.exit_code != 0 {
            if Self::is_not_found(&output.stderr) {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty)),
                );
                return Ok(data);
            }
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az network nsg show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az network nsg show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("resourceGuid", "resource_guid"),
            ("etag", "etag"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // Rule arrays
        let empty_arr = serde_json::Value::Array(Vec::new());
        let security_rules = resp.get("securityRules").unwrap_or(&empty_arr);
        let default_rules = resp.get("defaultSecurityRules").unwrap_or(&empty_arr);

        let sec_count = security_rules.as_array().map(|a| a.len()).unwrap_or(0) as i64;
        let def_count = default_rules.as_array().map(|a| a.len()).unwrap_or(0) as i64;

        data.add_field(
            "security_rule_count".to_string(),
            ResolvedValue::Integer(sec_count),
        );
        data.add_field(
            "default_security_rule_count".to_string(),
            ResolvedValue::Integer(def_count),
        );
        data.add_field(
            "has_custom_rules".to_string(),
            ResolvedValue::Boolean(sec_count > 0),
        );

        // direction/access counts (custom rules only)
        data.add_field(
            "inbound_allow_count".to_string(),
            ResolvedValue::Integer(Self::count_rules(security_rules, "Inbound", "Allow")),
        );
        data.add_field(
            "inbound_deny_count".to_string(),
            ResolvedValue::Integer(Self::count_rules(security_rules, "Inbound", "Deny")),
        );
        data.add_field(
            "outbound_allow_count".to_string(),
            ResolvedValue::Integer(Self::count_rules(security_rules, "Outbound", "Allow")),
        );
        data.add_field(
            "outbound_deny_count".to_string(),
            ResolvedValue::Integer(Self::count_rules(security_rules, "Outbound", "Deny")),
        );

        data.add_field(
            "has_internet_inbound_allow".to_string(),
            ResolvedValue::Boolean(Self::has_inbound_internet_allow(security_rules)),
        );

        // dangerous port detection
        data.add_field(
            "has_ssh_open_to_internet".to_string(),
            ResolvedValue::Boolean(Self::has_internet_inbound_port(security_rules, 22)),
        );
        data.add_field(
            "has_rdp_open_to_internet".to_string(),
            ResolvedValue::Boolean(Self::has_internet_inbound_port(security_rules, 3389)),
        );
        data.add_field(
            "has_all_ports_open_to_internet".to_string(),
            ResolvedValue::Boolean(Self::has_internet_inbound_all_ports(security_rules)),
        );

        // total rule count (custom + default)
        data.add_field(
            "total_rule_count".to_string(),
            ResolvedValue::Integer(sec_count + def_count),
        );

        // subnet / NIC bindings (networkInterfaces may be absent or null)
        let subnet_count = resp
            .get("subnets")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let nic_count = resp
            .get("networkInterfaces")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);

        data.add_field(
            "subnet_binding_count".to_string(),
            ResolvedValue::Integer(subnet_count),
        );
        data.add_field(
            "nic_binding_count".to_string(),
            ResolvedValue::Integer(nic_count),
        );
        data.add_field(
            "has_subnet_bindings".to_string(),
            ResolvedValue::Boolean(subnet_count > 0),
        );
        data.add_field(
            "has_nic_bindings".to_string(),
            ResolvedValue::Boolean(nic_count > 0),
        );
        data.add_field(
            "is_attached".to_string(),
            ResolvedValue::Boolean(subnet_count + nic_count > 0),
        );

        // Capture NSG id before moving resp into RecordData
        let nsg_id = resp
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let nsg_location = resp
            .get("location")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        // Behavior-gated: flow log status
        let include_flow_log = hints
            .get_parameter_as_bool("include_flow_log_status")
            .unwrap_or(false);
        if include_flow_log && !nsg_id.is_empty() && !nsg_location.is_empty() {
            let mut fl_args: Vec<String> = vec![
                "network".to_string(),
                "watcher".to_string(),
                "flow-log".to_string(),
                "list".to_string(),
                "--location".to_string(),
                nsg_location,
            ];
            if let Some(ref sub) = subscription {
                fl_args.push("--subscription".to_string());
                fl_args.push(sub.clone());
            }
            fl_args.push("--output".to_string());
            fl_args.push("json".to_string());

            let fl_arg_refs: Vec<&str> = fl_args.iter().map(|s| s.as_str()).collect();
            match self
                .executor
                .execute("az", &fl_arg_refs, Some(Duration::from_secs(30)))
            {
                Ok(fl_output) if fl_output.exit_code == 0 => {
                    if let Ok(fl_resp) = serde_json::from_str::<serde_json::Value>(
                        fl_output.stdout.trim(),
                    ) {
                        Self::extract_flow_log_fields(&fl_resp, &nsg_id, &mut data);
                    }
                }
                _ => {
                    // Non-fatal: flow log query failed, fields stay absent
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_nsg".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_nsg" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_nsg', got '{}'",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_matches_resource_not_found() {
        let stderr = "ERROR: (ResourceNotFound) The Resource \
                     'Microsoft.Network/networkSecurityGroups/nsg-missing' under resource group \
                     'rg-real' was not found.";
        assert!(AzNsgCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found_code_line() {
        let stderr = "ERROR: something\nCode: ResourceNotFound\nMessage: whatever";
        assert!(AzNsgCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_nsg() {
        let stderr = "ERROR: (AuthorizationFailed) The client 'x' does not have authorization \
                     to perform action 'Microsoft.Network/networkSecurityGroups/read' over scope \
                     '/subscriptions/abc/resourceGroups/rg-gone/providers/Microsoft.Network/networkSecurityGroups/nsg-x' \
                     or the scope is invalid.";
        assert!(AzNsgCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1'";
        assert!(!AzNsgCollector::is_not_found(stderr));
    }

    #[test]
    fn forbidden_is_not_not_found() {
        let stderr = "ERROR: (Forbidden) Caller is not authorized to perform action on resource.";
        assert!(!AzNsgCollector::is_not_found(stderr));
    }

    #[test]
    fn internet_inbound_allow_detected_singular() {
        let rules = serde_json::json!([
            {
                "name": "AllowInternetHTTPS",
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "Internet",
                "sourceAddressPrefixes": []
            }
        ]);
        assert!(AzNsgCollector::has_inbound_internet_allow(&rules));
    }

    #[test]
    fn internet_inbound_allow_detected_wildcard() {
        let rules = serde_json::json!([
            {"name": "r", "direction": "Inbound", "access": "Allow",
             "sourceAddressPrefix": "*", "sourceAddressPrefixes": []}
        ]);
        assert!(AzNsgCollector::has_inbound_internet_allow(&rules));
    }

    #[test]
    fn internet_inbound_allow_detected_plural() {
        let rules = serde_json::json!([
            {"name": "r", "direction": "Inbound", "access": "Allow",
             "sourceAddressPrefix": null,
             "sourceAddressPrefixes": ["10.0.0.0/8", "0.0.0.0/0"]}
        ]);
        assert!(AzNsgCollector::has_inbound_internet_allow(&rules));
    }

    #[test]
    fn internet_inbound_deny_does_not_count() {
        let rules = serde_json::json!([
            {"name": "r", "direction": "Inbound", "access": "Deny",
             "sourceAddressPrefix": "Internet"}
        ]);
        assert!(!AzNsgCollector::has_inbound_internet_allow(&rules));
    }

    #[test]
    fn port_matches_exact() {
        assert!(AzNsgCollector::port_matches("22", 22));
        assert!(!AzNsgCollector::port_matches("22", 80));
    }

    #[test]
    fn port_matches_wildcard() {
        assert!(AzNsgCollector::port_matches("*", 22));
        assert!(AzNsgCollector::port_matches("*", 3389));
    }

    #[test]
    fn port_matches_range() {
        assert!(AzNsgCollector::port_matches("20-25", 22));
        assert!(!AzNsgCollector::port_matches("20-25", 80));
        assert!(AzNsgCollector::port_matches("3380-3400", 3389));
        assert!(!AzNsgCollector::port_matches("3380-3388", 3389));
    }

    #[test]
    fn ssh_open_to_internet_detected() {
        let rules = serde_json::json!([
            {
                "name": "AllowSSH",
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "Internet",
                "sourceAddressPrefixes": [],
                "destinationPortRange": "22",
                "destinationPortRanges": []
            }
        ]);
        assert!(AzNsgCollector::has_internet_inbound_port(&rules, 22));
        assert!(!AzNsgCollector::has_internet_inbound_port(&rules, 3389));
    }

    #[test]
    fn rdp_open_via_range() {
        let rules = serde_json::json!([
            {
                "name": "AllowRange",
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "*",
                "sourceAddressPrefixes": [],
                "destinationPortRange": null,
                "destinationPortRanges": ["80", "3380-3400"]
            }
        ]);
        assert!(AzNsgCollector::has_internet_inbound_port(&rules, 3389));
        assert!(!AzNsgCollector::has_internet_inbound_port(&rules, 22));
    }

    #[test]
    fn all_ports_open_detected() {
        let rules = serde_json::json!([
            {
                "name": "AllowAll",
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "0.0.0.0/0",
                "sourceAddressPrefixes": [],
                "destinationPortRange": "*",
                "destinationPortRanges": []
            }
        ]);
        assert!(AzNsgCollector::has_internet_inbound_all_ports(&rules));
    }

    #[test]
    fn all_ports_not_triggered_by_range() {
        let rules = serde_json::json!([
            {
                "name": "AllowBigRange",
                "direction": "Inbound",
                "access": "Allow",
                "sourceAddressPrefix": "Internet",
                "sourceAddressPrefixes": [],
                "destinationPortRange": "1-65535",
                "destinationPortRanges": []
            }
        ]);
        // has_all_ports_open_to_internet only matches literal "*", not ranges
        assert!(!AzNsgCollector::has_internet_inbound_all_ports(&rules));
        // But port-specific checks still match
        assert!(AzNsgCollector::has_internet_inbound_port(&rules, 22));
    }

    #[test]
    fn flow_log_fields_extracted() {
        let resp = serde_json::json!([
            {
                "targetResourceId": "/subscriptions/abc/providers/Microsoft.Network/networkSecurityGroups/nsg-test",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": true,
                    "days": 90
                },
                "flowAnalyticsConfiguration": {
                    "networkWatcherFlowAnalyticsConfiguration": {
                        "enabled": true,
                        "trafficAnalyticsInterval": 10
                    }
                }
            }
        ]);
        let mut data = CollectedData::new("test".to_string(), "az_nsg".to_string(), "c".to_string());
        AzNsgCollector::extract_flow_log_fields(
            &resp,
            "/subscriptions/abc/providers/Microsoft.Network/networkSecurityGroups/nsg-test",
            &mut data,
        );
        assert_eq!(
            data.fields.get("flow_log_enabled"),
            Some(&ResolvedValue::Boolean(true))
        );
        assert_eq!(
            data.fields.get("flow_log_retention_enabled"),
            Some(&ResolvedValue::Boolean(true))
        );
        assert_eq!(
            data.fields.get("flow_log_retention_days"),
            Some(&ResolvedValue::Integer(90))
        );
        assert_eq!(
            data.fields.get("flow_log_traffic_analytics_enabled"),
            Some(&ResolvedValue::Boolean(true))
        );
        assert_eq!(
            data.fields.get("flow_log_analytics_interval_minutes"),
            Some(&ResolvedValue::Integer(10))
        );
    }

    #[test]
    fn flow_log_not_found_returns_false() {
        let resp = serde_json::json!([]);
        let mut data = CollectedData::new("test".to_string(), "az_nsg".to_string(), "c".to_string());
        AzNsgCollector::extract_flow_log_fields(&resp, "/subscriptions/abc/nsg-other", &mut data);
        assert_eq!(
            data.fields.get("flow_log_enabled"),
            Some(&ResolvedValue::Boolean(false))
        );
    }

    #[test]
    fn count_rules_direction_access() {
        let rules = serde_json::json!([
            {"direction": "Inbound", "access": "Allow"},
            {"direction": "Inbound", "access": "Allow"},
            {"direction": "Inbound", "access": "Deny"},
            {"direction": "Outbound", "access": "Allow"}
        ]);
        assert_eq!(AzNsgCollector::count_rules(&rules, "Inbound", "Allow"), 2);
        assert_eq!(AzNsgCollector::count_rules(&rules, "Inbound", "Deny"), 1);
        assert_eq!(AzNsgCollector::count_rules(&rules, "Outbound", "Allow"), 1);
        assert_eq!(AzNsgCollector::count_rules(&rules, "Outbound", "Deny"), 0);
    }
}
