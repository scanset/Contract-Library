//! Azure Application Gateway Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_application_gateway;
//  pub use az_application_gateway::AzApplicationGatewayCollector;
//
///////////////////////////////////////////////////////

//! Single `az network application-gateway show --name <name>
//! --resource-group <rg> [--subscription <id>] --output json` call.
//! Returns scalar fields for SKU, WAF, SSL policy, listeners,
//! backend pools, routing rules, zones, autoscale, and redirect
//! configuration, plus the full response as RecordData.
//!
//! ## NotFound handling
//!
//! Same dual-pattern as other Azure CTNs:
//! - `(ResourceNotFound)` - real RG with missing/malformed name
//! - `(AuthorizationFailed)` scoped to `/applicationGateways/`

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzApplicationGatewayCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzApplicationGatewayCollector {
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

    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/applicationgateways/") {
                return true;
            }
        }
        false
    }

    /// Check if any listener uses HTTPS protocol
    fn has_https_listener(resp: &serde_json::Value) -> bool {
        resp.get("httpListeners")
            .and_then(|v| v.as_array())
            .map(|listeners| {
                listeners.iter().any(|l| {
                    l.get("properties")
                        .or(Some(l))
                        .and_then(|p| p.get("protocol"))
                        .and_then(|v| v.as_str())
                        .map(|p| p.eq_ignore_ascii_case("https"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Check if any redirect configuration does HTTP->HTTPS
    fn has_http_to_https_redirect(resp: &serde_json::Value) -> bool {
        resp.get("redirectConfigurations")
            .and_then(|v| v.as_array())
            .map(|configs| {
                configs.iter().any(|c| {
                    let props = c.get("properties").unwrap_or(c);
                    let redirect_type = props
                        .get("redirectType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    // Permanent or Found redirect indicates HTTP->HTTPS
                    redirect_type == "Permanent" || redirect_type == "Found"
                })
            })
            .unwrap_or(false)
    }
}

impl CtnDataCollector for AzApplicationGatewayCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let name = self.extract_string_field(object, "name").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'name' is required for az_application_gateway".to_string(),
            }
        })?;
        let resource_group =
            self.extract_string_field(object, "resource_group")
                .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                    object_id: object.identifier.clone(),
                    reason: "'resource_group' is required for az_application_gateway".to_string(),
                })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_application_gateway".to_string(),
            self.id.clone(),
        );

        let mut args: Vec<String> = vec![
            "network".to_string(),
            "application-gateway".to_string(),
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
        let target = format!("appgw:{}", name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Application Gateway via Azure CLI")
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
                    "az network application-gateway show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse application-gateway show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("location", "location"),
            ("resourceGroup", "resource_group"),
            ("provisioningState", "provisioning_state"),
            ("operationalState", "operational_state"),
        ] {
            if let Some(v) = resp.get(*json_key).and_then(|v| v.as_str()) {
                data.add_field(
                    field_name.to_string(),
                    ResolvedValue::String(v.to_string()),
                );
            }
        }

        // SKU
        if let Some(sku) = resp.get("sku") {
            if let Some(name_val) = sku.get("name").and_then(|v| v.as_str()) {
                data.add_field(
                    "sku_name".to_string(),
                    ResolvedValue::String(name_val.to_string()),
                );
            }
            if let Some(tier) = sku.get("tier").and_then(|v| v.as_str()) {
                data.add_field(
                    "sku_tier".to_string(),
                    ResolvedValue::String(tier.to_string()),
                );
            }
            if let Some(capacity) = sku.get("capacity").and_then(|v| v.as_i64()) {
                data.add_field(
                    "sku_capacity".to_string(),
                    ResolvedValue::Integer(capacity),
                );
            }
        }

        // WAF configuration
        let waf_config = resp.get("webApplicationFirewallConfiguration");
        let waf_enabled = waf_config
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "waf_enabled".to_string(),
            ResolvedValue::Boolean(waf_enabled),
        );

        if let Some(waf) = waf_config {
            if let Some(mode) = waf.get("firewallMode").and_then(|v| v.as_str()) {
                data.add_field(
                    "waf_mode".to_string(),
                    ResolvedValue::String(mode.to_string()),
                );
            }
            if let Some(rule_set) = waf.get("ruleSetType").and_then(|v| v.as_str()) {
                data.add_field(
                    "waf_rule_set_type".to_string(),
                    ResolvedValue::String(rule_set.to_string()),
                );
            }
            if let Some(rule_ver) = waf.get("ruleSetVersion").and_then(|v| v.as_str()) {
                data.add_field(
                    "waf_rule_set_version".to_string(),
                    ResolvedValue::String(rule_ver.to_string()),
                );
            }
        }

        // SSL policy
        if let Some(ssl) = resp.get("sslPolicy") {
            if let Some(policy_type) = ssl.get("policyType").and_then(|v| v.as_str()) {
                data.add_field(
                    "ssl_policy_type".to_string(),
                    ResolvedValue::String(policy_type.to_string()),
                );
            }
            if let Some(policy_name) = ssl.get("policyName").and_then(|v| v.as_str()) {
                data.add_field(
                    "ssl_policy_name".to_string(),
                    ResolvedValue::String(policy_name.to_string()),
                );
            }
            if let Some(min_ver) = ssl.get("minProtocolVersion").and_then(|v| v.as_str()) {
                data.add_field(
                    "ssl_min_protocol_version".to_string(),
                    ResolvedValue::String(min_ver.to_string()),
                );
            }
        }

        // HTTP/2
        let http2 = resp
            .get("enableHttp2")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        data.add_field(
            "http2_enabled".to_string(),
            ResolvedValue::Boolean(http2),
        );

        // Zones
        let zones = resp
            .get("zones")
            .and_then(|v| v.as_array());
        let zone_count = zones.map(|a| a.len() as i64).unwrap_or(0);
        data.add_field(
            "zone_count".to_string(),
            ResolvedValue::Integer(zone_count),
        );
        data.add_field(
            "zone_redundant".to_string(),
            ResolvedValue::Boolean(zone_count > 1),
        );

        // Autoscale
        let autoscale = resp.get("autoscaleConfiguration");
        let autoscale_enabled = autoscale.is_some();
        data.add_field(
            "autoscale_enabled".to_string(),
            ResolvedValue::Boolean(autoscale_enabled),
        );
        if let Some(auto) = autoscale {
            if let Some(min_cap) = auto.get("minCapacity").and_then(|v| v.as_i64()) {
                data.add_field(
                    "autoscale_min_capacity".to_string(),
                    ResolvedValue::Integer(min_cap),
                );
            }
            if let Some(max_cap) = auto.get("maxCapacity").and_then(|v| v.as_i64()) {
                data.add_field(
                    "autoscale_max_capacity".to_string(),
                    ResolvedValue::Integer(max_cap),
                );
            }
        }

        // Counts
        let count_field = |json_key: &str| -> i64 {
            resp.get(json_key)
                .and_then(|v| v.as_array())
                .map(|a| a.len() as i64)
                .unwrap_or(0)
        };

        data.add_field(
            "frontend_ip_count".to_string(),
            ResolvedValue::Integer(count_field("frontendIPConfigurations")),
        );
        data.add_field(
            "frontend_port_count".to_string(),
            ResolvedValue::Integer(count_field("frontendPorts")),
        );
        data.add_field(
            "http_listener_count".to_string(),
            ResolvedValue::Integer(count_field("httpListeners")),
        );
        data.add_field(
            "backend_pool_count".to_string(),
            ResolvedValue::Integer(count_field("backendAddressPools")),
        );
        data.add_field(
            "backend_http_settings_count".to_string(),
            ResolvedValue::Integer(count_field("backendHttpSettingsCollection")),
        );
        data.add_field(
            "request_routing_rule_count".to_string(),
            ResolvedValue::Integer(count_field("requestRoutingRules")),
        );
        data.add_field(
            "ssl_certificate_count".to_string(),
            ResolvedValue::Integer(count_field("sslCertificates")),
        );
        data.add_field(
            "probe_count".to_string(),
            ResolvedValue::Integer(count_field("probes")),
        );
        data.add_field(
            "redirect_configuration_count".to_string(),
            ResolvedValue::Integer(count_field("redirectConfigurations")),
        );

        // Derived booleans
        data.add_field(
            "has_https_listener".to_string(),
            ResolvedValue::Boolean(Self::has_https_listener(&resp)),
        );
        data.add_field(
            "has_http_to_https_redirect".to_string(),
            ResolvedValue::Boolean(Self::has_http_to_https_redirect(&resp)),
        );

        // Identity
        let has_identity = resp.get("identity").is_some();
        data.add_field(
            "has_managed_identity".to_string(),
            ResolvedValue::Boolean(has_identity),
        );
        if let Some(identity) = resp.get("identity") {
            if let Some(id_type) = identity.get("type").and_then(|v| v.as_str()) {
                data.add_field(
                    "identity_type".to_string(),
                    ResolvedValue::String(id_type.to_string()),
                );
            }
        }

        // RecordData
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_application_gateway".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_application_gateway" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_application_gateway', got '{}'",
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
                     'Microsoft.Network/applicationGateways/appgw-missing' was not found.";
        assert!(AzApplicationGatewayCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_appgw() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/appgw-x'";
        assert!(AzApplicationGatewayCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1'";
        assert!(!AzApplicationGatewayCollector::is_not_found(stderr));
    }

    #[test]
    fn has_https_listener_detects_https() {
        let resp = serde_json::json!({
            "httpListeners": [
                { "protocol": "Http" },
                { "protocol": "Https" }
            ]
        });
        assert!(AzApplicationGatewayCollector::has_https_listener(&resp));
    }

    #[test]
    fn has_https_listener_false_when_http_only() {
        let resp = serde_json::json!({
            "httpListeners": [
                { "protocol": "Http" }
            ]
        });
        assert!(!AzApplicationGatewayCollector::has_https_listener(&resp));
    }

    #[test]
    fn has_redirect_detects_permanent() {
        let resp = serde_json::json!({
            "redirectConfigurations": [
                { "redirectType": "Permanent" }
            ]
        });
        assert!(AzApplicationGatewayCollector::has_http_to_https_redirect(&resp));
    }
}
