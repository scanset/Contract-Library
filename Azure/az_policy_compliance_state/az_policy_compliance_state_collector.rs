//! Azure Policy Compliance State Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_policy_compliance_state;
//  pub use az_policy_compliance_state::AzPolicyComplianceStateCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzPolicyComplianceStateCollector::new(
//          "az-policy-compliance-state-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzPolicyComplianceStateExecutor::new(
//          contracts::create_az_policy_compliance_state_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az policy state summarize` call.
//!
//! The scope OBJECT field (a full ARM URI) is parsed into one of three
//! `az` flag combinations because `az policy state summarize` does not
//! accept a single `--scope` argument - it takes explicit scope flags:
//!
//! | Scope URI pattern                                                     | Flags                         |
//! |-----------------------------------------------------------------------|-------------------------------|
//! | `/providers/Microsoft.Management/managementGroups/<mg>`               | `--management-group <mg>`     |
//! | `/subscriptions/<sub>/resourceGroups/<rg>` (any suffix)               | `--resource-group <rg>` + sub |
//! | `/subscriptions/<sub>` (exact)                                        | `--subscription <sub>`        |
//!
//! The subscription is always propagated via `--subscription` when the
//! scope embeds one so the CLI session lands on the right tenant/sub
//! regardless of the user's `az account` default.
//!
//! ## Error surface
//!
//! The Policy Insights API is a query-by-time-window surface, so missing
//! scope / missing assignment / filter-mismatch all return exit 0 with
//! an empty `policyAssignments[]`. There is therefore NO `is_not_found()`
//! stderr matcher in this collector - `found` is derived directly from
//! the response shape. The only true error is `Code:
//! InvalidFilterInQueryString` on a malformed `--filter`, which bubbles
//! up as `CollectionError::CollectionFailed` since it indicates an
//! author-side bug rather than a runtime state.
//!
//! ## Drift handling
//!
//! Every `queryResultsUri` field in the response embeds a request
//! timestamp (`$from=...&$to=...`) and therefore differs on every call.
//! The collector strips every `queryResultsUri` occurrence from the
//! JSON before storing it as RecordData so nested assertions on the
//! record never flap. All other fields are byte-stable (verified in
//! discovery: 30s drift diff = only queryResultsUri lines).

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzPolicyComplianceStateCollector {
    id: String,
    executor: SystemCommandExecutor,
}

/// Parsed scope variant - controls which `az` flag(s) we supply.
#[derive(Debug, PartialEq, Eq)]
enum ScopeKind {
    ManagementGroup { name: String },
    ResourceGroup { subscription: String, rg: String },
    Subscription { subscription: String },
}

impl AzPolicyComplianceStateCollector {
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

    /// Parse an ARM scope URI into a ScopeKind. Returns None when the
    /// input does not match one of the three accepted shapes.
    fn parse_scope(scope: &str) -> Option<ScopeKind> {
        let trimmed = scope.trim_end_matches('/');
        // Management group: /providers/Microsoft.Management/managementGroups/<name>
        if let Some(rest) = trimmed
            .strip_prefix("/providers/Microsoft.Management/managementGroups/")
            .or_else(|| trimmed.strip_prefix("/providers/microsoft.management/managementgroups/"))
        {
            // Name is everything up to the next slash (there shouldn't be one, but be defensive).
            let name = rest.split('/').next().unwrap_or("");
            if name.is_empty() {
                return None;
            }
            return Some(ScopeKind::ManagementGroup {
                name: name.to_string(),
            });
        }

        // Subscription-anchored scopes: /subscriptions/<sub>[/resourceGroups/<rg>[/...]]
        let lower = trimmed.to_lowercase();
        let subs_prefix = "/subscriptions/";
        if let Some(rest_lower) = lower.strip_prefix(subs_prefix) {
            // Take the sub id as the next segment, using the ORIGINAL (case-preserved) string.
            let after_subs = &trimmed[subs_prefix.len()..];
            let sub_end = after_subs.find('/').unwrap_or(after_subs.len());
            let subscription = after_subs[..sub_end].to_string();
            if subscription.is_empty() {
                return None;
            }

            // Check for a resourceGroups segment (case-insensitive) after the sub.
            let after_sub_lower = &rest_lower[sub_end..];
            let rg_marker = "/resourcegroups/";
            if let Some(rg_rest_lower) = after_sub_lower.strip_prefix(rg_marker) {
                // rg_rest_lower is a suffix of `lower`, which is
                // character-for-character parallel to `trimmed`. Compute the
                // start offset into `trimmed` by subtracting the suffix length
                // from the total; this sidesteps the error-prone manual
                // summation of `subs_prefix.len() + sub_end + rg_marker.len()`
                // which previously indexed into `after_subs` space rather
                // than `trimmed` space and pulled out the literal segment
                // label "resourceGroups" instead of the actual rg name.
                let rg_rest_start = trimmed.len() - rg_rest_lower.len();
                let after_rg = &trimmed[rg_rest_start..];
                let rg_end = after_rg.find('/').unwrap_or(after_rg.len());
                let rg = after_rg[..rg_end].to_string();
                if rg.is_empty() {
                    return None;
                }
                // Accept scopes that descend further (e.g., provider/resource paths)
                // but still treat the summarize scope as the resource group.
                return Some(ScopeKind::ResourceGroup { subscription, rg });
            }

            // Plain subscription scope (no resourceGroups segment).
            return Some(ScopeKind::Subscription { subscription });
        }

        None
    }

    /// Recursively remove every occurrence of the key `queryResultsUri`
    /// from a JSON value. Used to produce a drift-free RecordData.
    fn strip_query_results_uri(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.remove("queryResultsUri");
                for v in map.values_mut() {
                    Self::strip_query_results_uri(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter_mut() {
                    Self::strip_query_results_uri(v);
                }
            }
            _ => {}
        }
    }

    /// Sum `count` for every entry in `resourceDetails[]` whose
    /// `complianceState` matches `target`. Case-insensitive match since
    /// the API emits lowercase (`"compliant"`, `"noncompliant"`,
    /// `"unknown"`).
    fn sum_resource_detail_count(
        results: Option<&serde_json::Value>,
        target_state_lower: &str,
    ) -> i64 {
        results
            .and_then(|r| r.get("resourceDetails"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|entry| {
                        entry
                            .get("complianceState")
                            .and_then(|s| s.as_str())
                            .map(|s| s.eq_ignore_ascii_case(target_state_lower))
                            .unwrap_or(false)
                    })
                    .filter_map(|entry| entry.get("count").and_then(|c| c.as_i64()))
                    .sum::<i64>()
            })
            .unwrap_or(0)
    }

    fn sum_all_resource_detail_count(results: Option<&serde_json::Value>) -> i64 {
        results
            .and_then(|r| r.get("resourceDetails"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entry| entry.get("count").and_then(|c| c.as_i64()))
                    .sum::<i64>()
            })
            .unwrap_or(0)
    }
}

impl CtnDataCollector for AzPolicyComplianceStateCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let scope = self.extract_string_field(object, "scope").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'scope' is required for az_policy_compliance_state".to_string(),
            }
        })?;
        let assignment_name = self.extract_string_field(object, "policy_assignment_name");
        let subscription_override = self.extract_string_field(object, "subscription");

        let scope_kind = Self::parse_scope(&scope).ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: format!(
                    "scope '{}' is not a recognized ARM scope \
                     (expected /subscriptions/..., \
                     /subscriptions/.../resourceGroups/..., or \
                     /providers/Microsoft.Management/managementGroups/...)",
                    scope
                ),
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_policy_compliance_state".to_string(),
            self.id.clone(),
        );

        // Echo the scope input so ESP can assert on it trivially.
        data.add_field("scope".to_string(), ResolvedValue::String(scope.clone()));

        // -- Build argv --------------------------------------------
        let mut args: Vec<String> = vec![
            "policy".to_string(),
            "state".to_string(),
            "summarize".to_string(),
        ];
        match &scope_kind {
            ScopeKind::ManagementGroup { name } => {
                args.push("--management-group".to_string());
                args.push(name.clone());
            }
            ScopeKind::ResourceGroup { subscription, rg } => {
                args.push("--resource-group".to_string());
                args.push(rg.clone());
                args.push("--subscription".to_string());
                args.push(subscription.clone());
            }
            ScopeKind::Subscription { subscription } => {
                args.push("--subscription".to_string());
                args.push(subscription.clone());
            }
        }
        if let Some(sub) = subscription_override.as_ref() {
            // Allow an explicit override to replace whatever the scope embedded.
            // Remove any prior --subscription we may have pushed.
            let mut filtered: Vec<String> = Vec::with_capacity(args.len());
            let mut skip_next = false;
            for a in args.drain(..) {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if a == "--subscription" {
                    skip_next = true;
                    continue;
                }
                filtered.push(a);
            }
            args = filtered;
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        if let Some(name) = assignment_name.as_ref() {
            args.push("--policy-assignment".to_string());
            args.push(name.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));
        let target = match (&assignment_name, &scope_kind) {
            (Some(n), _) => format!("policy-state:{}@{}", n, scope),
            (None, _) => format!("policy-state:@{}", scope),
        };

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Summarize Azure Policy compliance state via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("scope", &scope);
        if let Some(name) = assignment_name.as_ref() {
            method_builder = method_builder.input("policy_assignment_name", name);
        }
        if let Some(sub) = subscription_override.as_ref() {
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
            // Only one error mode is expected here: malformed OData filter.
            // Every "missing" scenario returns 200/empty from the API.
            return Err(CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!(
                    "az policy state summarize failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let mut resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az policy state summarize JSON: {}", e),
            }
        })?;

        // -- Derive scalar fields from the response ----------------
        let assignments = resp
            .get("policyAssignments")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let assignment_count = assignments.len() as i64;
        let found = assignment_count > 0;
        data.add_field("found".to_string(), ResolvedValue::Boolean(found));
        data.add_field(
            "assignment_count".to_string(),
            ResolvedValue::Integer(assignment_count),
        );

        // Policy assignment / set ids come from the first entry when present.
        let first_assignment = assignments.first();
        let policy_assignment_id = first_assignment
            .and_then(|a| a.get("policyAssignmentId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let policy_set_definition_id = first_assignment
            .and_then(|a| a.get("policySetDefinitionId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        data.add_field(
            "policy_assignment_id".to_string(),
            ResolvedValue::String(policy_assignment_id),
        );
        let is_initiative = !policy_set_definition_id.is_empty();
        data.add_field(
            "policy_set_definition_id".to_string(),
            ResolvedValue::String(policy_set_definition_id),
        );
        data.add_field(
            "is_initiative".to_string(),
            ResolvedValue::Boolean(is_initiative),
        );

        // Top-level results{} is the aggregate; use it as the source of truth.
        let results = resp.get("results");
        let non_compliant_resources = results
            .and_then(|r| r.get("nonCompliantResources"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let non_compliant_policies = results
            .and_then(|r| r.get("nonCompliantPolicies"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let compliant_resource_count = Self::sum_resource_detail_count(results, "compliant");
        let noncompliant_resource_count = Self::sum_resource_detail_count(results, "noncompliant");
        let unknown_resource_count = Self::sum_resource_detail_count(results, "unknown");
        let total_evaluated_count = Self::sum_all_resource_detail_count(results);
        let resource_detail_count = results
            .and_then(|r| r.get("resourceDetails"))
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);

        data.add_field(
            "non_compliant_resources".to_string(),
            ResolvedValue::Integer(non_compliant_resources),
        );
        data.add_field(
            "non_compliant_policies".to_string(),
            ResolvedValue::Integer(non_compliant_policies),
        );
        data.add_field(
            "compliant_resource_count".to_string(),
            ResolvedValue::Integer(compliant_resource_count),
        );
        data.add_field(
            "noncompliant_resource_count".to_string(),
            ResolvedValue::Integer(noncompliant_resource_count),
        );
        data.add_field(
            "unknown_resource_count".to_string(),
            ResolvedValue::Integer(unknown_resource_count),
        );
        data.add_field(
            "total_evaluated_count".to_string(),
            ResolvedValue::Integer(total_evaluated_count),
        );
        data.add_field(
            "resource_detail_count".to_string(),
            ResolvedValue::Integer(resource_detail_count),
        );

        // Derived booleans
        let has_evaluations = total_evaluated_count > 0;
        data.add_field(
            "has_evaluations".to_string(),
            ResolvedValue::Boolean(has_evaluations),
        );
        data.add_field(
            "is_compliant".to_string(),
            ResolvedValue::Boolean(non_compliant_resources == 0 && has_evaluations),
        );
        data.add_field(
            "has_noncompliant_resources".to_string(),
            ResolvedValue::Boolean(non_compliant_resources > 0),
        );
        data.add_field(
            "has_noncompliant_policies".to_string(),
            ResolvedValue::Boolean(non_compliant_policies > 0),
        );

        // Strip drift-prone queryResultsUri everywhere in the response
        // before exposing as RecordData.
        Self::strip_query_results_uri(&mut resp);
        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_policy_compliance_state".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_policy_compliance_state" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_policy_compliance_state', got '{}'",
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
    use serde_json::json;

    #[test]
    fn parse_scope_management_group() {
        let s = "/providers/Microsoft.Management/managementGroups/my-mg";
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope(s),
            Some(ScopeKind::ManagementGroup {
                name: "my-mg".to_string()
            })
        );
    }

    #[test]
    fn parse_scope_resource_group() {
        let s = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/\
                 rg-prooflayer-demo-eastus";
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope(s),
            Some(ScopeKind::ResourceGroup {
                subscription: "00000000-0000-0000-0000-000000000000".to_string(),
                rg: "rg-prooflayer-demo-eastus".to_string(),
            })
        );
    }

    #[test]
    fn parse_scope_resource_group_case_insensitive_segment() {
        // Azure often returns /resourcegroups/ lower-cased in some CLI outputs;
        // the matcher must accept either casing without mangling the name.
        let s = "/subscriptions/abc/resourcegroups/my-rg";
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope(s),
            Some(ScopeKind::ResourceGroup {
                subscription: "abc".to_string(),
                rg: "my-rg".to_string(),
            })
        );
    }

    #[test]
    fn parse_scope_subscription_only() {
        let s = "/subscriptions/00000000-0000-0000-0000-000000000000";
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope(s),
            Some(ScopeKind::Subscription {
                subscription: "00000000-0000-0000-0000-000000000000".to_string()
            })
        );
    }

    #[test]
    fn parse_scope_rejects_garbage() {
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope("not a scope"),
            None
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope("/subscriptions/"),
            None
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::parse_scope(
                "/providers/Microsoft.Management/managementGroups/"
            ),
            None
        );
    }

    #[test]
    fn strip_query_results_uri_scrubs_nested_occurrences() {
        let mut v = json!({
            "results": {
                "queryResultsUri": "https://example/x",
                "nonCompliantResources": 0,
                "resourceDetails": [
                    {"complianceState": "compliant", "count": 3}
                ]
            },
            "policyAssignments": [
                {
                    "policyAssignmentId": "/subs/x/.../policyAssignments/a",
                    "results": {
                        "queryResultsUri": "https://example/y",
                        "nonCompliantResources": 0
                    }
                }
            ]
        });
        AzPolicyComplianceStateCollector::strip_query_results_uri(&mut v);
        // Top-level results no longer has queryResultsUri
        assert!(v
            .get("results")
            .unwrap()
            .as_object()
            .unwrap()
            .get("queryResultsUri")
            .is_none());
        // Nested per-assignment queryResultsUri also removed
        assert!(v
            .get("policyAssignments")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .get("results")
            .unwrap()
            .as_object()
            .unwrap()
            .get("queryResultsUri")
            .is_none());
        // Sibling fields preserved
        assert_eq!(
            v["results"]["nonCompliantResources"].as_i64().unwrap(),
            0
        );
        assert_eq!(
            v["results"]["resourceDetails"][0]["count"].as_i64().unwrap(),
            3
        );
    }

    #[test]
    fn sum_resource_detail_count_filters_by_state() {
        let results = json!({
            "resourceDetails": [
                {"complianceState": "compliant", "count": 26},
                {"complianceState": "noncompliant", "count": 3},
                {"complianceState": "unknown", "count": 1}
            ]
        });
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_resource_detail_count(
                Some(&results),
                "compliant"
            ),
            26
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_resource_detail_count(
                Some(&results),
                "noncompliant"
            ),
            3
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_resource_detail_count(
                Some(&results),
                "unknown"
            ),
            1
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_all_resource_detail_count(Some(&results)),
            30
        );
    }

    #[test]
    fn sum_resource_detail_count_handles_absent_results() {
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_resource_detail_count(None, "compliant"),
            0
        );
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_all_resource_detail_count(None),
            0
        );
    }

    #[test]
    fn sum_resource_detail_count_case_insensitive_match() {
        // API emits lower-case but be defensive against upper-case drift.
        let results = json!({
            "resourceDetails": [
                {"complianceState": "Compliant", "count": 7},
                {"complianceState": "COMPLIANT", "count": 2}
            ]
        });
        assert_eq!(
            AzPolicyComplianceStateCollector::sum_resource_detail_count(
                Some(&results),
                "compliant"
            ),
            9
        );
    }
}
