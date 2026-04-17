//! Azure Policy Assignment Collector

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/collectors/mod.rs)
//
//  pub mod az_policy_assignment;
//  pub use az_policy_assignment::AzPolicyAssignmentCollector;
//
//  Registry wiring (agent/src/registry.rs):
//
//  registry.register_ctn_strategy(
//      Box::new(collectors::AzPolicyAssignmentCollector::new(
//          "az-policy-assignment-collector",
//          commands::create_az_executor(),
//      )),
//      Box::new(executors::AzPolicyAssignmentExecutor::new(
//          contracts::create_az_policy_assignment_contract(),
//      )),
//  )?;
//
///////////////////////////////////////////////////////

//! Single `az policy assignment show --name <name> --scope <scope>
//! [--subscription <id>] --output json` call. Returns scalar config
//! fields plus the full response as RecordData for nested assertions
//! on parameters, nonComplianceMessages, notScopes, and overrides.
//!
//! ## NotFound handling
//!
//! Three distinct stderr patterns all map to `found=false`:
//!
//! 1. **Assignment name doesn't exist at scope** - exit 3, stderr contains
//!    `(PolicyAssignmentNotFound)` or `Code: PolicyAssignmentNotFound`.
//!    This is the policy-API-specific NotFound code (distinct from the
//!    generic `ResourceNotFound` used by most ARM resources). Azure
//!    Resource Manager's Microsoft.Authorization provider specializes
//!    its error codes by resource type.
//! 2. **Generic ResourceNotFound** - exit 3, stderr contains
//!    `(ResourceNotFound)`. Retained as a fallback in case Azure ever
//!    normalizes the code for policy assignments; also covers adjacent
//!    paths (missing scope resource, etc.).
//! 3. **Scope is forbidden for the caller** - exit 1, stderr contains
//!    `(AuthorizationFailed)` with action `Microsoft.Authorization/\
//!    policyAssignments/read`. The RBAC layer treats "missing" and
//!    "forbidden" identically from the caller's perspective; we surface
//!    both as found=false so policy evaluation does not error on scope
//!    restrictions.
//! 4. **Malformed scope string** - exit 3, stderr contains
//!    `(MissingSubscription)` (e.g., scope missing `/subscriptions/`
//!    prefix). Treated as "assignment cannot exist at this scope" since
//!    Azure refuses to look it up.
//!
//! All other non-zero exits bubble up as `CollectionError::CollectionFailed`.

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct AzPolicyAssignmentCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl AzPolicyAssignmentCollector {
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

    /// Returns true when Azure's error shape matches a genuine
    /// "assignment cannot be observed at this scope" state - the net
    /// effect on policy is identical regardless of whether it's missing,
    /// forbidden, or addressed by a malformed scope.
    ///
    /// - `(PolicyAssignmentNotFound)` is the policy-API-specific
    ///   NotFound code - distinct from the generic ResourceNotFound
    ///   used by most ARM resources. This is the code actually returned
    ///   by `az policy assignment show` when the named assignment does
    ///   not exist at the given scope.
    /// - `(ResourceNotFound)` is the canonical generic Azure NotFound
    ///   code; retained as a fallback in case Azure ever normalizes
    ///   codes across resource types.
    /// - `(AuthorizationFailed)` is gated on the policyAssignments scope
    ///   substring so unrelated RBAC failures still surface as errors.
    /// - `(MissingSubscription)` covers malformed ARM scopes (no
    ///   /subscriptions/ prefix); Azure refuses to even look up the
    ///   assignment, which is semantically equivalent to not-found.
    fn is_not_found(stderr: &str) -> bool {
        if stderr.contains("(PolicyAssignmentNotFound)")
            || stderr.contains("Code: PolicyAssignmentNotFound")
        {
            return true;
        }
        if stderr.contains("(ResourceNotFound)") || stderr.contains("Code: ResourceNotFound") {
            return true;
        }
        if stderr.contains("(MissingSubscription)") || stderr.contains("Code: MissingSubscription") {
            return true;
        }
        if stderr.contains("(AuthorizationFailed)") {
            let lower = stderr.to_lowercase();
            if lower.contains("/policyassignments/")
                || lower.contains("microsoft.authorization/policyassignments")
            {
                return true;
            }
        }
        false
    }

    /// Determine policy_definition_kind by URI-segment inspection.
    /// `/providers/Microsoft.Authorization/policySetDefinitions/...` -> "initiative"
    /// `/providers/Microsoft.Authorization/policyDefinitions/...`    -> "single_policy"
    /// Empty/unrecognized -> "unknown" (would only occur on a malformed response)
    fn classify_definition(policy_definition_id: &str) -> &'static str {
        if policy_definition_id.contains("/policySetDefinitions/") {
            "initiative"
        } else if policy_definition_id.contains("/policyDefinitions/") {
            "single_policy"
        } else {
            "unknown"
        }
    }
}

impl CtnDataCollector for AzPolicyAssignmentCollector {
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
                reason: "'name' is required for az_policy_assignment".to_string(),
            }
        })?;
        let scope = self.extract_string_field(object, "scope").ok_or_else(|| {
            CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'scope' is required for az_policy_assignment (full ARM scope path)"
                    .to_string(),
            }
        })?;
        let subscription = self.extract_string_field(object, "subscription");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "az_policy_assignment".to_string(),
            self.id.clone(),
        );

        // Build argv
        let mut args: Vec<String> = vec![
            "policy".to_string(),
            "assignment".to_string(),
            "show".to_string(),
            "--name".to_string(),
            name.clone(),
            "--scope".to_string(),
            scope.clone(),
        ];
        if let Some(ref sub) = subscription {
            args.push("--subscription".to_string());
            args.push(sub.clone());
        }
        args.push("--output".to_string());
        args.push("json".to_string());

        let command_str = format!("az {}", args.join(" "));

        let target = format!("policy-assignment:{}@{}", name, scope);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query Azure Policy Assignment via Azure CLI")
            .target(&target)
            .command(&command_str)
            .input("name", &name)
            .input("scope", &scope);
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
                    "az policy assignment show failed (exit {}): {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        let resp: serde_json::Value = serde_json::from_str(output.stdout.trim()).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to parse az policy assignment show JSON: {}", e),
            }
        })?;

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Top-level strings that are always present in a successful response
        for (json_key, field_name) in &[
            ("name", "name"),
            ("id", "id"),
            ("type", "type"),
            ("scope", "scope"),
            ("displayName", "display_name"),
            ("enforcementMode", "enforcement_mode"),
            ("policyDefinitionId", "policy_definition_id"),
        ] {
            let val = resp
                .get(*json_key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            data.add_field(field_name.to_string(), ResolvedValue::String(val));
        }

        // Optional top-level strings - coalesce absent to empty string
        let optional_strings = [
            ("description", "description"),
            ("definitionVersion", "definition_version"),
            ("resourceGroup", "resource_group"),
            ("location", "location"),
        ];
        for (json_key, field_name) in &optional_strings {
            let val = resp
                .get(*json_key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            data.add_field(field_name.to_string(), ResolvedValue::String(val));
        }

        // Identity - populated only when the assignment has a managed identity
        let identity = resp.get("identity");
        let identity_type = identity
            .and_then(|i| i.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("None")
            .to_string();
        let identity_principal_id = identity
            .and_then(|i| i.get("principalId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let identity_tenant_id = identity
            .and_then(|i| i.get("tenantId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        data.add_field(
            "identity_type".to_string(),
            ResolvedValue::String(identity_type.clone()),
        );
        data.add_field(
            "identity_principal_id".to_string(),
            ResolvedValue::String(identity_principal_id),
        );
        data.add_field(
            "identity_tenant_id".to_string(),
            ResolvedValue::String(identity_tenant_id),
        );

        // Metadata + systemData - both are informational provenance fields
        let metadata = resp.get("metadata");
        let metadata_created_by = metadata
            .and_then(|m| m.get("createdBy"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let metadata_created_on = metadata
            .and_then(|m| m.get("createdOn"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        data.add_field(
            "metadata_created_by".to_string(),
            ResolvedValue::String(metadata_created_by),
        );
        data.add_field(
            "metadata_created_on".to_string(),
            ResolvedValue::String(metadata_created_on),
        );

        let system_data = resp.get("systemData");
        let sd_created_by = system_data
            .and_then(|s| s.get("createdBy"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sd_created_by_type = system_data
            .and_then(|s| s.get("createdByType"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        data.add_field(
            "system_data_created_by".to_string(),
            ResolvedValue::String(sd_created_by),
        );
        data.add_field(
            "system_data_created_by_type".to_string(),
            ResolvedValue::String(sd_created_by_type),
        );

        // Derived classification from policyDefinitionId
        let policy_def_id = resp
            .get("policyDefinitionId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let kind = Self::classify_definition(policy_def_id);
        data.add_field(
            "policy_definition_kind".to_string(),
            ResolvedValue::String(kind.to_string()),
        );

        // Derived counts from optional arrays / maps
        let parameter_count = resp
            .get("parameters")
            .and_then(|v| v.as_object())
            .map(|m| m.len() as i64)
            .unwrap_or(0);
        let non_compliance_message_count = resp
            .get("nonComplianceMessages")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let not_scopes_count = resp
            .get("notScopes")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let resource_selectors_count = resp
            .get("resourceSelectors")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);
        let overrides_count = resp
            .get("overrides")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as i64)
            .unwrap_or(0);

        data.add_field(
            "parameter_count".to_string(),
            ResolvedValue::Integer(parameter_count),
        );
        data.add_field(
            "non_compliance_message_count".to_string(),
            ResolvedValue::Integer(non_compliance_message_count),
        );
        data.add_field(
            "not_scopes_count".to_string(),
            ResolvedValue::Integer(not_scopes_count),
        );
        data.add_field(
            "resource_selectors_count".to_string(),
            ResolvedValue::Integer(resource_selectors_count),
        );
        data.add_field(
            "overrides_count".to_string(),
            ResolvedValue::Integer(overrides_count),
        );

        // Derived booleans
        let enforcement_mode = resp
            .get("enforcementMode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        data.add_field(
            "is_enforcing".to_string(),
            ResolvedValue::Boolean(enforcement_mode == "Default"),
        );
        data.add_field(
            "has_managed_identity".to_string(),
            ResolvedValue::Boolean(identity_type != "None" && !identity_type.is_empty()),
        );
        data.add_field(
            "has_non_compliance_messages".to_string(),
            ResolvedValue::Boolean(non_compliance_message_count > 0),
        );
        data.add_field(
            "is_initiative".to_string(),
            ResolvedValue::Boolean(kind == "initiative"),
        );
        data.add_field(
            "has_parameters".to_string(),
            ResolvedValue::Boolean(parameter_count > 0),
        );
        data.add_field(
            "has_not_scopes".to_string(),
            ResolvedValue::Boolean(not_scopes_count > 0),
        );

        let record_data = RecordData::from_json_value(resp);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["az_policy_assignment".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "az_policy_assignment" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'az_policy_assignment', got '{}'",
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
    fn not_found_matches_policy_assignment_not_found_paren() {
        let stderr = "ERROR: (PolicyAssignmentNotFound) The policy assignment \
                     'fx-does-not-exist-xyz' is not found.";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_policy_assignment_not_found_code_line() {
        let stderr = "ERROR: ...\nCode: PolicyAssignmentNotFound\nMessage: The policy \
                     assignment 'x' is not found.";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found_paren() {
        let stderr = "ERROR: (ResourceNotFound) The policy assignment does not exist.";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_resource_not_found_code_line() {
        let stderr = "ERROR: something\nCode: ResourceNotFound\nMessage: whatever";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_missing_subscription() {
        let stderr = "ERROR: (MissingSubscription) The request did not have a subscription or a \
                     valid tenant level resource provider.";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn not_found_matches_authz_failed_scoped_to_policy_assignments() {
        let stderr = "ERROR: (AuthorizationFailed) The client '7bcd6d2a-...' does not have \
                     authorization to perform action 'Microsoft.Authorization/policyAssignments/\
                     read' over scope '/subscriptions/.../providers/Microsoft.Authorization/\
                     policyAssignments/fake' or the scope is invalid.";
        assert!(AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn authz_failed_on_unrelated_scope_is_not_not_found() {
        let stderr = "ERROR: (AuthorizationFailed) scope \
                     '/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/\
                     virtualMachines/vm1'";
        assert!(!AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn forbidden_is_not_not_found() {
        let stderr = "ERROR: (Forbidden) Caller is not authorized to perform action on resource.";
        assert!(!AzPolicyAssignmentCollector::is_not_found(stderr));
    }

    #[test]
    fn classify_single_policy() {
        let pid = "/providers/Microsoft.Authorization/policyDefinitions/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
        assert_eq!(
            AzPolicyAssignmentCollector::classify_definition(pid),
            "single_policy"
        );
    }

    #[test]
    fn classify_initiative() {
        let pid = "/providers/Microsoft.Authorization/policySetDefinitions/095e4ed9-c835-4ab6-9439-b5644362a06c";
        assert_eq!(
            AzPolicyAssignmentCollector::classify_definition(pid),
            "initiative"
        );
    }

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(
            AzPolicyAssignmentCollector::classify_definition(""),
            "unknown"
        );
    }
}
