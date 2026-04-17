//! Azure Policy Compliance State CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_policy_compliance_state;
//  pub use az_policy_compliance_state::create_az_policy_compliance_state_contract;
//
///////////////////////////////////////////////////////

//! Read-only, evaluation-plane validator for the **compliance state**
//! surface of Azure Policy (`Microsoft.PolicyInsights/policyStates`).
//! Companion to `az_policy_assignment`, which covers the assignment
//! CONFIG surface; this CTN covers the eventually-consistent
//! EVALUATION surface.
//!
//! Primary command: `az policy state summarize --scope <arm-scope>
//! [--policy-assignment <name>] --output json`. Summarize is preferred
//! over `list` because:
//!
//! 1. It returns a single bounded dict regardless of evaluation volume
//!    (list returns one flat array per resource-policy pair; a sub scope
//!    can have thousands).
//! 2. The aggregate counters (`nonCompliantResources`, per-state
//!    `resourceDetails[].count`) are the natural ESP posture signal:
//!    "is this assignment compliant?" -> yes iff nonCompliantResources=0.
//! 3. Every field except `queryResultsUri` is byte-stable across
//!    back-to-back reads (verified: 30s drift probe diff = 4 lines, all
//!    queryResultsUri timestamp embeds). `queryResultsUri` is stripped
//!    from scalar surface and excluded from RecordData.
//!
//! ## Fundamentally different error surface from prior Azure CTNs
//!
//! Unlike `az group show` or `az policy assignment show`, the Policy
//! Insights API treats missing scopes as empty result sets, not errors.
//! A summarize at a nonexistent RG or for a nonexistent assignment name
//! returns exit 0 and an empty `policyAssignments[]`. Therefore:
//!
//! - **No `is_not_found()` stderr matcher is needed.**
//! - `found` is derived from `policyAssignments.len() > 0`.
//! - The only true error mode is `Code: InvalidFilterInQueryString` on
//!   malformed `--filter`; that bubbles up as a CTN error since it is
//!   an author-side bug in the ESP policy, not a runtime state.
//!
//! ## Notes on eventual consistency
//!
//! Compliance evaluation is asynchronous. After a new assignment is
//! created or a `trigger-scan` is issued, up to ~15 min can pass before
//! `summarize` reports non-zero counts. During that window,
//! `total_evaluated_count` will be 0 and `has_evaluations` will be
//! false. Author ESP policies around `has_evaluations=true` guard when
//! freshness matters.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE posture_clean
//!     found boolean = true
//!     has_evaluations boolean = true
//!     is_compliant boolean = true
//!     non_compliant_resources int = 0
//!     compliant_resource_count int >= 1
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_policy_compliance_state_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_policy_compliance_state".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Full ARM scope path at which to summarize compliance state. Accepts \
                          subscription, resource group, or management group scopes."
                .to_string(),
            example_values: vec![
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/\
                 rg-prooflayer-demo-eastus"
                    .to_string(),
                "/subscriptions/00000000-0000-0000-0000-000000000000".to_string(),
                "/providers/Microsoft.Management/managementGroups/my-mg".to_string(),
            ],
            validation_notes: Some(
                "Passed as either `--resource-group`, `--subscription`, or `--management-group` \
                 depending on URI shape. Malformed scopes surface as empty result sets (exit 0) \
                 rather than errors - `found=false` is the signal."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "policy_assignment_name".to_string(),
            data_type: DataType::String,
            description: "When set, narrows the summary to a single named assignment via \
                          `--policy-assignment`. When absent, returns an aggregate across every \
                          assignment visible at the scope (including inherited parent-scope \
                          assignments and built-in initiatives like SecurityCenterBuiltIn)."
                .to_string(),
            example_values: vec!["fx-allowed-locations-rg".to_string()],
            validation_notes: Some(
                "Use the Azure-normalized short name, not the displayName. A name that does not \
                 exist returns empty data (found=false) rather than an error. For initiatives, \
                 use the assignment name, not the initiative definition name."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subscription".to_string(),
            data_type: DataType::String,
            description: "Subscription ID override for the CLI session".to_string(),
            example_values: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            validation_notes: Some(
                "Usually redundant because the scope already embeds the subscription."
                    .to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    // scalar strings
    for (name, ops, desc, example) in [
        (
            "scope",
            str_full.clone(),
            "ARM scope echoed from the OBJECT (for assertion convenience)",
            "/subscriptions/.../resourceGroups/rg-prooflayer-demo-eastus",
        ),
        (
            "policy_assignment_id",
            str_full.clone(),
            "Full ARM URI of the first (and only, when --policy-assignment is used) assignment \
             in the response. Empty string when the response contains no assignments.",
            "/subscriptions/.../providers/Microsoft.Authorization/policyAssignments/\
             fx-allowed-locations-rg",
        ),
        (
            "policy_set_definition_id",
            str_full.clone(),
            "Full ARM URI of the policy set definition referenced by the assignment. Empty string \
             for single-policy assignments and when no assignments are in the response.",
            "",
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::String,
                allowed_operations: ops,
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }
    // Minimal compile-time use of str_eq so clippy stays quiet without changing field semantics.
    let _ = &str_eq;

    // booleans
    for (name, desc, example, notes) in [
        (
            "found",
            "Whether any policy assignment data was returned at this scope. \
             Derived: `policyAssignments.len() > 0`. Empty responses are not errors in \
             Policy Insights - missing scope/assignment/filter-mismatch all yield found=false.",
            "true",
            Some(
                "This is the canonical existence check for this CTN. Note that found=true does \
                 not imply anything has been EVALUATED yet - use `has_evaluations` for that.",
            ),
        ),
        (
            "has_evaluations",
            "Derived: true when `total_evaluated_count > 0`. Distinguishes 'assignment exists \
             but no resources have been evaluated yet' (eventually-consistent gap after \
             trigger-scan or assignment creation) from 'assignment has been evaluated'.",
            "true",
            Some(
                "Guard subsequent compliance assertions on this field when evaluation freshness \
                 matters. Combine with `behavior time_window_hours N` if the default 24h window \
                 is too narrow/wide.",
            ),
        ),
        (
            "is_compliant",
            "Derived: true iff `non_compliant_resources == 0 AND total_evaluated_count > 0`. \
             The canonical posture bit. Returns false when zero resources have been evaluated \
             so that a not-yet-evaluated assignment does not falsely pass.",
            "true",
            None,
        ),
        (
            "is_initiative",
            "Derived: true when `policy_set_definition_id` is non-empty (the summarized \
             assignment is an initiative, not a single policy).",
            "false",
            None,
        ),
        (
            "has_noncompliant_resources",
            "Derived: true when `non_compliant_resources > 0`.",
            "false",
            None,
        ),
        (
            "has_noncompliant_policies",
            "Derived: true when `non_compliant_policies > 0`. Distinct from resource-level \
             noncompliance because Azure tracks policy-level and resource-level counts \
             separately - an initiative can have 0 noncompliant policies while still having \
             noncompliant resources when the aggregation rules classify things that way.",
            "false",
            None,
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: bool_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    // integers
    for (name, desc, example, notes) in [
        (
            "assignment_count",
            "Number of entries in `policyAssignments[]` in the response. 1 when filtered via \
             --policy-assignment (or 0 if the name does not exist); N when summarizing a whole \
             scope.",
            "1",
            None,
        ),
        (
            "non_compliant_resources",
            "Aggregate `results.nonCompliantResources` across the response. When filtered to a \
             single assignment, this is the assignment-specific count; otherwise it is the \
             scope-wide sum.",
            "0",
            Some(
                "This is the field most ESP compliance policies will assert `= 0` against.",
            ),
        ),
        (
            "non_compliant_policies",
            "Aggregate `results.nonCompliantPolicies`. Null in the API is coalesced to 0. See \
             `has_noncompliant_policies` for the derived boolean.",
            "0",
            None,
        ),
        (
            "compliant_resource_count",
            "Sum of `results.resourceDetails[?complianceState=='compliant'].count` across the \
             response. The count of evaluated resources that evaluated to Compliant.",
            "26",
            None,
        ),
        (
            "noncompliant_resource_count",
            "Sum of `results.resourceDetails[?complianceState=='noncompliant'].count`. Should \
             equal `non_compliant_resources` in well-formed responses but exposed separately so \
             policies can assert both and catch API drift.",
            "0",
            None,
        ),
        (
            "unknown_resource_count",
            "Sum of `results.resourceDetails[?complianceState=='unknown'].count`. Nonzero \
             indicates evaluation errors on some resources.",
            "0",
            None,
        ),
        (
            "total_evaluated_count",
            "Sum of every `results.resourceDetails[].count` - the total number of resources \
             that have been evaluated at this scope against the summarized assignment(s), \
             across all compliance states.",
            "26",
            Some(
                "Zero total_evaluated_count is the unambiguous signal for 'evaluation has not \
                 yet propagated'. Gate freshness-sensitive assertions with \
                 `has_evaluations=true`.",
            ),
        ),
        (
            "resource_detail_count",
            "Number of entries in `results.resourceDetails[]`. Equals the number of distinct \
             complianceState values observed (at most one entry per state). Typically 1-3.",
            "1",
            None,
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Int,
                allowed_operations: int_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full summarize response as RecordData (with queryResultsUri fields \
                          stripped so nested assertions stay drift-free)."
                .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for nested assertions: \
                 `field policyAssignments[0].results.resourceDetails[0].complianceState \
                    string = \\`compliant\\`` or \
                 `field policyAssignments[0].policyDefinitions length >= 1`. \
                 queryResultsUri has been stripped out of the record because it embeds a request \
                 timestamp and would flap between calls."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("scope", "scope_input"),
        ("policy_assignment_name", "policy_assignment_name_input"),
        ("subscription", "subscription"),
    ] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(obj.to_string(), col.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "scope".to_string(),
        "policy_assignment_id".to_string(),
        "policy_set_definition_id".to_string(),
        "has_evaluations".to_string(),
        "is_compliant".to_string(),
        "is_initiative".to_string(),
        "has_noncompliant_resources".to_string(),
        "has_noncompliant_policies".to_string(),
        "assignment_count".to_string(),
        "non_compliant_resources".to_string(),
        "non_compliant_policies".to_string(),
        "compliant_resource_count".to_string(),
        "noncompliant_resource_count".to_string(),
        "unknown_resource_count".to_string(),
        "total_evaluated_count".to_string(),
        "resource_detail_count".to_string(),
    ];

    for field in &[
        "found",
        "scope",
        "policy_assignment_id",
        "policy_set_definition_id",
        "has_evaluations",
        "is_compliant",
        "is_initiative",
        "has_noncompliant_resources",
        "has_noncompliant_policies",
        "assignment_count",
        "non_compliant_resources",
        "non_compliant_policies",
        "compliant_resource_count",
        "noncompliant_resource_count",
        "unknown_resource_count",
        "total_evaluated_count",
        "resource_detail_count",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "resource".to_string());

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_policy_compliance_state".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(4),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
