//! Azure Policy Assignment CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_policy_assignment;
//  pub use az_policy_assignment::create_az_policy_assignment_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates a single named Azure Policy
//! Assignment at a specified scope (subscription, resource group, or
//! management group) via `az policy assignment show --name <name>
//! --scope <arm-scope> --output json`. Exposes config-only scalars
//! (enforcement mode, definition kind, identity presence, parameter
//! count, notScopes count) plus the full assignment as RecordData for
//! per-parameter and per-non-compliance-message record_checks.
//!
//! This CTN covers the **assignment CONFIG surface** only
//! (`az policy assignment`). The separate **compliance EVALUATION
//! surface** (`az policy state`) is an eventually-consistent, distinct
//! API family and is modeled by a future `az_policy_compliance_state`
//! CTN with its own staleness-tolerance patterns. Keeping these two
//! apart is deliberate: assignment config is byte-stable across reads
//! (verified: zero drift on a 30s probe) while compliance state flaps.
//!
//! Requires Reader role at the assignment's scope. An RG-level Reader
//! cannot see subscription- or MG-scoped assignments (Azure RBAC
//! silently filters them to empty) so the calling SPN must have
//! Reader at or above the target scope.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE enforcing_allowed_locations
//!     found boolean = true
//!     enforcement_mode string = `Default`
//!     is_enforcing boolean = true
//!     is_initiative boolean = false
//!     parameter_count int >= 1
//!     record
//!         field parameters.listOfAllowedLocations.value[0] string = `eastus`
//!     record_end
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_policy_assignment_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_policy_assignment".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Azure Policy Assignment name (the short azure-normalized name, not the \
                          displayName)"
                .to_string(),
            example_values: vec!["fx-allowed-locations-rg".to_string()],
            validation_notes: Some(
                "Passed to `az policy assignment show --name`. Azure normalizes this to \
                 lower-case with hyphens; match the value from \
                 `az policy assignment list --query \"[].name\" -o tsv`."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "scope".to_string(),
            data_type: DataType::String,
            description: "Full ARM scope path the assignment is attached to. Accepts subscription, \
                          resource group, or management group scopes."
                .to_string(),
            example_values: vec![
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/\
                 rg-prooflayer-demo-eastus"
                    .to_string(),
                "/subscriptions/00000000-0000-0000-0000-000000000000".to_string(),
                "/providers/Microsoft.Management/managementGroups/my-mg".to_string(),
            ],
            validation_notes: Some(
                "Must be a valid ARM scope string. Malformed scopes (no /subscriptions/ prefix \
                 and no /providers/Microsoft.Management/managementGroups/ prefix) return \
                 MissingSubscription and surface as found=false. Case-sensitive in some segments."
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
                "Usually redundant because the `scope` argument already embeds the subscription. \
                 Only useful in multi-tenant sessions where `az` defaults to a different sub."
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
            "name",
            str_full.clone(),
            "Assignment name (Azure-normalized)",
            "fx-allowed-locations-rg",
        ),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID of the assignment",
            "/subscriptions/.../policyAssignments/fx-allowed-locations-rg",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type (always Microsoft.Authorization/policyAssignments)",
            "Microsoft.Authorization/policyAssignments",
        ),
        (
            "scope",
            str_full.clone(),
            "ARM scope the assignment is attached to",
            "/subscriptions/.../resourceGroups/rg-prooflayer-demo-eastus",
        ),
        (
            "display_name",
            str_full.clone(),
            "Human-readable assignment display name (may differ from `name`)",
            "Fixture - Allowed locations (RG)",
        ),
        (
            "description",
            str_full.clone(),
            "Free-text description (empty string when not set)",
            "",
        ),
        (
            "enforcement_mode",
            str_eq.clone(),
            "Enforcement mode (`Default` = enforce, `DoNotEnforce` = audit-only)",
            "Default",
        ),
        (
            "policy_definition_id",
            str_full.clone(),
            "Full ARM URI of the referenced policy definition OR policy set definition",
            "/providers/Microsoft.Authorization/policyDefinitions/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        ),
        (
            "policy_definition_kind",
            str_eq.clone(),
            "Derived: `single_policy` when policyDefinitionId points at a policyDefinitions URI, \
             `initiative` when it points at a policySetDefinitions URI",
            "single_policy",
        ),
        (
            "definition_version",
            str_full.clone(),
            "Definition version pin (empty string when absent). Format like `1.*.*` or `2.0.0`.",
            "1.*.*",
        ),
        (
            "resource_group",
            str_full.clone(),
            "Resource group name when the assignment is RG-scoped (empty for sub/MG-scoped)",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "location",
            str_eq.clone(),
            "Region for the assignment's managed identity (empty when no identity is set)",
            "eastus",
        ),
        (
            "identity_type",
            str_eq.clone(),
            "Managed identity type: `None`, `SystemAssigned`, `UserAssigned`, or \
             `SystemAssigned,UserAssigned`",
            "SystemAssigned",
        ),
        (
            "identity_principal_id",
            str_full.clone(),
            "SystemAssigned MI principal (service principal object) ID, empty when no SA identity",
            "88888888-8888-8888-8888-888888888888",
        ),
        (
            "identity_tenant_id",
            str_eq.clone(),
            "SystemAssigned MI tenant ID, empty when no SA identity",
            "11111111-1111-1111-1111-111111111111",
        ),
        (
            "metadata_created_by",
            str_full.clone(),
            "metadata.createdBy - typically a principal object ID (GUID)",
            "99999999-9999-9999-9999-999999999999",
        ),
        (
            "metadata_created_on",
            str_full.clone(),
            "metadata.createdOn - ISO 8601 timestamp string (informational only - not for drift \
             detection since timestamps would flap if Azure ever updates this; verified stable)",
            "2026-04-15T20:49:56.1557256Z",
        ),
        (
            "system_data_created_by",
            str_full.clone(),
            "systemData.createdBy - UPN / friendly name of creator (empty when absent)",
            "admin@example.com",
        ),
        (
            "system_data_created_by_type",
            str_eq.clone(),
            "systemData.createdByType - principal class (`User`, `ManagedIdentity`, \
             `Application`, `Key`)",
            "User",
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

    // booleans
    for (name, desc, example, notes) in [
        (
            "found",
            "Whether the policy assignment was found at the given scope",
            "true",
            None,
        ),
        (
            "is_enforcing",
            "Derived: true when enforcement_mode is Default (i.e., violations block writes / \
             trigger DINE)",
            "true",
            Some(
                "Pair with `enforcement_mode` when authoring: `is_enforcing=true` is the policy \
                 signal most controls care about. DoNotEnforce is audit-only and will not remediate.",
            ),
        ),
        (
            "has_managed_identity",
            "Derived: true when identity_type is not `None` (SystemAssigned or UserAssigned or both)",
            "true",
            Some(
                "DINE and Modify policies require an MI. Assignments without one are either \
                 pure audit policies or mis-provisioned DINE/Modify assignments.",
            ),
        ),
        (
            "has_non_compliance_messages",
            "Derived: true when nonComplianceMessages[] is non-empty",
            "true",
            None,
        ),
        (
            "is_initiative",
            "Derived: true when policyDefinitionId contains `/policySetDefinitions/` (assignment \
             references a policy set, not a single policy)",
            "false",
            Some(
                "Used to branch on assignment shape. Initiatives require different per-member \
                 compliance reporting - the record_checks syntax stays the same but the \
                 `nonComplianceMessages[]` entries carry `policyDefinitionReferenceId` fields \
                 pinning messages to specific policies within the set.",
            ),
        ),
        (
            "has_parameters",
            "Derived: true when parameters object is present and non-empty",
            "true",
            None,
        ),
        (
            "has_not_scopes",
            "Derived: true when notScopes[] is non-empty (the assignment excludes at least one \
             sub-scope from evaluation)",
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
            "parameter_count",
            "Number of entries in the parameters map (0 when absent)",
            "1",
            None,
        ),
        (
            "non_compliance_message_count",
            "Number of entries in nonComplianceMessages[] (0 when absent)",
            "1",
            None,
        ),
        (
            "not_scopes_count",
            "Number of entries in notScopes[] - scopes excluded from the assignment (0 when absent)",
            "0",
            Some(
                "Use `> 0` to assert that an assignment must carve out at least one exclusion, \
                 or `= 0` to assert no exclusions exist.",
            ),
        ),
        (
            "resource_selectors_count",
            "Number of entries in resourceSelectors[] (0 when absent). Advanced targeting feature \
             for scoping to specific resource types/locations within the assignment scope.",
            "0",
            None,
        ),
        (
            "overrides_count",
            "Number of entries in overrides[] (0 when absent). Used on initiatives to override \
             specific policy member settings.",
            "0",
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
            description: "Full policy assignment object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for nested assertions: \
                 `field parameters.listOfAllowedLocations.value[0] string = \\`eastus\\`` or \
                 `field nonComplianceMessages[0].message string contains \\`informational\\`` or \
                 `field notScopes[0] string contains \\`rg-exclude\\``."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("name", "name_input"),
        ("scope", "scope_input"),
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
        "name".to_string(),
        "id".to_string(),
        "type".to_string(),
        "scope".to_string(),
        "display_name".to_string(),
        "description".to_string(),
        "enforcement_mode".to_string(),
        "policy_definition_id".to_string(),
        "policy_definition_kind".to_string(),
        "definition_version".to_string(),
        "resource_group".to_string(),
        "location".to_string(),
        "identity_type".to_string(),
        "identity_principal_id".to_string(),
        "identity_tenant_id".to_string(),
        "metadata_created_by".to_string(),
        "metadata_created_on".to_string(),
        "system_data_created_by".to_string(),
        "system_data_created_by_type".to_string(),
        "is_enforcing".to_string(),
        "has_managed_identity".to_string(),
        "has_non_compliance_messages".to_string(),
        "is_initiative".to_string(),
        "has_parameters".to_string(),
        "has_not_scopes".to_string(),
        "parameter_count".to_string(),
        "non_compliance_message_count".to_string(),
        "not_scopes_count".to_string(),
        "resource_selectors_count".to_string(),
        "overrides_count".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "scope",
        "display_name",
        "description",
        "enforcement_mode",
        "policy_definition_id",
        "policy_definition_kind",
        "definition_version",
        "resource_group",
        "location",
        "identity_type",
        "identity_principal_id",
        "identity_tenant_id",
        "metadata_created_by",
        "metadata_created_on",
        "system_data_created_by",
        "system_data_created_by_type",
        "is_enforcing",
        "has_managed_identity",
        "has_non_compliance_messages",
        "is_initiative",
        "has_parameters",
        "has_not_scopes",
        "parameter_count",
        "non_compliance_message_count",
        "not_scopes_count",
        "resource_selectors_count",
        "overrides_count",
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
        collector_type: "az_policy_assignment".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(1500),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
