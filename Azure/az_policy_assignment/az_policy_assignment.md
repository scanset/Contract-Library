# `az_policy_assignment` CTN

Read-only, control-plane validator for a single named **Azure Policy Assignment** at a subscription, resource group, or management group scope. Config surface only — compliance evaluation state (`az policy state`) is a separate future CTN.

## What it checks

A single `az policy assignment show --name <name> --scope <scope> --output json` call. The response is parsed into:

- **Config scalars**: name, id, type, scope, displayName, description, enforcementMode, policyDefinitionId, definitionVersion, resourceGroup, location
- **Identity scalars**: identity_type, identity_principal_id, identity_tenant_id (populated only for assignments with a managed identity — DINE/Modify policies)
- **Provenance scalars**: metadata_created_by/on, systemData_created_by/by_type
- **Derived classification**: `policy_definition_kind` (`single_policy` vs `initiative`), `is_enforcing`, `has_managed_identity`, `is_initiative`, plus boolean flags and counts for optional arrays (parameters, nonComplianceMessages, notScopes, resourceSelectors, overrides)
- **Full response** as RecordData for nested assertions on parameters, messages, and excluded scopes

All config fields were verified byte-stable across back-to-back reads (30s drift probe on a SystemAssigned-MI assignment returned zero diff). No fields are drift-sensitive.

## OBJECT inputs

| Field | Required | Example | Notes |
|---|---|---|---|
| `name` | yes | `fx-allowed-locations-rg` | Azure-normalized short name, not displayName |
| `scope` | yes | `/subscriptions/.../resourceGroups/rg-prooflayer-demo-eastus` | Accepts subscription, RG, or MG scope strings |
| `subscription` | no | `00000000-0000-0000-0000-000000000000` | Override; usually redundant with scope |

## STATE fields

### Strings (19)
`name`, `id`, `type`, `scope`, `display_name`, `description`, `enforcement_mode`, `policy_definition_id`, `policy_definition_kind`, `definition_version`, `resource_group`, `location`, `identity_type`, `identity_principal_id`, `identity_tenant_id`, `metadata_created_by`, `metadata_created_on`, `system_data_created_by`, `system_data_created_by_type`

Absent/null fields coalesce to empty string. `identity_type` defaults to `"None"` when no identity block is present.

### Booleans (7)
- `found` — NotFound flag
- `is_enforcing` — derived: `enforcement_mode == "Default"`
- `has_managed_identity` — derived: `identity_type != "None"`
- `has_non_compliance_messages` — derived: count > 0
- `is_initiative` — derived: `policyDefinitionId contains "/policySetDefinitions/"`
- `has_parameters` — derived: count > 0
- `has_not_scopes` — derived: count > 0

### Integers (5)
`parameter_count`, `non_compliance_message_count`, `not_scopes_count`, `resource_selectors_count`, `overrides_count`

### Record
`record` maps to the full JSON response. Use `record_checks` for:
- `field parameters.<paramName>.value[0] string = \`...\``
- `field nonComplianceMessages[0].message string contains \`...\``
- `field notScopes[0] string contains \`rg-exclude\``
- `field overrides[0].kind string = \`policyEffect\`` (initiatives only)

## NotFound handling

Four stderr patterns all map to `found=false`:

| Pattern | Source | Meaning |
|---|---|---|
| `(PolicyAssignmentNotFound)` / `Code: PolicyAssignmentNotFound` | Azure API | Assignment name does not exist at scope (policy-API-specific code - the one Azure actually returns for `az policy assignment show` on a missing name) |
| `(ResourceNotFound)` / `Code: ResourceNotFound` | Azure API | Generic ARM NotFound - retained as fallback |
| `(AuthorizationFailed)` with `Microsoft.Authorization/policyAssignments` in message | Azure RBAC | Caller lacks read at this scope (Azure treats missing == forbidden from caller perspective) |
| `(MissingSubscription)` / `Code: MissingSubscription` | Azure API | Malformed ARM scope (missing `/subscriptions/` prefix) |

All other non-zero exits bubble up as collection errors.

## Example policy

```esp
STATE enforcing_allowed_locations
    found boolean = true
    enforcement_mode string = `Default`
    is_enforcing boolean = true
    is_initiative boolean = false
    policy_definition_kind string = `single_policy`
    parameter_count int >= 1
    has_managed_identity boolean = false
    record
        field parameters.listOfAllowedLocations.value[0] string = `eastus`
    record_end
STATE_END

CRI AND
    CTN az_policy_assignment
        TEST all all AND
        STATE_REF enforcing_allowed_locations
        OBJECT_REF my_assignment
    CTN_END
CRI_END
```

## Permissions

- **Subscription-Reader** — can see all assignments at sub, all RGs, and any MG the sub belongs to
- **RG-Reader** — can see only RG-scoped assignments in that RG; sub- and MG-scoped assignments silently filter to empty (AuthorizationFailed, surfaced as found=false)
- **MG-Reader** — needed to read MG-scoped assignments directly

For a compliance-scanning SPN intended to validate assignments across a subscription, Subscription-Reader is the minimum viable role.

## Non-Goals

- **No assignment mutation.** No create/update/delete. CTN is pure read.
- **No compliance state evaluation.** `az policy state` is a separate eventually-consistent API family; building that as a scalar CTN would cause flapping. It will have its own CTN (`az_policy_compliance_state`) with retry + staleness-tolerance patterns.
- **No policy definition inspection.** The CTN records `policyDefinitionId` and classifies single vs initiative, but does not dereference the definition to inspect rules, effects, or parameters schema. That would require a second API call and is out of scope.
- **No cross-assignment correlation.** Each assignment is validated in isolation. Detecting conflicts between two assignments with overlapping scopes would require batch enumeration and is not supported.
- **No `--expand` on show.** The optional `LatestDefinitionVersion` / `EffectiveDefinitionVersion` expansions are not yet exposed; `definitionVersion` as written in the assignment is exposed as-is. Expansion can be added behind a `behavior` modifier if needed.
- **No `--policy` filter flag.** Verified not to exist on `az policy assignment list` in `az` 2.85.0. Filtering by definition ID is client-side only (done in the ESP policy via `policy_definition_id contains ...`).

## Drift characteristics

Verified with a 30-second drift probe on the DINE fixture (`fx-dine-sysassigned-mi`, which has a SystemAssigned managed identity and is the most drift-prone config). Diff between two back-to-back `show` calls: **empty**. Every top-level key is byte-stable. All scalar fields can safely be asserted without flap risk.

## Coverage tested against

Live validation performed against fixtures provisioned by `azure/modules/policy_fixtures/`:

| Fixture | Exercises |
|---|---|
| `fx-allowed-locations-rg` | Single-policy, Default enforcement, parameters map |
| `fx-audit-unmanaged-disks` | DoNotEnforce enforcement, nonComplianceMessages |
| `fx-dine-sysassigned-mi` | SystemAssigned MI, location field, DINE parameters |
| `fx-...-insecure-password-audit` (sub-scoped) | Initiative shape (`/policySetDefinitions/`) |
| `fx-...-notscopes` (sub-scoped) | notScopes[] excluding secondary RG |

Sub-scoped fixtures require the scanning SPN to have Reader at subscription scope.
