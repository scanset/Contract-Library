# `az_policy_compliance_state` CTN

Read-only, evaluation-plane validator for Azure Policy compliance state at a subscription, resource group, or management group scope. Companion to `az_policy_assignment` (which covers the static assignment-config surface). This CTN covers the eventually-consistent `Microsoft.PolicyInsights/policyStates` aggregate API.

## What it checks

A single `az policy state summarize --resource-group <rg> | --subscription <sub> | --management-group <name> [--policy-assignment <name>] --output json` call. The response is parsed into:

- **Aggregate counters**: `non_compliant_resources`, `non_compliant_policies`, `compliant_resource_count`, `noncompliant_resource_count`, `unknown_resource_count`, `total_evaluated_count`, `resource_detail_count`, `assignment_count`
- **Assignment identification**: `policy_assignment_id`, `policy_set_definition_id` (first entry in response when filtered to one assignment)
- **Derived posture bits**: `found`, `has_evaluations`, `is_compliant`, `is_initiative`, `has_noncompliant_resources`, `has_noncompliant_policies`
- **Full summarize response as RecordData** for nested assertions on `policyAssignments[]` entries, `policyDefinitions[]`, `resourceDetails[]`, etc. The drift-prone `queryResultsUri` field is **stripped recursively** from the response before exposing so nested record assertions never flap.

Every non-stripped field was verified byte-stable across back-to-back reads (30s drift probe on the `fx-allowed-locations-rg` fixture — diff limited to `queryResultsUri` lines only).

## OBJECT inputs

| Field | Required | Example | Notes |
|---|---|---|---|
| `scope` | yes | `/subscriptions/.../resourceGroups/rg-prooflayer-demo-eastus` | ARM scope URI. Parsed into `--resource-group`, `--subscription`, or `--management-group` based on shape. |
| `policy_assignment_name` | no | `fx-allowed-locations-rg` | When set, adds `--policy-assignment` to narrow the summary to a single assignment. Azure-normalized short name, not displayName. |
| `subscription` | no | `00000000-0000-0000-0000-000000000000` | Override for the CLI session; usually redundant when the scope already embeds the subscription. |

### Scope URI parsing

| URI pattern | `az` flags emitted |
|---|---|
| `/providers/Microsoft.Management/managementGroups/<mg>` | `--management-group <mg>` |
| `/subscriptions/<sub>/resourceGroups/<rg>` (with or without a deeper suffix) | `--resource-group <rg> --subscription <sub>` |
| `/subscriptions/<sub>` (exact) | `--subscription <sub>` |

Anything else returns `InvalidObjectConfiguration`. The `/resourceGroups/` segment match is case-insensitive because Azure normalizes it inconsistently (some CLI outputs emit `/resourcegroups/`).

## STATE fields

### Strings (3)
`scope`, `policy_assignment_id`, `policy_set_definition_id`

- `scope` is echoed from the OBJECT input so it can be asserted trivially.
- `policy_assignment_id` is the `policyAssignmentId` from `policyAssignments[0]` — empty when the response contains no assignments.
- `policy_set_definition_id` is `policyAssignments[0].policySetDefinitionId` — empty string for single-policy assignments.

### Booleans (6)
- `found` — **derived from response shape, NOT from a NotFound stderr**: `policyAssignments.len() > 0`.
- `has_evaluations` — `total_evaluated_count > 0`; distinguishes "assignment exists" from "assignment has been evaluated".
- `is_compliant` — `non_compliant_resources == 0 AND has_evaluations`. The canonical posture bit. Returns false when zero resources have been evaluated so a not-yet-evaluated assignment does not silently pass.
- `is_initiative` — `policy_set_definition_id != ""`.
- `has_noncompliant_resources` — `non_compliant_resources > 0`.
- `has_noncompliant_policies` — `non_compliant_policies > 0`. Distinct from the resource-level signal because Azure tracks policy-level and resource-level counts separately in the response.

### Integers (8)
`assignment_count`, `non_compliant_resources`, `non_compliant_policies`, `compliant_resource_count`, `noncompliant_resource_count`, `unknown_resource_count`, `total_evaluated_count`, `resource_detail_count`

- `non_compliant_resources` comes from `results.nonCompliantResources` (top level).
- `compliant_resource_count`, `noncompliant_resource_count`, `unknown_resource_count` come from summing `results.resourceDetails[?complianceState=='<state>'].count`. Case-insensitive state match.
- `total_evaluated_count` sums every `results.resourceDetails[].count` - the universe of resources evaluated against the summarized assignment(s) at this scope.

### Record
`record` maps to the full `summarize` response (`queryResultsUri` stripped). Use `record_checks` for:
- `field policyAssignments[0].results.resourceDetails[0].complianceState string = \`compliant\``
- `field policyAssignments[0].policyDefinitions length >= 1`
- `field results.nonCompliantResources int = 0`

## Error / empty-result handling

**Fundamentally different from every prior Azure CTN.** The Policy Insights API is a query-by-time-window surface rather than a resource-fetch surface, so missing scopes and missing assignment names return `200 OK` with empty `policyAssignments: []` and zeroed `results`, not an error.

| Scenario | CLI exit | How this CTN models it |
|---|---|---|
| Scope has visible assignments | 0 | `found=true`, counts populated |
| Scope has zero assignments visible to the caller (missing RG, missing assignment name, or RBAC-filtered) | 0 | `found=false`, counts all 0 |
| Malformed `--filter` OData expression | 1, `Code: InvalidFilterInQueryString` | `CollectionError::CollectionFailed` (author bug — ESP policy needs fixing) |
| Malformed scope URI (doesn't match any pattern) | n/a (client-side) | `CollectionError::InvalidObjectConfiguration` |

There is deliberately **no `is_not_found()` stderr matcher** in this collector, because the API never emits one. `found` is derived from the response shape.

## Eventual consistency

Compliance evaluation is asynchronous. After a new assignment is created, after a resource is created under an existing assignment, or after a manual `az policy state trigger-scan`, up to ~15 minutes can pass before `summarize` reports non-zero counts. Symptoms during the gap:

- `found=true`, `has_evaluations=false`, `total_evaluated_count=0`, `is_compliant=false`.
- All `resourceDetails[]` arrays empty.

Guard freshness-sensitive ESP assertions on `has_evaluations=true` so a brand-new assignment does not cause a false Fail while Azure is catching up.

## Drift characteristics

30-second drift probe on `fx-allowed-locations-rg` (RG scope + `--policy-assignment`):

- **4 lines differ** — every one is a `queryResultsUri` with an embedded `$from=...&$to=...` window that shifts with each call.
- **All other fields byte-stable.** `policyAssignments[]`, `results.*`, `resourceDetails[].count`, all IDs, all counts.

The collector recursively strips `queryResultsUri` from the response before storing as RecordData, so nested `record_checks` cannot flap either.

## Example policy

```esp
STATE assignment_is_compliant
    found boolean = true
    has_evaluations boolean = true
    is_compliant boolean = true
    non_compliant_resources int = 0
    compliant_resource_count int >= 1
    is_initiative boolean = false
STATE_END

CRI AND
    CTN az_policy_compliance_state
        TEST all all AND
        STATE_REF assignment_is_compliant
        OBJECT_REF my_scope
    CTN_END
CRI_END
```

## Permissions

Same Reader hierarchy as `az_policy_assignment`:

- **Subscription-Reader** — can summarize at sub, any RG in the sub, or any MG the sub belongs to. Also sees inherited assignments (e.g. sub-scoped fixtures showing up in an RG-scope summary).
- **RG-Reader** — can summarize only that RG; sub- and MG-scoped summaries return empty even if assignments exist there (RBAC silently filters).
- **MG-Reader** — required to summarize at MG scope.

For a compliance-scanning SPN intended to validate a subscription, Subscription-Reader is the minimum viable role.

## Non-Goals

- **No `list` mode (per-record query).** `az policy state list` returns a flat array with one record per (resource, policy) pair; at sub/MG scope this can be thousands of records. Per-resource assertions belong in a future separate CTN (tentative `az_policy_state_record`) with its own volume controls (`--top` required, OData filter pass-through). This CTN is posture-only.
- **No `trigger-scan`.** That is a mutation. If fresh evaluation is needed before scanning, it is a manual operator action, not a CTN side effect.
- **No `--filter` OData pass-through.** Summarize does accept `--filter`, but deciding-what-is-compliant happens in the summarize aggregate already; filter-driven custom slicing is a power-user knob that adds one more author-side failure mode (the only live error this CTN can hit) without clear wins for posture queries. Deferred.
- **No `--from`/`--to` time-window control in v1.** The Azure default 24h window is appropriate for almost every posture question. Longer retention queries are a future `behavior time_window_hours N` modifier if needed.
- **No multi-assignment matrix.** When `policy_assignment_name` is absent the CTN summarizes the whole scope aggregate but exposes only first-assignment identity fields (`policy_assignment_id`, `policy_set_definition_id`). To validate N assignments, author N OBJECTs, one per assignment.
- **No per-resource breakdown as scalars.** `resourceDetails[]` is available in RecordData for `record_checks` but not promoted to individual scalar fields - the useful aggregate is `compliant_resource_count` / `noncompliant_resource_count` / `unknown_resource_count`, which are already promoted.

## Coverage tested against

Live validation performed against fixtures provisioned by `azure/modules/policy_fixtures/`:

| Fixture | Exercises |
|---|---|
| `fx-allowed-locations-rg` | RG-scoped single-policy assignment with all evaluations Compliant — baseline posture path |
| (no assignment) | Empty-result path: `policy_assignment_name=<nonexistent>` returns `found=false` via empty `policyAssignments[]` |

Discovery observed 96 state records / 74 Compliant + 22 NonCompliant at RG scope on the subscription, proving the aggregate counters wire correctly across Compliant / NonCompliant states. `Unknown`, `Exempt`, `notStarted`, `notApplicable` API states exist per the spec but are not represented in the tested tenant.
