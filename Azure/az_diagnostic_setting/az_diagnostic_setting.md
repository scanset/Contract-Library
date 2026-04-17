# az_diagnostic_setting

## Overview

**Read-only, control-plane-only.** This CTN validates a single named
Azure diagnostic setting attached to a target resource (Key Vault, NSG,
Storage Account, SQL server, etc.) via a single Azure CLI call —
`az monitor diagnostic-settings show --name <setting>
--resource <target ARM ID> [--subscription <id>] --output json`. Returns
destination scalars (Log Analytics workspace, Event Hub, Storage
Account, Marketplace), per-category log + metric record arrays, and
derived counts for enabled/disabled categories and destination
population.

Diagnostic settings are child resources scoped by their parent's ARM
resource ID — this CTN's OBJECT therefore takes a `resource_id` +
`setting_name` pair rather than the single-name shape used by other
Azure CTNs. Subscription-level activity-log diagnostic settings are a
separate API surface with a different response shape
(`{value:[...]}` vs bare `[...]`) and are **out of scope** for this
CTN.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode — see `az_resource_group.md` for the full env-var
matrix)
**Collection Method:** Single Azure CLI command per object via the shared
hardened `SystemCommandExecutor`.
**Scope:** Control-plane only, read-only.

---

## Environment Variables

All Azure CTNs share a single executor factory -
`agent::contract_kit::commands::az::create_az_executor()` - wired in via
`registry.rs`. `az_diagnostic_setting` inherits the same env surface as
every other Azure CTN - no per-collector overrides. See `az_key_vault.md`
for the full env-var table (SPN+secret, SPN+cert, workload identity,
managed identity, cached `az login`, plus `PATH` pin and `az` binary
whitelist).

---

## Object Fields

| Field          | Type   | Required | Description                                                | Example                                                                                          |
| -------------- | ------ | -------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `resource_id`  | string | **Yes**  | Full ARM resource ID of the TARGET resource                | `/subscriptions/.../resourceGroups/rg-prooflayer-demo-eastus/providers/Microsoft.KeyVault/vaults/kv-prooflayer-demo-ybuu` |
| `setting_name` | string | **Yes**  | Name of the diagnostic setting                             | `diag-kv`                                                                                        |
| `subscription` | string | opt      | Subscription ID override                                   | `00000000-0000-0000-0000-000000000000`                                                           |

`resource_id` must be a full ARM ID — copy from
`az <service> show --query id -o tsv`. Azure normalizes the returned
`id` field with lowercased provider segments
(`resourcegroups`, `microsoft.keyvault`, `microsoft.insights`); don't
compare against the input verbatim, and the CTN exposes `id` for
traceability, not equality assertions.

---

## Commands Executed

```
az monitor diagnostic-settings show \
    --name diag-kv \
    --resource /subscriptions/.../vaults/kv-prooflayer-demo-ybuu \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per diagnostic setting object. `list` is not used — the CTN
operates on a single named setting by design. Policies that need
"resource has at least one setting" semantics should author a separate
OBJECT per known setting name, or a future batch-mode CTN variant.

---

## Collected Data Fields (scalars)

| Field                              | Type   | Source                                                       | Notes                                                                       |
| ---------------------------------- | ------ | ------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `found`                            | bool   | exit-code + stderr                                           | `true` on 0; `false` on any of 3 NotFound patterns                          |
| `name`                             | string | `name`                                                       | Setting name                                                                |
| `id`                               | string | `id`                                                         | ARM ID of the setting (may be lowercased by Azure)                          |
| `type`                             | string | `type`                                                       | Always `Microsoft.Insights/diagnosticSettings`                              |
| `target_resource_group`            | string | `resourceGroup`                                              | RG of the TARGET resource (not the setting)                                 |
| `workspace_id`                     | string | `workspaceId`                                                | Log Analytics ARM ID; empty when not configured                             |
| `event_hub_name`                   | string | `eventHubName`                                               | Empty when not configured                                                   |
| `event_hub_authorization_rule_id`  | string | `eventHubAuthorizationRuleId`                                | Empty when not configured                                                   |
| `storage_account_id`               | string | `storageAccountId`                                           | Empty when not configured                                                   |
| `marketplace_partner_id`           | string | `marketplacePartnerId`                                       | Empty when not configured                                                   |
| `service_bus_rule_id`              | string | `serviceBusRuleId`                                           | Legacy; empty on modern settings                                            |
| `log_analytics_destination_type`   | string | `logAnalyticsDestinationType`                                | `Dedicated`, `AzureDiagnostics`, or empty                                   |
| `has_workspace_destination`        | bool   | derived: `workspace_id != ""`                                | **Key compliance signal**                                                   |
| `has_event_hub_destination`        | bool   | derived: `event_hub_authorization_rule_id != ""`             |                                                                             |
| `has_storage_destination`          | bool   | derived: `storage_account_id != ""`                          |                                                                             |
| `has_marketplace_destination`      | bool   | derived: `marketplace_partner_id != ""`                      |                                                                             |
| `destination_count`                | int    | derived: count of populated destinations                     | Should be >= 1                                                              |
| `log_category_count`               | int    | `logs.len()`                                                 |                                                                             |
| `metric_category_count`            | int    | `metrics.len()`                                              |                                                                             |
| `log_categories_enabled_count`     | int    | derived: count of `logs[i].enabled==true`                    | **Key compliance signal**                                                   |
| `metric_categories_enabled_count`  | int    | derived                                                      |                                                                             |
| `all_log_categories_enabled`       | bool   | derived: every `logs[i].enabled==true`                       | Vacuously true when `logs[]` empty                                          |
| `all_metric_categories_enabled`    | bool   | derived                                                      | Vacuously true when `metrics[]` empty                                       |

### Absent-vs-empty semantics

Azure omits optional destination fields entirely (not null, not empty)
when they aren't configured. The collector coalesces absent fields to
empty strings for all destination scalars, then derives the
`has_*_destination` booleans from non-empty. Policies should assert on
the derived booleans, not the string fields, unless they need to match
a specific workspace/storage ID.

---

## RecordData Structure

The full `az monitor diagnostic-settings show` JSON is exposed as the
`resource` field, castable to `RecordData`. Use `record_checks` in ESP
policies for per-category assertions.

### Log / metric entry shape

Each entry in `logs[]` or `metrics[]`:

| Field                        | Type         | Notes                                                             |
| ---------------------------- | ------------ | ----------------------------------------------------------------- |
| `category`                   | string / null | e.g. `AuditEvent`, `AzurePolicyEvaluationDetails`, `AllMetrics`   |
| `categoryGroup`              | string / absent | Newer settings may use this instead of `category`               |
| `enabled`                    | bool         |                                                                   |
| `retentionPolicy.enabled`    | bool         |                                                                   |
| `retentionPolicy.days`       | int          | Typically 0 (Azure moved retention to the storage-level policy)   |

**Category vs categoryGroup:** newer diagnostic setting definitions can
use a `categoryGroup` field (`allLogs`, `audit`, etc.) instead of naming
individual categories. The CTN's RecordData exposes both shapes; policy
authors should match whichever applies to the resource type they're
targeting.

---

## State Fields (for ESP STATE blocks)

All scalars listed under Collected Data Fields above are valid state
fields. Plus:

- `record` (RecordData) — used with the `record` / `record_end` block
  inside a STATE for per-category / nested assertions.

Allowed operations:
- **Strings:** `=`, `!=` (all); `contains`, `starts_with` (most fields)
- **Booleans:** `=`, `!=`
- **Integers:** `=`, `!=`, `<`, `<=`, `>`, `>=`

---

## Collection Strategy

```rust
CollectionStrategy {
    collector_type: "az_diagnostic_setting",
    collection_mode: CollectionMode::Metadata,
    required_capabilities: ["az_cli", "reader"],
    performance_hints: {
        expected_collection_time_ms: 2000,
        memory_usage_mb: 2,
        network_intensive: true,
        cpu_intensive: false,
        requires_elevated_privileges: false,
    },
}
```

---

## Required Azure Permissions

**Unconditional:** `Reader` role at subscription, RG, target-resource,
or diagnostic-setting scope. That's all. `az monitor
diagnostic-settings show` is a pure ARM GET. The reader SPN's
subscription-level Reader grant was confirmed sufficient during
discovery.

---

## ESP Policy Examples

### Baseline — setting routes AuditEvent to Log Analytics

```esp
META
    esp_id `ksi-clg-lgc-diag-kv-audit-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-CLG-LGC`
    title `Key Vault diagnostic setting - audit events to Log Analytics`
META_END

DEF
    OBJECT kv_diag
        resource_id `/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prooflayer-demo-eastus/providers/Microsoft.KeyVault/vaults/kv-prooflayer-demo-ybuu`
        setting_name `diag-kv`
    OBJECT_END

    STATE st_to_workspace
        found boolean = true
        has_workspace_destination boolean = true
        all_log_categories_enabled boolean = true
        log_categories_enabled_count int >= 1
        destination_count int >= 1
    STATE_END

    CRI AND
        CTN az_diagnostic_setting
            TEST all all AND
            STATE_REF st_to_workspace
            OBJECT_REF kv_diag
        CTN_END
    CRI_END
DEF_END
```

### Per-category assertion via record_checks

```esp
STATE st_audit_enabled
    found boolean = true
    record
        field logs[?category==`AuditEvent`].enabled boolean = true
        field logs[?category==`AzurePolicyEvaluationDetails`].enabled boolean = true
        field metrics[?category==`AllMetrics`].enabled boolean = true
        field logAnalyticsDestinationType string = `AzureDiagnostics`
    record_end
STATE_END
```

### NotFound path

```esp
OBJECT missing_diag
    resource_id `/subscriptions/.../vaults/kv-prooflayer-demo-ybuu`
    setting_name `diag-does-not-exist`
OBJECT_END

STATE st_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                                     | Collector behavior                                                           |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Setting does not exist on a real target resource              | `found=false` - stderr contains `(ResourceNotFound)` "doesn't exist"         |
| Target resource does not exist                                | `found=false` - stderr contains `(ResourceNotFound)` "was not found"         |
| RG does not exist / caller has no access                      | `found=false` - stderr contains `(AuthorizationFailed)` scoped to diag settings |
| Malformed provider namespace in `resource_id`                 | `found=false` - stderr contains `(InvalidResourceNamespace)`                 |
| `az` binary missing / not authenticated                       | `CollectionError::CollectionFailed` - bubbles up                             |
| Unexpected non-zero exit with non-matching stderr             | `CollectionError::CollectionFailed`                                          |
| Malformed JSON in stdout on success                           | `CollectionError::CollectionFailed`                                          |

**NotFound triple-pattern detection:** unlike prior Azure CTNs which had
two NotFound stderr shapes, diagnostic settings have three. The
collector's `is_not_found` matches:
1. `(ResourceNotFound)` / `Code: ResourceNotFound` — covers both the
   "setting doesn't exist" and "target resource not found" wordings.
2. `(InvalidResourceNamespace)` / `Code: InvalidResourceNamespace` —
   malformed provider segment of the resource ID.
3. `(AuthorizationFailed)` scoped to `/diagnosticsettings` or
   `microsoft.insights` (case-insensitive) — fake or inaccessible RG.

All three map to `found=false` rather than a collection error, because
from a policy standpoint the effect is identical: the configuration
being asserted on isn't present.

---

## Non-Goals

These are **never** in scope for this CTN. Adding any of them would
break the read-only invariant or the Reader-only permission model:

1. **No setting mutation.** The CTN will never call
   `az monitor diagnostic-settings create`, `update`, or `delete`.
2. **No subscription-level activity log settings.** The
   `az monitor diagnostic-settings subscription` subgroup is a separate
   API with a different response shape (`{value:[]}` wrapper vs bare
   array). A future `az_activity_log_diagnostic_setting` CTN can cover
   it; this CTN stays scoped to resource-level settings.
3. **No cross-setting enumeration.** The CTN validates one named
   setting at a time. Policies that need "resource has at least one
   setting" semantics should enumerate all expected setting names as
   separate OBJECTs, or use a future batch-mode CTN variant.
4. **No category / category-group catalog lookups.** The companion
   `az monitor diagnostic-settings categories` subcommand enumerates the
   set of valid log/metric categories for a given resource type. That's
   a separate concern (schema validation) and out of scope here.

---

## Related CTN Types

- `az_key_vault`, `az_nsg`, `az_storage_account` — parent resources this
  CTN most commonly attaches to. Use these CTNs to validate the parent
  exists and is hardened, and `az_diagnostic_setting` to validate the
  setting attached to it.
- `az_resource_group` — parent RG context.
- Future `az_log_analytics_workspace` — would validate the sink side
  (workspace retention, solutions installed, etc.) to complement this
  CTN's verification of the source side.
