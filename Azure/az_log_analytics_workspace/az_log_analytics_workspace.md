# az_log_analytics_workspace

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Log Analytics
Workspace's configuration surface via a single Azure CLI call --
`az monitor log-analytics workspace show --workspace-name <name>
--resource-group <rg> [--subscription <id>] --output json`. Returns
compliance scalars for SKU tier, data retention period, public network
access (ingestion + query), local authentication, resource-context access
control, daily ingestion quota cap, and derived compliance threshold
fields, plus the full workspace document as RecordData for tag-based
record_checks.

The CTN never modifies any resource, never calls data-plane APIs (no
query execution, no data ingestion), and never requires any Azure
permission above `Reader`. See "Non-Goals" at the bottom for the full
list of things this CTN will never do.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode)
**Collection Method:** Single Azure CLI command per object via the shared
hardened `SystemCommandExecutor`.
**Scope:** Control-plane only, read-only.

---

## Environment Variables

All Azure CTNs share a single executor factory -
`agent::contract_kit::commands::az::create_az_executor()` - wired in via
`registry.rs`. The hardened `SystemCommandExecutor` calls `env_clear()` before
spawning, so anything not explicitly re-injected is stripped. The factory
re-injects the following via `set_env_from` (each line passes through the
named var from the agent process if set, skipped silently otherwise):

| Purpose                       | Env Var(s)                                                          |
| ----------------------------- | ------------------------------------------------------------------- |
| SPN + client secret           | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`         |
| Subscription pin              | `AZURE_SUBSCRIPTION_ID`                                             |
| SPN + client certificate      | `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_CLIENT_CERTIFICATE_PASSWORD`|
| Workload identity (federated) | `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`                |
| Managed identity              | `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `MSI_ENDPOINT`, `MSI_SECRET`|
| Cached `az login`             | `HOME`, `AZURE_CONFIG_DIR`                                          |
| Python locale (az is Python)  | `LANG`, `LC_ALL`                                                    |

The factory also pins `PATH` to `/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin`
and whitelists the `az` binary (plus common absolute paths) on the executor.

`az_log_analytics_workspace` inherits this env surface unchanged - no per-CTN
overrides, no per-collector env. If `az_resource_group` can authenticate
successfully, so can `az_log_analytics_workspace`.

### Supported auth modes

| Mode                         | Required agent env                                                        |
| ---------------------------- | ------------------------------------------------------------------------- |
| SPN with client secret       | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`               |
| SPN with client certificate  | `AZURE_CLIENT_ID`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_TENANT_ID`     |
| Workload identity (federated)| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`        |
| Managed Identity             | (none - Azure VM injects `IDENTITY_ENDPOINT` automatically)               |
| Cached `az login`            | `HOME` (or `AZURE_CONFIG_DIR`) - tokens read from `~/.azure/`             |

Subscription selection precedence: `--subscription` arg on the call >
`AZURE_SUBSCRIPTION_ID` env > cached-config default.

---

## Object Fields

| Field            | Type   | Required | Description                               | Example                                 |
| ---------------- | ------ | -------- | ----------------------------------------- | --------------------------------------- |
| `name`           | string | **Yes**  | Log Analytics Workspace name              | `law-prooflayer-demo`                   |
| `resource_group` | string | **Yes**  | Resource group that owns the workspace    | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                  | `00000000-0000-0000-0000-000000000000`  |

Both `name` and `resource_group` are required -- workspace names are only
unique within an RG, and `az monitor log-analytics workspace show` demands
`-g`. Note that this command uses `--workspace-name`, not `--name` (unlike
most other Azure resource types). Azure performs no client-side validation
of the name: malformed inputs return `ResourceNotFound` at runtime.

---

## Commands Executed

```
az monitor log-analytics workspace show \
    --workspace-name law-prooflayer-demo \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per workspace object. Returns SKU, retention, access control,
public network access, capping, features, and tags inline.

**Sample response:**

```json
{
  "createdDate": "2026-04-14T17:24:56.3509416Z",
  "customerId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "features": {
    "disableLocalAuth": false,
    "enableLogAccessUsingOnlyResourcePermissions": true,
    "legacy": 0,
    "searchVersion": 1
  },
  "location": "eastus",
  "name": "law-prooflayer-demo",
  "provisioningState": "Succeeded",
  "publicNetworkAccessForIngestion": "Enabled",
  "publicNetworkAccessForQuery": "Enabled",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "retentionInDays": 30,
  "sku": {
    "lastSkuUpdate": "2026-04-14T17:24:56.3509416Z",
    "name": "PerGB2018"
  },
  "workspaceCapping": {
    "dailyQuotaGb": -1.0,
    "dataIngestionStatus": "RespectQuota",
    "quotaNextResetTime": "2026-04-14T18:00:00Z"
  }
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                              | Type    | Always Present | Source                                                 |
| ---------------------------------- | ------- | -------------- | ------------------------------------------------------ |
| `found`                           | boolean | Yes            | Derived - true on successful show, false on NotFound   |
| `name`                            | string  | When found     | `name`                                                 |
| `id`                              | string  | When found     | `id`                                                   |
| `location`                        | string  | When found     | `location`                                             |
| `resource_group`                  | string  | When found     | `resourceGroup`                                        |
| `provisioning_state`              | string  | When found     | `provisioningState`                                    |
| `customer_id`                     | string  | When found     | `customerId`                                           |
| `created_date`                    | string  | When found     | `createdDate`                                          |
| `sku_name`                        | string  | When found     | `sku.name`                                             |
| `public_network_access_ingestion` | string  | When found     | `publicNetworkAccessForIngestion`                      |
| `public_network_access_query`     | string  | When found     | `publicNetworkAccessForQuery`                          |
| `data_ingestion_status`           | string  | When present   | `workspaceCapping.dataIngestionStatus`                 |

### Boolean Fields

| Field                              | Type    | Always Present | Source                                                 |
| ---------------------------------- | ------- | -------------- | ------------------------------------------------------ |
| `local_auth_disabled`             | boolean | When found     | `features.disableLocalAuth` (defaults false if absent) |
| `resource_permissions_enabled`    | boolean | When found     | `features.enableLogAccessUsingOnlyResourcePermissions`  |
| `has_daily_cap`                   | boolean | When present   | Derived: `dailyQuotaGb > 0`                           |
| `retention_meets_90_days`         | boolean | When found     | Derived: `retentionInDays >= 90`                       |
| `retention_meets_365_days`        | boolean | When found     | Derived: `retentionInDays >= 365`                      |

### Integer Fields

| Field                              | Type    | Always Present | Source                                                 |
| ---------------------------------- | ------- | -------------- | ------------------------------------------------------ |
| `retention_in_days`               | integer | When found     | `retentionInDays`                                      |
| `daily_quota_gb`                  | integer | When present   | `workspaceCapping.dailyQuotaGb` (truncated to int; -1 = unlimited) |

### RecordData Field

| Field      | Type       | Always Present | Description                                                       |
| ---------- | ---------- | -------------- | ----------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az monitor log-analytics workspace show` object. Empty `{}` when not found |

### Derived-field semantics

- **`local_auth_disabled`** -- when `true`, the workspace rejects API keys
  and shared keys, requiring AAD-only authentication. This is the stronger
  security posture. Defaults to `false` if `features.disableLocalAuth` is
  absent from the response.
- **`resource_permissions_enabled`** -- when `true`, access control uses
  resource-context mode (`enableLogAccessUsingOnlyResourcePermissions`).
  Users with Reader on a resource can see that resource's logs without
  workspace-level access.
- **`has_daily_cap`** -- `true` when `dailyQuotaGb > 0` (an explicit cap
  is set). When `dailyQuotaGb` is `-1.0` (unlimited), this is `false`.
- **`retention_meets_90_days`** / **`retention_meets_365_days`** -- derived
  compliance thresholds. 90 days is the common FedRAMP Moderate minimum;
  365 days covers FedRAMP High and stricter NIST controls.
- **`daily_quota_gb`** -- stored as integer (float truncated). `-1` means
  unlimited (no cap set).

---

## RecordData Structure

```
name                                              -> "law-prooflayer-demo"
customerId                                        -> "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
location                                          -> "eastus"
resourceGroup                                     -> "rg-prooflayer-demo-eastus"
provisioningState                                 -> "Succeeded"
createdDate                                       -> "2026-04-14T17:24:56.3509416Z"
retentionInDays                                   -> 30
sku.name                                          -> "PerGB2018"
sku.lastSkuUpdate                                 -> "2026-04-14T17:24:56.3509416Z"
features.disableLocalAuth                         -> false
features.enableLogAccessUsingOnlyResourcePermissions -> true
features.legacy                                   -> 0
features.searchVersion                            -> 1
publicNetworkAccessForIngestion                   -> "Enabled" | "Disabled"
publicNetworkAccessForQuery                       -> "Enabled" | "Disabled"
workspaceCapping.dailyQuotaGb                     -> -1.0 | 5.0
workspaceCapping.dataIngestionStatus              -> "RespectQuota" | "OverQuota"
workspaceCapping.quotaNextResetTime               -> "2026-04-14T18:00:00Z"
tags.<Key>                                        -> "<Value>"
```

Use `field <path> <type> = \`<value>\`` in `record_checks` to enforce
nested properties. Example:
`field features.disableLocalAuth boolean = true`.

---

## State Fields

| State Field                        | Type       | Allowed Operations                           | Maps To Collected Field                    |
| ---------------------------------- | ---------- | -------------------------------------------- | ------------------------------------------ |
| `found`                           | boolean    | `=`, `!=`                                    | `found`                                    |
| `name`                            | string     | `=`, `!=`, `contains`, `starts`              | `name`                                     |
| `id`                              | string     | `=`, `!=`, `contains`, `starts`              | `id`                                       |
| `location`                        | string     | `=`, `!=`                                    | `location`                                 |
| `resource_group`                  | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                           |
| `provisioning_state`              | string     | `=`, `!=`                                    | `provisioning_state`                       |
| `customer_id`                     | string     | `=`, `!=`, `contains`, `starts`              | `customer_id`                              |
| `created_date`                    | string     | `=`, `!=`, `contains`, `starts`              | `created_date`                             |
| `sku_name`                        | string     | `=`, `!=`                                    | `sku_name`                                 |
| `public_network_access_ingestion` | string     | `=`, `!=`                                    | `public_network_access_ingestion`          |
| `public_network_access_query`     | string     | `=`, `!=`                                    | `public_network_access_query`              |
| `data_ingestion_status`           | string     | `=`, `!=`                                    | `data_ingestion_status`                    |
| `local_auth_disabled`             | boolean    | `=`, `!=`                                    | `local_auth_disabled`                      |
| `resource_permissions_enabled`    | boolean    | `=`, `!=`                                    | `resource_permissions_enabled`             |
| `has_daily_cap`                   | boolean    | `=`, `!=`                                    | `has_daily_cap`                            |
| `retention_meets_90_days`         | boolean    | `=`, `!=`                                    | `retention_meets_90_days`                  |
| `retention_meets_365_days`        | boolean    | `=`, `!=`                                    | `retention_meets_365_days`                 |
| `retention_in_days`               | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `retention_in_days`                        |
| `daily_quota_gb`                  | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `daily_quota_gb`                           |
| `record`                          | RecordData | (record checks)                              | `resource`                                 |

---

## Collection Strategy

| Property                 | Value                                       |
| ------------------------ | ------------------------------------------- |
| Collector ID             | `az-log-analytics-workspace-collector`      |
| Collector Type           | `az_log_analytics_workspace`                |
| Collection Mode          | Metadata                                    |
| Required Capabilities    | `az_cli`, `reader`                          |
| Expected Collection Time | ~2000ms                                     |
| Memory Usage             | ~2MB                                        |
| Batch Collection         | No                                          |
| Per-call Timeout         | 30s                                         |
| API Calls                | 1                                           |

---

## Required Azure Permissions

`Reader` role at subscription, RG, or workspace scope. That's all.
`az monitor log-analytics workspace show` is a pure ARM GET; no data
plane is accessed (no queries executed, no data read). The workspace's
`customerId` is metadata, not a secret -- it identifies the workspace
for ingestion but grants no access without proper auth.

---

## ESP Policy Examples

### Baseline -- workspace exists with expected SKU and retention

```esp
META
    esp_id `example-law-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-AFR-UCM`
    title `LAW baseline - SKU, retention, provisioning state`
META_END

DEF
    OBJECT law_prod
        name `law-prooflayer-demo`
        resource_group `rg-prooflayer-demo-eastus`
    OBJECT_END

    STATE law_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        sku_name string = `PerGB2018`
        retention_in_days int >= 30
    STATE_END

    CRI AND
        CTN az_log_analytics_workspace
            TEST all all AND
            STATE_REF law_baseline
            OBJECT_REF law_prod
        CTN_END
    CRI_END
DEF_END
```

### FedRAMP Moderate retention -- 90 days minimum

```esp
STATE law_fedramp_moderate
    found boolean = true
    retention_meets_90_days boolean = true
    retention_in_days int >= 90
STATE_END
```

### Security hardening -- disable local auth, restrict public access

```esp
STATE law_hardened
    found boolean = true
    local_auth_disabled boolean = true
    public_network_access_ingestion string = `Disabled`
    public_network_access_query string = `Disabled`
STATE_END
```

### Daily ingestion cap -- ensure cost controls are in place

```esp
STATE law_cost_controlled
    found boolean = true
    has_daily_cap boolean = true
    daily_quota_gb int >= 1
    data_ingestion_status string = `RespectQuota`
STATE_END
```

### Tag compliance via record_checks

```esp
STATE law_tagged
    found boolean = true
    record
        field tags.Environment string = `production`
        field tags.FedRAMPImpactLevel string = `moderate`
    record_end
STATE_END
```

### NotFound path -- workspace must not exist

```esp
STATE law_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                             | Collector behavior                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------------ |
| Workspace does not exist (real RG + missing name)     | `found=false`, `resource={}` - stderr matches `(ResourceNotFound)`       |
| RG does not exist / caller has no access              | `found=false` - stderr matches `(AuthorizationFailed)` scoped to `/workspaces/` |
| `name` missing from OBJECT                            | `InvalidObjectConfiguration` - Error                                    |
| `resource_group` missing from OBJECT                  | `InvalidObjectConfiguration` - Error                                    |
| `az` binary missing / not authenticated               | `CollectionError::CollectionFailed` - bubbles up                         |
| Unexpected non-zero exit with non-NotFound stderr     | `CollectionError::CollectionFailed`                                      |
| Malformed JSON in stdout on success                   | `CollectionError::CollectionFailed`                                      |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr
matches either:

1. `(ResourceNotFound)` / `Code: ResourceNotFound` - covers real RG with
   missing or malformed workspace name (exit code 3).
2. `(AuthorizationFailed)` **and** the scope string contains
   `/workspaces/` (case-insensitive) - covers fake or inaccessible
   RG (exit code 1). An `AuthorizationFailed` that does NOT mention
   `/workspaces/` is treated as a real error, not a NotFound.

---

## Non-Goals

These are **never** in scope for this CTN:

1. **No mutation.** The CTN will never call `az monitor log-analytics workspace create`,
   `update`, or `delete`. All inspection is via `show` only.
2. **No query execution.** The CTN does not run any KQL queries against the
   workspace. Log query results are out of scope -- use a dedicated query CTN
   if policy needs to assert on ingested data.
3. **No data-plane access.** No log ingestion, no saved searches, no alerts,
   no linked storage accounts. The CTN reads only the ARM resource metadata.
4. **No solution/intelligence-pack enumeration.** The response from `workspace show`
   does not include installed solutions. Use `az monitor log-analytics solution list`
   in a separate CTN if needed.
5. **No linked-service or private-link inspection.** Private link connections
   and linked services are separate ARM resources requiring additional API calls.

---

## Related CTN Types

| CTN Type                          | Relationship                                                         |
| --------------------------------- | -------------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the workspace                                     |
| `az_diagnostic_setting`           | Diagnostic settings route logs to LAW via workspace ID               |
| `az_storage_account`              | Storage accounts linked for long-term log archival                   |
| `az_nsg`                          | Flow logs may target this workspace for NSG flow analytics           |
| `az_key_vault`                    | Key Vault diagnostic logs may route to this workspace                |
| `az_virtual_network`              | VNet flow logs may target this workspace                             |
