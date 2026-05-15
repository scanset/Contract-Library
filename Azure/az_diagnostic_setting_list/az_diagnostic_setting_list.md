# az_diagnostic_setting_list

## Overview

List-mode CTN that wraps
`az monitor diagnostic-settings list --resource <resource_id> --output json`.
Diagnostic settings are an *extension* resource type -- every Azure
resource that supports them attaches diag settings via its own ARM id
(or, for storage accounts, via a sub-service path such as
`<storage_account_id>/blobServices/default`). The OBJECT takes the
target resource id as a single field; the discovery cascade is
responsible for picking the right path per parent type.

The collector hoists the destination references (`workspace_id` for Log
Analytics, `storage_account_id` for archive, `event_hub_authorization_rule_id`
for Event Hub) and computes per-record `log_count` / `metric_count`
totals plus the `enabled_log_categories` and `enabled_metric_categories`
arrays so policy authors can assert on enabled telemetry without
walking the nested `logs` / `metrics` shape.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** Storage accounts have a quirk -- diagnostic settings on the
control plane attach to the storage account id directly, but per-service
settings (blob, file, queue, table) attach to the sub-resource path
`<storage_account_id>/blobServices/default` etc. The cascade builder
must know to dispatch this CTN multiple times per storage account.
The collector itself takes the path verbatim and does not introspect.

The Azure response can also vary in shape: the collector accepts both
the bare-array form `[{...}, ...]` and the older envelope form
`{"value": [{...}, ...]}`, normalizing to the same projected output.

---

## Environment Variables

The agent's `SystemCommandExecutor` calls `env_clear()` before spawning
`az`, then re-injects only the variables below via `set_env_from`. Any
variable not set on the agent is silently skipped.

**You do not need to set all of these.** Pick ONE auth mode and configure
only its required vars -- the rest stay unset and are simply skipped.

### Auth mode: SPN with client secret

| Env var                              | Required | Purpose                     |
| ------------------------------------ | :------: | --------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | SPN application (client) ID |
| `AZURE_CLIENT_SECRET`                |    Yes   | SPN client secret           |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID           |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin    |

### Auth mode: SPN with client certificate

| Env var                              | Required | Purpose                                |
| ------------------------------------ | :------: | -------------------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | SPN application (client) ID            |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID                      |
| `AZURE_CLIENT_CERTIFICATE_PATH`      |    Yes   | Path to PEM/PFX cert on disk           |
| `AZURE_CLIENT_CERTIFICATE_PASSWORD`  |    opt   | Cert password if PFX is encrypted      |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin               |

### Auth mode: Workload Identity (federated OIDC)

| Env var                              | Required | Purpose                                  |
| ------------------------------------ | :------: | ---------------------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | Federated identity application ID        |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID                        |
| `AZURE_FEDERATED_TOKEN_FILE`         |    Yes   | Path to OIDC token file                  |
| `AZURE_AUTHORITY_HOST`               |    opt   | Sovereign cloud override                 |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin                 |

### Auth mode: Managed Identity

No explicit env vars on the agent. Azure injects `IDENTITY_ENDPOINT` and
`IDENTITY_HEADER` (or legacy `MSI_ENDPOINT` / `MSI_SECRET`) on a VM or
App Service with an assigned identity; the passthrough list forwards
them to `az`.

### Auth mode: Cached `az login`

| Env var                              | Required | Purpose                                            |
| ------------------------------------ | :------: | -------------------------------------------------- |
| `HOME`                               |    Yes   | `az` looks for `~/.azure/` token cache under HOME  |
| `AZURE_CONFIG_DIR`                   |    opt   | Overrides `~/.azure/` location                     |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Overrides the cached default subscription          |

### Locale (all modes)

| Env var              | Required | Purpose                                     |
| -------------------- | :------: | ------------------------------------------- |
| `LANG` / `LC_ALL`    |    opt   | Suppresses Python locale warnings from `az` |

---

## Object Fields

| Field          | Type   | Required | Description                                                                                                                       | Example                                                                                              |
| -------------- | ------ | -------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `resource_id`  | string | **Yes**  | Full ARM id of the parent resource. Storage accounts use a sub-service path: `<storage_id>/blobServices/default`, etc.            | `/subscriptions/.../providers/Microsoft.KeyVault/vaults/kv-prooflayer`                               |
| `subscription` | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent.                                          | `00000000-0000-0000-0000-000000000000`                                                               |

Storage account sub-paths (each must be queried as a separate OBJECT):
- `<storage_id>` -- account-level metrics
- `<storage_id>/blobServices/default` -- blob telemetry
- `<storage_id>/fileServices/default` -- file telemetry
- `<storage_id>/queueServices/default` -- queue telemetry
- `<storage_id>/tableServices/default` -- table telemetry

---

## Commands Executed

```
az monitor diagnostic-settings list \
    --resource /subscriptions/.../providers/Microsoft.KeyVault/vaults/kv-prooflayer \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated, bare-array form):**

```json
[
  {
    "id": "/subscriptions/.../vaults/kv-prooflayer/providers/microsoft.insights/diagnosticSettings/send-to-law",
    "name": "send-to-law",
    "type": "Microsoft.Insights/diagnosticSettings",
    "resourceGroup": "rg-prooflayer-platform",
    "workspaceId": "/subscriptions/.../workspaces/law-prooflayer-central",
    "storageAccountId": null,
    "eventHubAuthorizationRuleId": null,
    "logs": [
      { "category": "AuditEvent",  "enabled": true,  "retentionPolicy": { "enabled": false, "days": 0 } },
      { "category": "AzurePolicyEvaluationDetails", "enabled": false, "retentionPolicy": { "enabled": false, "days": 0 } }
    ],
    "metrics": [
      { "category": "AllMetrics", "enabled": true, "retentionPolicy": { "enabled": false, "days": 0 } }
    ]
  }
]
```

The collector also accepts `{"value": [...]}` envelope responses
(returned by older API versions / management-group scopes) and
normalizes them to the same projected shape.

---

## Collected Data Fields

### Scalar Fields

| Field           | Type    | Always Present | Source                                                                       |
| --------------- | ------- | -------------- | ---------------------------------------------------------------------------- |
| `found`         | boolean | Yes            | Derived -- `true` whenever `az monitor diagnostic-settings list` exits cleanly. |
| `setting_count` | integer | Yes            | Length of the returned array (often `0` -- most resources don't have diag).  |

### List/Records Field

| Field      | Type       | Always Present | Description                                                                          |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------------ |
| `settings` | RecordData | Yes            | Projected record array. Empty `[]` when none are configured (still `found=true`).    |

---

## Record/List Structure

| Path                                         | Type    | Example Value                                                                          |
| -------------------------------------------- | ------- | -------------------------------------------------------------------------------------- |
| `settings.*.id`                              | string  | `"/subscriptions/.../diagnosticSettings/send-to-law"`                                  |
| `settings.*.name`                            | string  | `"send-to-law"`                                                                        |
| `settings.*.type`                            | string  | `"Microsoft.Insights/diagnosticSettings"`                                              |
| `settings.*.resource_group`                  | string  | `"rg-prooflayer-platform"`                                                             |
| `settings.*.workspace_id`                    | string  | `"/subscriptions/.../workspaces/law-prooflayer-central"` (omitted when absent)         |
| `settings.*.storage_account_id`              | string  | `"/subscriptions/.../storageAccounts/saprooflayerlogs"` (omitted when absent)          |
| `settings.*.event_hub_authorization_rule_id` | string  | `"/subscriptions/.../authorizationRules/RootManageSharedAccessKey"` (omitted when absent) |
| `settings.*.log_count`                       | integer | `2` (total log entries; both enabled and disabled)                                     |
| `settings.*.metric_count`                    | integer | `1` (total metric entries; both enabled and disabled)                                  |
| `settings.*.enabled_log_categories[]`        | array   | `["AuditEvent"]` (categories with `enabled=true`; absent when none)                    |
| `settings.*.enabled_metric_categories[]`     | array   | `["AllMetrics"]` (categories with `enabled=true`; absent when none)                    |

---

## State Fields

| State Field     | Type       | Allowed Operations              | Maps To Collected Field |
| --------------- | ---------- | ------------------------------- | ----------------------- |
| `found`         | boolean    | `=`, `!=`                       | `found`                 |
| `setting_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `setting_count`         |
| `settings`      | RecordData | (record checks)                 | `settings`              |

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `az-diagnostic-setting-list-collector` |
| Collector Type               | `az_diagnostic_setting_list`         |
| Collection Mode              | Metadata                             |
| Required Capabilities        | `az_cli`, `reader`                   |
| Expected Collection Time     | ~2000ms                              |
| Memory Usage                 | ~1MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |
| Per-call Timeout             | 30s                                  |

---

## Required Azure Permissions

`Reader` role at the target resource scope (or any inherited scope).
Reading diagnostic settings requires
`Microsoft.Insights/diagnosticSettings/read`, carried by `Reader`.

---

## ESP Examples

### Key Vault must ship AuditEvent logs to a Log Analytics workspace

```esp
OBJECT kv_diag
    resource_id `/subscriptions/00000000-.../resourceGroups/rg-platform/providers/Microsoft.KeyVault/vaults/kv-prooflayer`
OBJECT_END

STATE kv_audit_to_law
    found boolean = true
    setting_count int >= 1
    record
        field settings.0.workspace_id string contains `law-prooflayer-central`
        field settings.0.enabled_log_categories.0 string = `AuditEvent`
    record_end
STATE_END

CTN az_diagnostic_setting_list
    TEST all all AND
    STATE_REF kv_audit_to_law
    OBJECT_REF kv_diag
CTN_END
```

### Storage account blob telemetry must include AllMetrics

```esp
OBJECT sa_blob_diag
    resource_id `/subscriptions/00000000-.../storageAccounts/saprooflayer/blobServices/default`
OBJECT_END

STATE blob_metrics_enabled
    found boolean = true
    setting_count int >= 1
    record
        field settings.0.enabled_metric_categories.0 string = `AllMetrics`
    record_end
STATE_END

CTN az_diagnostic_setting_list
    TEST all all AND
    STATE_REF blob_metrics_enabled
    OBJECT_REF sa_blob_diag
CTN_END
```

### Resource must have at least one diagnostic setting configured

```esp
STATE diag_present
    found boolean = true
    setting_count int >= 1
STATE_END
```

---

## Error Conditions

| Condition                                                    | Error Type              | Outcome                          |
| ------------------------------------------------------------ | ----------------------- | -------------------------------- |
| Resource has zero diagnostic settings                        | N/A (not an error)      | `found=true`, `setting_count=0`  |
| `resource_id` missing from OBJECT                            | `CollectionFailed`      | Error                            |
| Parent resource does not exist / no access                   | `CollectionFailed`      | Error (full stderr in reason)    |
| `az` binary missing / not authenticated                      | `CollectionFailed`      | Error                            |
| Non-zero exit from `az monitor diagnostic-settings list`     | `CollectionFailed`      | Error                            |
| Stdout is not valid JSON                                     | `CollectionFailed`      | Error                            |
| Stdout is JSON but neither array nor `{value: [...]}` shape  | N/A (not an error)      | `found=true`, `setting_count=0`  |
| Incompatible CTN type                                        | `CtnContractValidation` | Error                            |

---

## Related CTN Types

| CTN Type                  | Relationship                                                                                       |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| `az_diagnostic_setting`   | Typed cousin -- per-setting lookup by name on a known parent resource id.                          |
| `az_resource_list`        | Discovery feed -- each resource id from `az_resource_list` triggers one cascade dispatch (with the storage-account multi-path expansion handled by the cascade builder). |
| `az_log_analytics_workspace` | Resolves the `workspace_id` referenced by each setting record.                                  |
| `az_storage_account`      | Resolves the `storage_account_id` referenced by archive-target settings.                            |
