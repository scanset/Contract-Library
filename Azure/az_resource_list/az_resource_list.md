# az_resource_list

## Overview

List-mode CTN that wraps `az resource list --output json`. Returns a flat
inventory of every Azure resource visible to the credential's role
assignments at the chosen scope. Each record carries the canonical ARM
identifiers (`id`, `name`, `type`, `location`, `resourceGroup`,
`provisioningState`, `createdTime`, `changedTime`) plus optional `kind`,
`sku`, and `tags` when the resource type carries them. The ARM
`properties` blob is always null in this call -- use the typed
`az_<resource>_list` cousins (e.g. `az_subnet_list`, `az_nsg_rule_list`)
when you need configuration data.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`. Optional `--resource-group` / `--resource-type`
narrowing flags are passed when the corresponding OBJECT fields are set.

**Note:** This is the primary discovery feed for Cat 1 inventory and the
asset-cascade pipeline. Whole-subscription enumeration of a tenant with
hundreds of resources finishes in seconds because the call returns
projection-only metadata; configuration scanning lives elsewhere.

---

## Environment Variables

The agent's `SystemCommandExecutor` calls `env_clear()` before spawning
`az`, then re-injects only the variables below via `set_env_from`. Any
variable not set on the agent is silently skipped.

**You do not need to set all of these.** Pick ONE auth mode and configure
only its required vars -- the rest stay unset and are simply skipped.
Any supported var CAN be used when needed (e.g. you may override
`AZURE_SUBSCRIPTION_ID` regardless of which auth mode is active, or set
`AZURE_CONFIG_DIR` to relocate the `az login` cache).

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
them to `az`. Optionally set `AZURE_SUBSCRIPTION_ID` to pin a default
subscription.

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

| Field            | Type   | Required | Description                                                                                       | Example                                |
| ---------------- | ------ | -------- | ------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `scope`          | string | **Yes**  | Discovery scope. `subscription` enumerates everything visible to the credential.                  | `subscription`                         |
| `subscription`   | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent.         | `00000000-0000-0000-0000-000000000000` |
| `resource_group` | string | opt      | Optional RG filter -- collector adds `--resource-group <rg>` to the call.                         | `rg-prooflayer-platform`               |
| `resource_type`  | string | opt      | Optional ARM type filter -- collector adds `--resource-type <type>`.                              | `Microsoft.Storage/storageAccounts`    |

Currently only `scope = subscription` is wired through end to end; the
narrower scopes are reserved for the next iteration. The optional
`resource_group` and `resource_type` fields work today regardless of
scope value because they're translated to direct `az` flags.

---

## Commands Executed

```
az resource list \
    --resource-group rg-prooflayer-platform \
    --resource-type Microsoft.Storage/storageAccounts \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

The `--resource-group` / `--resource-type` flags are added only when the
matching OBJECT fields are set. Pure subscription-wide discovery uses
just `az resource list --output json`.

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../resourceGroups/rg-platform/providers/Microsoft.KeyVault/vaults/kv-prooflayer",
    "name": "kv-prooflayer",
    "type": "Microsoft.KeyVault/vaults",
    "location": "eastus",
    "resourceGroup": "rg-platform",
    "provisioningState": "Succeeded",
    "createdTime": "2026-04-14T15:55:21.123456+00:00",
    "changedTime": "2026-04-19T11:02:03.987654+00:00",
    "kind": null,
    "sku": null,
    "tags": { "Environment": "demo" },
    "properties": null
  }
]
```

The top-level response is always a JSON array. The collector projects
each element into the snake_case shape below before stuffing it into
the `resources` field. `properties` is always null in this call and is
deliberately dropped.

---

## Collected Data Fields

### Scalar Fields

| Field            | Type    | Always Present | Source                                                       |
| ---------------- | ------- | -------------- | ------------------------------------------------------------ |
| `found`          | boolean | Yes            | Derived -- `true` whenever `az resource list` exits cleanly. |
| `resource_count` | integer | Yes            | Length of the returned array (`0` when nothing visible).     |

### List/Records Field

| Field       | Type       | Always Present | Description                                                                              |
| ----------- | ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| `resources` | RecordData | Yes            | Projected record array. Empty `[]` when no resources match the filter (still `found=true`). |

---

## Record/List Structure

Each element in the `resources` array exposes the projected snake_case
shape below. Use array index (`resources.0.id`) or wildcard
(`resources.*.type`) paths in record_checks.

| Path                         | Type    | Example Value                                                                       |
| ---------------------------- | ------- | ----------------------------------------------------------------------------------- |
| `resources.*.id`             | string  | `"/subscriptions/.../providers/Microsoft.KeyVault/vaults/kv-prooflayer"`            |
| `resources.*.name`           | string  | `"kv-prooflayer"`                                                                   |
| `resources.*.type`           | string  | `"Microsoft.KeyVault/vaults"`                                                       |
| `resources.*.location`       | string  | `"eastus"`                                                                          |
| `resources.*.resource_group` | string  | `"rg-platform"`                                                                     |
| `resources.*.provisioning_state` | string | `"Succeeded"`                                                                    |
| `resources.*.created_time`   | string  | `"2026-04-14T15:55:21.123456+00:00"`                                                |
| `resources.*.changed_time`   | string  | `"2026-04-19T11:02:03.987654+00:00"`                                                |
| `resources.*.kind`           | string  | `"StorageV2"` (when applicable)                                                     |
| `resources.*.sku_name`       | string  | `"Standard_LRS"` (when applicable)                                                  |
| `resources.*.sku_tier`       | string  | `"Standard"` (when applicable)                                                      |
| `resources.*.tags.<Key>`     | string  | `"<Value>"` (flat string-to-string map; absent when no tags)                        |

---

## State Fields

| State Field      | Type       | Allowed Operations                            | Maps To Collected Field |
| ---------------- | ---------- | --------------------------------------------- | ----------------------- |
| `found`          | boolean    | `=`, `!=`                                     | `found`                 |
| `resource_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`               | `resource_count`        |
| `resources`      | RecordData | (record checks)                               | `resources`             |

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `az-resource-list-collector`   |
| Collector Type               | `az_resource_list`             |
| Collection Mode              | Metadata                       |
| Required Capabilities        | `az_cli`, `reader`             |
| Expected Collection Time     | ~3000ms                        |
| Memory Usage                 | ~4MB                           |
| Network Intensive            | Yes                            |
| CPU Intensive                | No                             |
| Requires Elevated Privileges | No                             |
| Batch Collection             | No                             |
| Per-call Timeout             | 30s                            |

---

## Required Azure Permissions

`Reader` role at subscription scope (broadest) or RG scope (when paired
with `resource_group` filter). Resources outside the role assignment's
scope are silently omitted from the response -- `az resource list` does
not error on partial visibility.

---

## ESP Examples

### Tenant inventory baseline -- subscription must contain resources

```esp
OBJECT sub_inventory
    scope `subscription`
    subscription `00000000-0000-0000-0000-000000000000`
OBJECT_END

STATE inventory_admit
    found boolean = true
    resource_count int >= 1
STATE_END

CTN az_resource_list
    TEST all all AND
    STATE_REF inventory_admit
    OBJECT_REF sub_inventory
CTN_END
```

### Storage-account-only enumeration with tag enforcement

```esp
OBJECT storage_inventory
    scope `subscription`
    resource_type `Microsoft.Storage/storageAccounts`
OBJECT_END

STATE every_storage_tagged
    found boolean = true
    record
        field resources.*.tags.FedRAMPImpactLevel string = `moderate`
        field resources.*.tags.Environment string = `prod`
    record_end
STATE_END

CTN az_resource_list
    TEST all all AND
    STATE_REF every_storage_tagged
    OBJECT_REF storage_inventory
CTN_END
```

### RG-scoped scan -- everything in the RG must be `Succeeded`

```esp
OBJECT rg_inventory
    scope `subscription`
    resource_group `rg-prooflayer-platform`
OBJECT_END

STATE all_succeeded
    found boolean = true
    resource_count int >= 1
    record
        field resources.*.provisioning_state string = `Succeeded`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                                    | Error Type              | Outcome                          |
| -------------------------------------------- | ----------------------- | -------------------------------- |
| Empty subscription / no resources visible    | N/A (not an error)      | `found=true`, `resource_count=0` |
| `scope` missing from OBJECT                  | `CollectionFailed`      | Error                            |
| `az` binary missing / not authenticated      | `CollectionFailed`      | Error                            |
| Non-zero exit from `az resource list`        | `CollectionFailed`      | Error (full stderr in reason)    |
| Stdout is not a JSON array                   | `CollectionFailed`      | Error                            |
| Stdout is not valid JSON                     | `CollectionFailed`      | Error                            |
| Incompatible CTN type                        | `CtnContractValidation` | Error                            |

Unlike single-resource CTNs (e.g. `az_resource_group`), there is no
NotFound branch. A successful list of 0 resources is a clean
`found=true` / `resource_count=0` response, not an error.

---

## Related CTN Types

| CTN Type                     | Relationship                                                                            |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| `az_resource_group_list`     | Sibling list -- RGs don't appear in `az resource list` so they have their own contract. |
| `az_resource_group`          | Typed cousin -- per-RG configuration scanning.                                          |
| `az_virtual_machine`         | Typed cousin -- per-VM configuration scanning.                                          |
| `az_subnet_list`             | Cascade child -- dispatched per VNet returned in this list.                             |
| `az_diagnostic_setting_list` | Cascade child -- dispatched per resource id returned in this list.                     |
