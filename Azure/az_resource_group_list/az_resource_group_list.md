# az_resource_group_list

## Overview

List-mode CTN that wraps `az group list --output json`. Returns one
record per resource group visible to the credential's role assignments
in the active subscription. Each projected record carries `id`, `name`,
`type`, `location`, `provisioning_state` (hoisted from
`properties.provisioningState`), optional `tags`, and optional
`managed_by` (when the RG is owned by an Azure service such as
Databricks). Resource groups are containers, not "resources" in ARM's
enumeration sense, so they don't appear in `az resource list` -- this
is the dedicated discovery feed for them.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** Native filter args are not available on `az group list` --
narrowing happens client-side via record_checks (e.g. enforce
`tags.Environment = prod` over the projected list).

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

| Field          | Type   | Required | Description                                                                              | Example                                |
| -------------- | ------ | -------- | ---------------------------------------------------------------------------------------- | -------------------------------------- |
| `scope`        | string | **Yes**  | Discovery scope. Only `subscription` is implemented today.                               | `subscription`                         |
| `subscription` | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent. | `00000000-0000-0000-0000-000000000000` |

---

## Commands Executed

```
az group list \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/00000000-.../resourceGroups/rg-prooflayer-platform",
    "name": "rg-prooflayer-platform",
    "type": "Microsoft.Resources/resourceGroups",
    "location": "eastus",
    "managedBy": null,
    "properties": { "provisioningState": "Succeeded" },
    "tags": {
      "Environment": "prod",
      "FedRAMPImpactLevel": "moderate",
      "Owner": "platform-team"
    }
  }
]
```

The collector hoists `properties.provisioningState` to a top-level
`provisioning_state` and drops `managedBy` when null (it's null for
typical deployments, populated only when Azure manages the RG on behalf
of a managed service).

---

## Collected Data Fields

### Scalar Fields

| Field         | Type    | Always Present | Source                                                       |
| ------------- | ------- | -------------- | ------------------------------------------------------------ |
| `found`       | boolean | Yes            | Derived -- `true` whenever `az group list` exits cleanly.    |
| `group_count` | integer | Yes            | Length of the returned array (`0` if no RGs are visible).    |

### List/Records Field

| Field    | Type       | Always Present | Description                                                                            |
| -------- | ---------- | -------------- | -------------------------------------------------------------------------------------- |
| `groups` | RecordData | Yes            | Projected record array. Empty `[]` when no RGs are visible (still `found=true`).       |

---

## Record/List Structure

Each element of the `groups` array exposes the projected snake_case
shape below.

| Path                            | Type   | Example Value                                                            |
| ------------------------------- | ------ | ------------------------------------------------------------------------ |
| `groups.*.id`                   | string | `"/subscriptions/.../resourceGroups/rg-prooflayer-platform"`             |
| `groups.*.name`                 | string | `"rg-prooflayer-platform"`                                               |
| `groups.*.type`                 | string | `"Microsoft.Resources/resourceGroups"`                                   |
| `groups.*.location`             | string | `"eastus"`                                                               |
| `groups.*.provisioning_state`   | string | `"Succeeded"`                                                            |
| `groups.*.managed_by`           | string | `"/subscriptions/.../databricks/.../"` (omitted when null)               |
| `groups.*.tags.<Key>`           | string | `"<Value>"` (flat string-to-string map; absent when no tags)             |

---

## State Fields

| State Field   | Type       | Allowed Operations              | Maps To Collected Field |
| ------------- | ---------- | ------------------------------- | ----------------------- |
| `found`       | boolean    | `=`, `!=`                       | `found`                 |
| `group_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `group_count`           |
| `groups`      | RecordData | (record checks)                 | `groups`                |

---

## Collection Strategy

| Property                     | Value                              |
| ---------------------------- | ---------------------------------- |
| Collector ID                 | `az-resource-group-list-collector` |
| Collector Type               | `az_resource_group_list`           |
| Collection Mode              | Metadata                           |
| Required Capabilities        | `az_cli`, `reader`                 |
| Expected Collection Time     | ~2000ms                            |
| Memory Usage                 | ~2MB                               |
| Network Intensive            | Yes                                |
| CPU Intensive                | No                                 |
| Requires Elevated Privileges | No                                 |
| Batch Collection             | No                                 |
| Per-call Timeout             | 30s                                |

---

## Required Azure Permissions

`Reader` role at subscription scope. RGs without an inherited or direct
role assignment are silently omitted from the response.

---

## ESP Examples

### Subscription must contain at least one RG

```esp
OBJECT rg_inventory
    scope `subscription`
OBJECT_END

STATE rgs_present
    found boolean = true
    group_count int >= 1
STATE_END

CTN az_resource_group_list
    TEST all all AND
    STATE_REF rgs_present
    OBJECT_REF rg_inventory
CTN_END
```

### Every RG must carry the FedRAMP impact-level tag

```esp
OBJECT rg_inventory
    scope `subscription`
OBJECT_END

STATE every_rg_tagged
    found boolean = true
    record
        field groups.*.tags.FedRAMPImpactLevel string = `moderate`
        field groups.*.tags.Environment string = `prod`
    record_end
STATE_END

CTN az_resource_group_list
    TEST all all AND
    STATE_REF every_rg_tagged
    OBJECT_REF rg_inventory
CTN_END
```

### Every RG must be in eastus and successfully provisioned

```esp
STATE rgs_eastus_succeeded
    found boolean = true
    record
        field groups.*.location string = `eastus`
        field groups.*.provisioning_state string = `Succeeded`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                                    | Error Type              | Outcome                       |
| -------------------------------------------- | ----------------------- | ----------------------------- |
| No RGs visible to the credential             | N/A (not an error)      | `found=true`, `group_count=0` |
| `scope` missing from OBJECT                  | `CollectionFailed`      | Error                         |
| `az` binary missing / not authenticated      | `CollectionFailed`      | Error                         |
| Non-zero exit from `az group list`           | `CollectionFailed`      | Error (full stderr in reason) |
| Stdout is not a JSON array                   | `CollectionFailed`      | Error                         |
| Stdout is not valid JSON                     | `CollectionFailed`      | Error                         |
| Incompatible CTN type                        | `CtnContractValidation` | Error                         |

There is no NotFound branch -- a 0-count response is a clean
`found=true`.

---

## Related CTN Types

| CTN Type                     | Relationship                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------------- |
| `az_resource_group`          | Typed cousin -- per-RG configuration scanning (tags, locks, role assignments at RG scope).  |
| `az_resource_list`           | Sibling list -- enumerates resources inside an RG; RGs themselves don't appear there.       |
| `az_role_assignment_list`    | Sibling list -- assignments at RG scope show up here, scoped via `groups.*.id`.             |
