# az_resource_group

## Overview

Validates an Azure Resource Group via the Azure CLI using
`az group show --name <name> [--subscription <id>] --output json`. Returns
core ARM scalars (location, provisioningState, managedBy) plus the full
response as RecordData for tag-based record_checks.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode)
**Collection Method:** Single Azure CLI command per object via the shared
hardened `SystemCommandExecutor` (see `az_resource_group_command.rs`)

**Note:** Resource group tags are a flat string-to-string map in Azure. The
Azure reserved prefixes `azure`, `microsoft`, and `windows` are rejected by
the service; use alternative names like `SubscriptionId` instead of
`AzureSubscriptionId`.

---

## Environment Variables

The agent's `SystemCommandExecutor` calls `env_clear()` before spawning `az`,
then re-injects only the variables below via `set_env_from`. Any variable not
set on the agent is silently skipped.

**You do not need to set all of these.** Pick ONE auth mode and configure
only its required vars — the rest stay unset and are simply skipped. Any
supported var CAN be used when needed (e.g. you may override
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
| `AZURE_FEDERATED_TOKEN_FILE`         |    Yes   | Path to OIDC token file (e.g. `/var/run/secrets/.../token`) |
| `AZURE_AUTHORITY_HOST`               |    opt   | Sovereign cloud override (default public) |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin                 |

### Auth mode: Managed Identity

No explicit env vars on the agent. Azure injects `IDENTITY_ENDPOINT` and
`IDENTITY_HEADER` (or legacy `MSI_ENDPOINT` / `MSI_SECRET`) on a VM or App
Service with an assigned identity; the passthrough list forwards them to `az`.
Optionally set `AZURE_SUBSCRIPTION_ID` to pin a default subscription.

### Auth mode: Cached `az login`

| Env var                              | Required | Purpose                                            |
| ------------------------------------ | :------: | -------------------------------------------------- |
| `HOME`                               |    Yes   | `az` looks for `~/.azure/` token cache under HOME  |
| `AZURE_CONFIG_DIR`                   |    opt   | Overrides `~/.azure/` location                     |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Overrides the cached default subscription          |

### Locale (all modes)

| Env var              | Required | Purpose                              |
| -------------------- | :------: | ------------------------------------ |
| `LANG` / `LC_ALL`    |    opt   | Suppresses Python locale warnings from `az` |

---

## Object Fields

| Field          | Type   | Required | Description                    | Example                            |
| -------------- | ------ | -------- | ------------------------------ | ---------------------------------- |
| `name`         | string | **Yes**  | Resource group name (exact)    | `rg-prooflayer-demo-eastus`        |
| `subscription` | string | opt      | Subscription ID override       | `00000000-0000-0000-0000-000000000000` |

If `subscription` is omitted the CLI uses `AZURE_SUBSCRIPTION_ID` or the cached
default from `az login`.

---

## Commands Executed

```
az group show --name rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
{
  "id": "/subscriptions/00000000-.../resourceGroups/rg-prooflayer-demo-eastus",
  "name": "rg-prooflayer-demo-eastus",
  "type": "Microsoft.Resources/resourceGroups",
  "location": "eastus",
  "managedBy": null,
  "properties": { "provisioningState": "Succeeded" },
  "tags": {
    "Environment": "demo",
    "FedRAMPImpactLevel": "moderate",
    "ManagedBy": "terraform",
    "Owner": "cslone",
    "Project": "prooflayer",
    "SubscriptionId": "00000000-0000-0000-0000-000000000000",
    "TenantId": "11111111-1111-1111-1111-111111111111"
  }
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                | Type    | Always Present | Source                                                                  |
| -------------------- | ------- | -------------- | ----------------------------------------------------------------------- |
| `found`              | boolean | Yes            | Derived — `true` on successful `az group show`, `false` on NotFound     |
| `name`               | string  | When found     | `name`                                                                  |
| `id`                 | string  | When found     | `id` (full ARM resource ID)                                             |
| `location`           | string  | When found     | `location` (lowercase short-name, e.g. `eastus`)                        |
| `provisioning_state` | string  | When found     | `properties.provisioningState`                                          |
| `managed_by`         | string  | When found     | `managedBy` — `null` in the API maps to empty string                    |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az group show` object. Empty `{}` when not found |

---

## RecordData Structure

```
id                           → "/subscriptions/.../resourceGroups/rg-name"
name                         → "rg-prooflayer-demo-eastus"
type                         → "Microsoft.Resources/resourceGroups"
location                     → "eastus"
managedBy                    → null
properties.provisioningState → "Succeeded"
tags.<Key>                   → "<Value>"      (flat string-to-string map)
```

Use `field tags.<Key> string = \`<Value>\`` in record_checks to enforce
required governance tags.

---

## State Fields

| State Field          | Type       | Allowed Operations                    | Maps To Collected Field |
| -------------------- | ---------- | ------------------------------------- | ----------------------- |
| `found`              | boolean    | `=`, `!=`                             | `found`                 |
| `name`               | string     | `=`, `!=`, `contains`, `starts`       | `name`                  |
| `id`                 | string     | `=`, `!=`, `contains`, `starts`       | `id`                    |
| `location`           | string     | `=`, `!=`                             | `location`              |
| `provisioning_state` | string     | `=`, `!=`                             | `provisioning_state`    |
| `managed_by`         | string     | `=`, `!=`, `contains`, `starts`       | `managed_by`            |
| `record`             | RecordData | (record checks)                       | `resource`              |

---

## Collection Strategy

| Property                 | Value                              |
| ------------------------ | ---------------------------------- |
| Collector ID             | `az-resource-group-collector`      |
| Collector Type           | `az_resource_group`                |
| Collection Mode          | Metadata                           |
| Required Capabilities    | `az_cli`, `reader`                 |
| Expected Collection Time | ~2000ms                            |
| Memory Usage             | ~2MB                               |
| Batch Collection         | No                                 |
| Per-call Timeout         | 15s (executor default 30s)         |

### Required Azure Permissions

`Reader` role on either:
- the subscription (enables enumeration — `ResourceGroupNotFound` on missing RG), or
- the specific resource group (denies enumeration — `AuthorizationFailed` on missing RG)

Both permission shapes are handled by the collector's NotFound detection.

---

## ESP Examples

### Baseline existence + provisioning check

```esp
OBJECT rg_eastus
    name `rg-prooflayer-demo-eastus`
    subscription `00000000-0000-0000-0000-000000000000`
OBJECT_END

STATE rg_provisioned
    found boolean = true
    provisioning_state string = `Succeeded`
STATE_END

CTN az_resource_group
    TEST all all AND
    STATE_REF rg_provisioned
    OBJECT_REF rg_eastus
CTN_END
```

### Required governance tags via record_checks

```esp
STATE required_tags_present
    found boolean = true
    record
        field tags.Environment string = `demo`
        field tags.ManagedBy string = `terraform`
        field tags.Project string = `prooflayer`
        field tags.FedRAMPImpactLevel string = `moderate`
    record_end
STATE_END

CTN az_resource_group
    TEST all all AND
    STATE_REF required_tags_present
    OBJECT_REF rg_eastus
    OBJECT_REF rg_westus
CTN_END
```

### RG must not be owned by a parent Azure service

```esp
STATE not_service_managed
    found boolean = true
    managed_by string = ``
STATE_END
```

### NotFound path — RG must not exist

```esp
STATE rg_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                        | Error Type                   | Outcome                          |
| ------------------------------------------------ | ---------------------------- | -------------------------------- |
| Resource group not found (subscription-scope)    | N/A (not an error)           | `found=false`                    |
| Resource group not found (RG-scope Reader)       | N/A (not an error)           | `found=false` via scope match    |
| `AuthorizationFailed` on a different scope       | `CollectionFailed`           | Error                            |
| `name` missing from OBJECT                       | `InvalidObjectConfiguration` | Error                            |
| Azure CLI binary not on PATH / not executable    | `CollectionFailed`           | Error                            |
| Azure CLI authentication failure                 | `CollectionFailed`           | Error                            |
| Stdout is not valid JSON                         | `CollectionFailed`           | Error                            |
| Incompatible CTN type                            | `CtnContractValidation`      | Error                            |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when any of:

1. stderr contains `ResourceGroupNotFound`
2. stderr contains `could not be found`
3. stderr contains `AuthorizationFailed` **and** the scope substring
   `resourcegroups/<rg_name>` (case-insensitive) appears — this catches
   RG-scoped Reader deployments where Azure cannot distinguish missing from
   forbidden.

Any other non-zero exit is a real `CollectionFailed` error.

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_role_assignment`              | RBAC assignments made at RG scope                               |
| `az_entra_group`                  | Entra groups often referenced by RG-scoped role assignments     |
