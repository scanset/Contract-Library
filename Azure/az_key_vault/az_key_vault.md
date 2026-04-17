# az_key_vault

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Key Vault's
configuration surface via a single Azure CLI call —
`az keyvault show --name <name> [--resource-group <rg>] [--subscription <id>]
--output json`. Returns core scalars (SKU, provisioning state,
RBAC/soft-delete/purge-protection flags, public network access, derived
network-ACL / access-policy / private-endpoint counts) plus the full response
as RecordData for tag-based and nested-field record_checks.

The CTN never enumerates or reads keys, secrets, or certificates, and never
requires any Azure permission above `Reader`. See "Non-Goals" at the bottom
for the full list of things this CTN will never do.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode — see `az_resource_group.md` for the full env-var matrix)
**Collection Method:** Single Azure CLI command per object via the shared
hardened `SystemCommandExecutor` (see `az_resource_group_command.rs`)
**Scope:** Control-plane only, read-only. Enumerates the vault's configuration
surface (SKU, flags, network ACLs, access policy / private-endpoint counts,
tags). Does NOT enumerate or read keys, secrets, or certificates — by design,
this CTN never touches the data plane and never requires any permission above
`Reader`.

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

`az_key_vault` inherits this env surface unchanged - no per-CTN overrides, no
per-collector env. If `az_resource_group` can authenticate successfully, so
can `az_key_vault`.

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

| Field            | Type   | Required | Description                                    | Example                                 |
| ---------------- | ------ | -------- | ---------------------------------------------- | --------------------------------------- |
| `name`           | string | **Yes**  | Key Vault name (exact, 3-24 alnum + hyphens)   | `kv-prooflayer-demo-ybuu`               |
| `resource_group` | string | opt      | Resource group name (disambiguation)           | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                       | `00000000-0000-0000-0000-000000000000`  |

`resource_group` is not required — `az keyvault show --name` alone resolves a
vault across accessible subscriptions. Pass it to narrow the lookup when the
SPN has visibility into multiple subs.

---

## Commands Executed

```
az keyvault show --name kv-prooflayer-demo-ybuu \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
{
  "id": "/subscriptions/00000000-.../vaults/kv-prooflayer-demo-ybuu",
  "name": "kv-prooflayer-demo-ybuu",
  "type": "Microsoft.KeyVault/vaults",
  "location": "eastus",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "properties": {
    "sku": { "family": "A", "name": "standard" },
    "tenantId": "11111111-...",
    "vaultUri": "https://kv-prooflayer-demo-ybuu.vault.azure.net/",
    "enableRbacAuthorization": true,
    "enablePurgeProtection": true,
    "enableSoftDelete": true,
    "enabledForDeployment": false,
    "enabledForDiskEncryption": false,
    "enabledForTemplateDeployment": false,
    "softDeleteRetentionInDays": null,
    "publicNetworkAccess": "Enabled",
    "provisioningState": "Succeeded",
    "accessPolicies": [],
    "networkAcls": null,
    "privateEndpointConnections": null
  },
  "tags": {
    "Environment": "demo",
    "FedRAMPImpactLevel": "moderate"
  }
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                             | Type    | Always Present | Source                                                |
| --------------------------------- | ------- | -------------- | ----------------------------------------------------- |
| `found`                           | boolean | Yes            | Derived - true on successful show, false on NotFound  |
| `name`                            | string  | When found     | `name`                                                |
| `id`                              | string  | When found     | `id`                                                  |
| `location`                        | string  | When found     | `location`                                            |
| `resource_group`                  | string  | When found     | `resourceGroup`                                       |
| `type`                            | string  | When found     | `type` (always `Microsoft.KeyVault/vaults`)           |
| `vault_uri`                       | string  | When found     | `properties.vaultUri`                                 |
| `tenant_id`                       | string  | When found     | `properties.tenantId`                                 |
| `sku_family`                      | string  | When found     | `properties.sku.family` (`A` = standard family)       |
| `sku_name`                        | string  | When found     | `properties.sku.name` (`standard` / `premium`)        |
| `provisioning_state`              | string  | When found     | `properties.provisioningState`                        |
| `public_network_access`           | string  | When found     | `properties.publicNetworkAccess` (`Enabled`/`Disabled`) |
| `enable_rbac_authorization`       | boolean | When found     | `properties.enableRbacAuthorization`                  |
| `enable_purge_protection`         | boolean | When found     | `properties.enablePurgeProtection`                    |
| `enable_soft_delete`              | boolean | When found     | `properties.enableSoftDelete`                         |
| `enabled_for_deployment`          | boolean | When found     | `properties.enabledForDeployment`                     |
| `enabled_for_disk_encryption`     | boolean | When found     | `properties.enabledForDiskEncryption`                 |
| `enabled_for_template_deployment` | boolean | When found     | `properties.enabledForTemplateDeployment`             |
| `soft_delete_retention_days`      | integer | When non-null  | `properties.softDeleteRetentionInDays` (omitted when null) |
| `has_network_acls`                | boolean | When found     | Derived - true when `properties.networkAcls != null`  |
| `network_acl_default_action`      | string  | When found     | `properties.networkAcls.defaultAction` (empty string when networkAcls absent) |
| `network_acl_bypass`              | string  | When found     | `properties.networkAcls.bypass` (empty string when networkAcls absent) |
| `network_acl_ip_rule_count`       | integer | When found     | `properties.networkAcls.ipRules.len()` (0 when networkAcls absent) |
| `network_acl_vnet_rule_count`     | integer | When found     | `properties.networkAcls.virtualNetworkRules.len()` (0 when networkAcls absent) |
| `network_acl_denies_by_default`   | boolean | When found     | Derived - true when `defaultAction` == `Deny` (case-insensitive) |
| `access_policy_count`             | integer | When found     | `properties.accessPolicies.len()` (0 when RBAC mode)  |
| `private_endpoint_count`          | integer | When found     | `properties.privateEndpointConnections.len()` (0 when null) |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az keyvault show` object. Empty `{}` when not found |

---

## RecordData Structure

```
id                                        -> "/subscriptions/.../vaults/<name>"
name                                      -> "kv-prooflayer-demo-ybuu"
type                                      -> "Microsoft.KeyVault/vaults"
location                                  -> "eastus"
resourceGroup                             -> "rg-prooflayer-demo-eastus"
properties.sku.name                       -> "standard"
properties.vaultUri                       -> "https://<name>.vault.azure.net/"
properties.publicNetworkAccess            -> "Enabled" | "Disabled"
properties.enableRbacAuthorization        -> true | false
properties.enablePurgeProtection          -> true | false
properties.enableSoftDelete               -> true | false
properties.softDeleteRetentionInDays      -> 7-90 | null
properties.networkAcls                    -> null | { bypass, defaultAction, ipRules[], virtualNetworkRules[] }
properties.privateEndpointConnections     -> null | [ { id, properties: { privateEndpoint, privateLinkServiceConnectionState } }, ... ]
properties.accessPolicies                 -> [] | [ { tenantId, objectId, permissions: { keys[], secrets[], certificates[] } }, ... ]
tags.<Key>                                -> "<Value>"   (flat string-to-string map)
```

Use `field properties.<path> <type> = \`<Value>\`` in record_checks to enforce
nested properties. Example: `field properties.networkAcls.defaultAction
string = \`Deny\``.

---

## State Fields

| State Field                       | Type       | Allowed Operations                           | Maps To Collected Field             |
| --------------------------------- | ---------- | -------------------------------------------- | ----------------------------------- |
| `found`                           | boolean    | `=`, `!=`                                    | `found`                             |
| `name`                            | string     | `=`, `!=`, `contains`, `starts`              | `name`                              |
| `id`                              | string     | `=`, `!=`, `contains`, `starts`              | `id`                                |
| `location`                        | string     | `=`, `!=`                                    | `location`                          |
| `resource_group`                  | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                    |
| `vault_uri`                       | string     | `=`, `!=`, `contains`, `starts`              | `vault_uri`                         |
| `tenant_id`                       | string     | `=`, `!=`                                    | `tenant_id`                         |
| `sku_family`                      | string     | `=`, `!=`                                    | `sku_family`                        |
| `sku_name`                        | string     | `=`, `!=`                                    | `sku_name`                          |
| `provisioning_state`              | string     | `=`, `!=`                                    | `provisioning_state`                |
| `public_network_access`           | string     | `=`, `!=`                                    | `public_network_access`             |
| `enable_rbac_authorization`       | boolean    | `=`, `!=`                                    | `enable_rbac_authorization`         |
| `enable_purge_protection`         | boolean    | `=`, `!=`                                    | `enable_purge_protection`           |
| `enable_soft_delete`              | boolean    | `=`, `!=`                                    | `enable_soft_delete`                |
| `enabled_for_deployment`          | boolean    | `=`, `!=`                                    | `enabled_for_deployment`            |
| `enabled_for_disk_encryption`     | boolean    | `=`, `!=`                                    | `enabled_for_disk_encryption`       |
| `enabled_for_template_deployment` | boolean    | `=`, `!=`                                    | `enabled_for_template_deployment`   |
| `has_network_acls`                | boolean    | `=`, `!=`                                    | `has_network_acls`                  |
| `network_acl_default_action`      | string     | `=`, `!=`                                    | `network_acl_default_action`        |
| `network_acl_bypass`              | string     | `=`, `!=`                                    | `network_acl_bypass`                |
| `network_acl_denies_by_default`   | boolean    | `=`, `!=`                                    | `network_acl_denies_by_default`     |
| `soft_delete_retention_days`      | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `soft_delete_retention_days`        |
| `access_policy_count`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `access_policy_count`               |
| `private_endpoint_count`          | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `private_endpoint_count`            |
| `network_acl_ip_rule_count`       | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `network_acl_ip_rule_count`         |
| `network_acl_vnet_rule_count`     | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `network_acl_vnet_rule_count`       |
| `record`                          | RecordData | (record checks)                              | `resource`                          |

---

## Collection Strategy

| Property                 | Value                              |
| ------------------------ | ---------------------------------- |
| Collector ID             | `az-key-vault-collector`           |
| Collector Type           | `az_key_vault`                     |
| Collection Mode          | Metadata                           |
| Required Capabilities    | `az_cli`, `reader`                 |
| Expected Collection Time | ~2000ms                            |
| Memory Usage             | ~2MB                               |
| Batch Collection         | No                                 |
| Per-call Timeout         | 15s (executor default 30s)         |

### Required Azure Permissions

`Reader` role at subscription, RG, or vault scope. That's it. No data-plane
role (`Key Vault Reader`, `Key Vault Secrets User`, etc.) is ever needed or
used — this CTN is read-only by design and never enumerates or reads keys,
secrets, or certificates.

---

## ESP Examples

### Baseline hardening check

```esp
OBJECT kv_prod
    name `kv-prooflayer-demo-ybuu`
OBJECT_END

STATE kv_hardened
    found boolean = true
    provisioning_state string = `Succeeded`
    enable_rbac_authorization boolean = true
    enable_purge_protection boolean = true
    enable_soft_delete boolean = true
    enabled_for_deployment boolean = false
    enabled_for_template_deployment boolean = false
STATE_END

CTN az_key_vault
    TEST all all AND
    STATE_REF kv_hardened
    OBJECT_REF kv_prod
CTN_END
```

### Network isolation check (requires networkAcls present)

```esp
STATE kv_network_locked_down
    found boolean = true
    public_network_access string = `Disabled`
    has_network_acls boolean = true
    record
        field properties.networkAcls.defaultAction string = `Deny`
        field properties.networkAcls.bypass string = `AzureServices`
    record_end
STATE_END
```

### Retention policy check

```esp
STATE kv_retention_sufficient
    found boolean = true
    soft_delete_retention_days integer >= 90
STATE_END
```

### Required KSI tags via record_checks

```esp
STATE kv_tagged_for_ksi
    found boolean = true
    record
        field tags.ksi-ksi-svc-asm string = `Automating Secret Management`
        field tags.ksi-ksi-afr-ucm string = `Using Cryptographic Modules`
    record_end
STATE_END
```

### NotFound path - vault must not exist

```esp
STATE kv_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                        | Error Type                   | Outcome                          |
| ------------------------------------------------ | ---------------------------- | -------------------------------- |
| Vault not found (any scope)                      | N/A (not an error)           | `found=false`                    |
| Vault name malformed (too short, bad chars)      | N/A (not an error)           | `found=false` (Azure returns NotFound) |
| `name` missing from OBJECT                       | `InvalidObjectConfiguration` | Error                            |
| Azure CLI binary not on PATH                     | `CollectionFailed`           | Error                            |
| Azure CLI authentication failure                 | `CollectionFailed`           | Error                            |
| Stdout is not valid JSON                         | `CollectionFailed`           | Error                            |
| Incompatible CTN type                            | `CtnContractValidation`      | Error                            |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr matches
any of:

1. `"not found within subscription"` - covers both genuine NotFound and
   malformed inputs (Azure returns the same error for `--name x`).
2. `"(ResourceNotFound)"` / `"(NotFound)"` - defensive fallback patterns.

Any other non-zero exit is a real `CollectionFailed` error.

---

## Non-Goals (what this CTN will never do)

Compliance-scanning CTNs must stay read-only and minimal-permission. The
following are out of scope permanently — not deferred, not on a roadmap,
not a future phase:

- **No data-plane enumeration.** The CTN will never call
  `az keyvault key list`, `secret list`, or `certificate list`, and will
  never require `Key Vault Reader`, `Key Vault Secrets User`, or any other
  data-plane role.
- **No read of key material, secret values, or certificate private keys.**
  Even "list" operations are intentionally excluded to keep the permission
  surface at `Reader` only.
- **No mutation of any kind.** No rotate, no update, no delete, no tag
  writes, no policy edits. The CTN only runs `az keyvault show` (GET).
- **No network probes.** No connectivity tests to `vaultUri`, no DNS
  resolution checks, no TLS handshakes.

If a compliance control requires evidence about the contents of a vault
(e.g. "no secret older than 90 days"), that evidence must come from a
separate system with its own auditable access path — not from the scanner.

---

## Known Azure CLI Bugs to Avoid

| Command                                          | Issue                                                          |
| ------------------------------------------------ | -------------------------------------------------------------- |
| `az network private-endpoint-connection list --id <vault-id>` | Crashes with `KeyError: 'privateEndpointConnections'` when the vault has null endpoints. Read `properties.privateEndpointConnections` from `az keyvault show` output instead. |

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the vault (tag inheritance reference point)   |
| `az_role_assignment`              | RBAC at vault scope when `enable_rbac_authorization=true`       |
| `az_diagnostic_setting` (future)  | Audit log routing for vault operations                          |
