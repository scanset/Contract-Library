# az_storage_account

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Storage
Account's configuration surface via a single Azure CLI call —
`az storage account show --name <name> --resource-group <rg>
[--subscription <id>] --output json`. Returns the major compliance scalars
(transport, auth posture, encryption, network ACLs, identity, provisioning)
plus the full response as RecordData for tag-based and nested-field
record_checks.

The CTN never enumerates containers, blobs, queues, tables, file shares,
keys, or SAS tokens, and never requires any Azure permission above `Reader`.
See "Non-Goals" at the bottom for the full list of things this CTN will
never do.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode — see `az_resource_group.md` for the full env-var matrix)
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

`az_storage_account` inherits this env surface unchanged - no per-CTN overrides,
no per-collector env. If `az_resource_group` can authenticate successfully, so
can `az_storage_account`.

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
| `name`           | string | **Yes**  | Storage account name (3-24 lowercase alnum)    | `stlogsprooflayerdemog71v`              |
| `resource_group` | string | **Yes**  | Resource group that owns the account           | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                       | `00000000-0000-0000-0000-000000000000`  |

### Behavior Modifiers

| Behavior                      | Type | Default | Description                                          |
| ----------------------------- | ---- | ------- | ---------------------------------------------------- |
| `include_blob_properties`     | bool | false   | Triggers a second API call to fetch blob-service-properties (soft delete, versioning, change feed, last-access-time tracking) |

When `behavior include_blob_properties true` is set on an OBJECT, the collector
makes an additional call to `az storage account blob-service-properties show`
after the base `az storage account show`. This populates 7 additional fields
(see Behavior-Gated Fields below). If the second call fails, those fields stay
absent and any STATE assertions against them produce Error (field missing) --
the base collection still succeeds.

`resource_group` is required -- unlike `az keyvault show`, `az storage account
show` demands `-g` even though storage account names are globally unique.
Azure performs no client-side validation of the name: malformed inputs
(uppercase, hyphens, single char, etc.) return `ResourceNotFound` at runtime.

---

## Commands Executed

### Base command (always)

```
az storage account show --name stlogsprooflayerdemog71v \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

### Behavior-gated command (when `include_blob_properties` is true)

```
az storage account blob-service-properties show \
    --account-name stlogsprooflayerdemog71v \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample base response (abbreviated):**

```json
{
  "id": "/subscriptions/.../storageAccounts/stlogsprooflayerdemog71v",
  "name": "stlogsprooflayerdemog71v",
  "type": "Microsoft.Storage/storageAccounts",
  "kind": "StorageV2",
  "location": "eastus",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "accessTier": "Hot",
  "sku": { "name": "Standard_LRS", "tier": "Standard" },
  "provisioningState": "Succeeded",
  "statusOfPrimary": "available",
  "primaryLocation": "eastus",
  "secondaryLocation": null,
  "enableHttpsTrafficOnly": true,
  "minimumTlsVersion": "TLS1_2",
  "allowBlobPublicAccess": false,
  "allowSharedKeyAccess": true,
  "allowCrossTenantReplication": false,
  "defaultToOAuthAuthentication": false,
  "publicNetworkAccess": "Enabled",
  "dnsEndpointType": "Standard",
  "isHnsEnabled": false,
  "isSftpEnabled": false,
  "isLocalUserEnabled": true,
  "enableNfsV3": false,
  "encryption": {
    "keySource": "Microsoft.Storage",
    "keyVaultProperties": null,
    "requireInfrastructureEncryption": null,
    "services": {
      "blob":  { "enabled": true, "keyType": "Account" },
      "file":  { "enabled": true, "keyType": "Account" },
      "queue": null,
      "table": null
    }
  },
  "networkRuleSet": {
    "bypass": "AzureServices",
    "defaultAction": "Allow",
    "ipRules": [],
    "virtualNetworkRules": [],
    "resourceAccessRules": []
  },
  "privateEndpointConnections": [],
  "identity": { "type": "None", "principalId": null, "tenantId": null },
  "tags": {
    "Environment": "demo",
    "FedRAMPImpactLevel": "moderate",
    "ksi-ksi-mla-let": "Logging Event Types"
  }
}
```

**Sample blob-service-properties response (abbreviated):**

```json
{
  "deleteRetentionPolicy": {
    "allowPermanentDelete": false,
    "days": 7,
    "enabled": true
  },
  "containerDeleteRetentionPolicy": {
    "days": 7,
    "enabled": true
  },
  "isVersioningEnabled": true,
  "changeFeed": {
    "enabled": true,
    "retentionInDays": null
  },
  "lastAccessTimeTrackingPolicy": {
    "blobType": ["blockBlob"],
    "enable": true,
    "name": "AccessTimeTracking",
    "trackingGranularityInDays": 1
  }
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                             | Type    | Always Present | Source                                                    |
| --------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`                           | boolean | Yes            | Derived - true on successful show, false on NotFound      |
| `name`                            | string  | When found     | `name`                                                    |
| `id`                              | string  | When found     | `id`                                                      |
| `type`                            | string  | When found     | `type`                                                    |
| `kind`                            | string  | When found     | `kind`                                                    |
| `location`                        | string  | When found     | `location`                                                |
| `resource_group`                  | string  | When found     | `resourceGroup`                                           |
| `access_tier`                     | string  | When present   | `accessTier` (may be null on some kinds)                  |
| `sku_name`                        | string  | When found     | `sku.name`                                                |
| `sku_tier`                        | string  | When found     | `sku.tier`                                                |
| `provisioning_state`              | string  | When found     | `provisioningState`                                       |
| `status_of_primary`               | string  | When found     | `statusOfPrimary`                                         |
| `primary_location`                | string  | When found     | `primaryLocation`                                         |
| `secondary_location`              | string  | When present   | `secondaryLocation` (null for LRS)                        |
| `minimum_tls_version`             | string  | When found     | `minimumTlsVersion`                                       |
| `public_network_access`           | string  | When found     | `publicNetworkAccess` (`Enabled` / `Disabled`)            |
| `dns_endpoint_type`               | string  | When found     | `dnsEndpointType` (`Standard` or `AzureDnsZone`)          |
| `encryption_key_source`           | string  | When found     | `encryption.keySource`                                    |
| `network_default_action`          | string  | When found     | `networkRuleSet.defaultAction`                            |
| `network_bypass`                  | string  | When found     | `networkRuleSet.bypass`                                   |
| `identity_type`                   | string  | Yes            | `identity.type` (defaulted to `None` when identity absent)|
| `enable_https_traffic_only`       | boolean | When found     | `enableHttpsTrafficOnly`                                  |
| `allow_blob_public_access`        | boolean | When found     | `allowBlobPublicAccess`                                   |
| `allow_shared_key_access`         | boolean | When found     | `allowSharedKeyAccess`                                    |
| `allow_cross_tenant_replication`  | boolean | When found     | `allowCrossTenantReplication`                             |
| `default_to_oauth_authentication` | boolean | When found     | `defaultToOAuthAuthentication`                            |
| `is_hns_enabled`                  | boolean | When found     | `isHnsEnabled`                                            |
| `is_sftp_enabled`                 | boolean | When found     | `isSftpEnabled`                                           |
| `is_local_user_enabled`           | boolean | When found     | `isLocalUserEnabled`                                      |
| `enable_nfs_v3`                   | boolean | When found     | `enableNfsV3`                                             |
| `cmk_enabled`                     | boolean | When found     | Derived - true when `keySource == Microsoft.Keyvault`     |
| `require_infrastructure_encryption`| boolean| When found     | `encryption.requireInfrastructureEncryption` (null -> false) |
| `blob_encryption_enabled`         | boolean | Usually        | `encryption.services.blob.enabled` (omitted if svc null)  |
| `file_encryption_enabled`         | boolean | Usually        | `encryption.services.file.enabled` (omitted if svc null)  |
| `queue_encryption_enabled`        | boolean | When present   | `encryption.services.queue.enabled` (null when unused)    |
| `table_encryption_enabled`        | boolean | When present   | `encryption.services.table.enabled` (null when unused)    |
| `has_network_acls`                | boolean | When found     | Derived - true when `networkRuleSet.defaultAction == Deny`|
| `has_private_endpoints`           | boolean | Yes            | Derived - true when `privateEndpointConnections.len() > 0`|
| `has_managed_identity`            | boolean | Yes            | Derived - true when `identity.type != None`               |
| `ip_rule_count`                   | integer | When found     | `networkRuleSet.ipRules.len()`                            |
| `vnet_rule_count`                 | integer | When found     | `networkRuleSet.virtualNetworkRules.len()`                |
| `private_endpoint_count`          | integer | Yes            | `privateEndpointConnections.len()` (0 when null/empty)    |

### Same-Response Fields (from base `az storage account show`)

| Field                             | Type    | Always Present | Source                                                    |
| --------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `immutable_storage_enabled`       | boolean | When found     | `immutableStorageWithVersioning.enabled` (false when absent) |
| `key_creation_time_key1`          | string  | When present   | `keyCreationTime.key1` (ISO 8601 timestamp)               |
| `key_creation_time_key2`          | string  | When present   | `keyCreationTime.key2` (ISO 8601 timestamp)               |
| `large_file_shares_state`         | string  | When present   | `largeFileSharesState` (null on most accounts)            |

### Behavior-Gated Fields (require `behavior include_blob_properties true`)

These fields are only populated when the OBJECT includes `behavior include_blob_properties true`.
They come from the second API call to `az storage account blob-service-properties show`.

| Field                             | Type    | Always Present | Source                                                    |
| --------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `blob_soft_delete_enabled`        | boolean | When behavior set | `deleteRetentionPolicy.enabled`                        |
| `blob_soft_delete_days`           | integer | When enabled   | `deleteRetentionPolicy.days` (absent when disabled)       |
| `container_soft_delete_enabled`   | boolean | When behavior set | `containerDeleteRetentionPolicy.enabled`               |
| `container_soft_delete_days`      | integer | When enabled   | `containerDeleteRetentionPolicy.days` (absent when disabled) |
| `versioning_enabled`              | boolean | When behavior set | `isVersioningEnabled`                                  |
| `change_feed_enabled`             | boolean | When behavior set | `changeFeed.enabled`                                   |
| `last_access_time_enabled`        | boolean | When behavior set | `lastAccessTimeTrackingPolicy.enable` (note: "enable" not "enabled") |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az storage account show` object. Empty `{}` when not found |

---

## RecordData Structure

```
id                                           -> "/subscriptions/.../storageAccounts/<name>"
name                                         -> "stlogsprooflayerdemog71v"
type                                         -> "Microsoft.Storage/storageAccounts"
kind                                         -> "StorageV2" | "Storage" | "BlobStorage" | ...
location                                     -> "eastus"
resourceGroup                                -> "rg-prooflayer-demo-eastus"
sku.name                                     -> "Standard_LRS" | "Standard_GRS" | ...
sku.tier                                     -> "Standard" | "Premium"
accessTier                                   -> "Hot" | "Cool" | "Premium" | null
enableHttpsTrafficOnly                       -> true | false
minimumTlsVersion                            -> "TLS1_0" | "TLS1_1" | "TLS1_2"
publicNetworkAccess                          -> "Enabled" | "Disabled"
allowBlobPublicAccess                        -> true | false
allowSharedKeyAccess                         -> true | false
allowCrossTenantReplication                  -> true | false
defaultToOAuthAuthentication                 -> true | false
isHnsEnabled / isSftpEnabled / enableNfsV3   -> true | false
encryption.keySource                         -> "Microsoft.Storage" | "Microsoft.Keyvault"
encryption.keyVaultProperties.keyName        -> "<kv-key-name>" (CMK only)
encryption.keyVaultProperties.keyVaultUri    -> "https://<kv>.vault.azure.net/" (CMK only)
encryption.keyVaultProperties.currentVersionedKeyIdentifier -> "..." (CMK only)
encryption.requireInfrastructureEncryption   -> true | false | null
encryption.services.blob.enabled             -> true | false
encryption.services.file.enabled             -> true | false
encryption.services.queue.enabled            -> true | false | null
encryption.services.table.enabled            -> true | false | null
networkRuleSet.defaultAction                 -> "Allow" | "Deny"
networkRuleSet.bypass                        -> "AzureServices" | "None" | ...
networkRuleSet.ipRules[]                     -> [ { value, action } ]
networkRuleSet.virtualNetworkRules[]         -> [ { id, action, state } ]
networkRuleSet.resourceAccessRules[]         -> [ { tenantId, resourceId } ]
privateEndpointConnections[]                 -> [ { id, properties: { privateLinkServiceConnectionState: { status } } } ]
identity.type                                -> "None" | "SystemAssigned" | "UserAssigned" | "SystemAssigned,UserAssigned"
identity.principalId                         -> "<guid>" | null
tags.<Key>                                   -> "<Value>"   (flat string-to-string map)
```

Use `field <path> <type> = \`<value>\`` in `record_checks` to enforce
nested properties. Example:
`field encryption.keyVaultProperties.keyName string = \`storage-cmk\``.

---

## State Fields

| State Field                       | Type       | Allowed Operations                           | Maps To Collected Field             |
| --------------------------------- | ---------- | -------------------------------------------- | ----------------------------------- |
| `found`                           | boolean    | `=`, `!=`                                    | `found`                             |
| `name`                            | string     | `=`, `!=`, `contains`, `starts`              | `name`                              |
| `id`                              | string     | `=`, `!=`, `contains`, `starts`              | `id`                                |
| `type`                            | string     | `=`, `!=`                                    | `type`                              |
| `kind`                            | string     | `=`, `!=`                                    | `kind`                              |
| `location`                        | string     | `=`, `!=`                                    | `location`                          |
| `resource_group`                  | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                    |
| `access_tier`                     | string     | `=`, `!=`                                    | `access_tier`                       |
| `sku_name`                        | string     | `=`, `!=`                                    | `sku_name`                          |
| `sku_tier`                        | string     | `=`, `!=`                                    | `sku_tier`                          |
| `provisioning_state`              | string     | `=`, `!=`                                    | `provisioning_state`                |
| `status_of_primary`               | string     | `=`, `!=`                                    | `status_of_primary`                 |
| `primary_location`                | string     | `=`, `!=`                                    | `primary_location`                  |
| `secondary_location`              | string     | `=`, `!=`                                    | `secondary_location`                |
| `minimum_tls_version`             | string     | `=`, `!=`                                    | `minimum_tls_version`               |
| `public_network_access`           | string     | `=`, `!=`                                    | `public_network_access`             |
| `dns_endpoint_type`               | string     | `=`, `!=`                                    | `dns_endpoint_type`                 |
| `encryption_key_source`           | string     | `=`, `!=`                                    | `encryption_key_source`             |
| `network_default_action`          | string     | `=`, `!=`                                    | `network_default_action`            |
| `network_bypass`                  | string     | `=`, `!=`                                    | `network_bypass`                    |
| `identity_type`                   | string     | `=`, `!=`                                    | `identity_type`                     |
| `enable_https_traffic_only`       | boolean    | `=`, `!=`                                    | `enable_https_traffic_only`         |
| `allow_blob_public_access`        | boolean    | `=`, `!=`                                    | `allow_blob_public_access`          |
| `allow_shared_key_access`         | boolean    | `=`, `!=`                                    | `allow_shared_key_access`           |
| `allow_cross_tenant_replication`  | boolean    | `=`, `!=`                                    | `allow_cross_tenant_replication`    |
| `default_to_oauth_authentication` | boolean    | `=`, `!=`                                    | `default_to_oauth_authentication`   |
| `is_hns_enabled`                  | boolean    | `=`, `!=`                                    | `is_hns_enabled`                    |
| `is_sftp_enabled`                 | boolean    | `=`, `!=`                                    | `is_sftp_enabled`                   |
| `is_local_user_enabled`           | boolean    | `=`, `!=`                                    | `is_local_user_enabled`             |
| `enable_nfs_v3`                   | boolean    | `=`, `!=`                                    | `enable_nfs_v3`                     |
| `cmk_enabled`                     | boolean    | `=`, `!=`                                    | `cmk_enabled`                       |
| `require_infrastructure_encryption`| boolean   | `=`, `!=`                                    | `require_infrastructure_encryption` |
| `blob_encryption_enabled`         | boolean    | `=`, `!=`                                    | `blob_encryption_enabled`           |
| `file_encryption_enabled`         | boolean    | `=`, `!=`                                    | `file_encryption_enabled`           |
| `queue_encryption_enabled`        | boolean    | `=`, `!=`                                    | `queue_encryption_enabled`          |
| `table_encryption_enabled`        | boolean    | `=`, `!=`                                    | `table_encryption_enabled`          |
| `has_network_acls`                | boolean    | `=`, `!=`                                    | `has_network_acls`                  |
| `has_private_endpoints`           | boolean    | `=`, `!=`                                    | `has_private_endpoints`             |
| `has_managed_identity`            | boolean    | `=`, `!=`                                    | `has_managed_identity`              |
| `ip_rule_count`                   | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `ip_rule_count`                     |
| `vnet_rule_count`                 | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `vnet_rule_count`                   |
| `private_endpoint_count`          | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `private_endpoint_count`            |
| `immutable_storage_enabled`       | boolean    | `=`, `!=`                                    | `immutable_storage_enabled`         |
| `key_creation_time_key1`          | string     | `=`, `!=`, `contains`, `starts`              | `key_creation_time_key1`            |
| `key_creation_time_key2`          | string     | `=`, `!=`, `contains`, `starts`              | `key_creation_time_key2`            |
| `large_file_shares_state`         | string     | `=`, `!=`                                    | `large_file_shares_state`           |
| `blob_soft_delete_enabled`        | boolean    | `=`, `!=`                                    | `blob_soft_delete_enabled` *        |
| `blob_soft_delete_days`           | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `blob_soft_delete_days` *           |
| `container_soft_delete_enabled`   | boolean    | `=`, `!=`                                    | `container_soft_delete_enabled` *   |
| `container_soft_delete_days`      | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `container_soft_delete_days` *      |
| `versioning_enabled`              | boolean    | `=`, `!=`                                    | `versioning_enabled` *              |
| `change_feed_enabled`             | boolean    | `=`, `!=`                                    | `change_feed_enabled` *             |
| `last_access_time_enabled`        | boolean    | `=`, `!=`                                    | `last_access_time_enabled` *        |
| `record`                          | RecordData | (record checks)                              | `resource`                          |

\* Requires `behavior include_blob_properties true` on the OBJECT. Without the
behavior modifier, these fields are absent and any STATE assertion produces Error.

---

## Collection Strategy

| Property                 | Value                                |
| ------------------------ | ------------------------------------ |
| Collector ID             | `az-storage-account-collector`       |
| Collector Type           | `az_storage_account`                 |
| Collection Mode          | Metadata                             |
| Required Capabilities    | `az_cli`, `reader`                   |
| Expected Collection Time | ~2000ms (base), ~4000ms (with blob props) |
| Memory Usage             | ~2MB                                 |
| Batch Collection         | No                                   |
| Per-call Timeout         | 30s per CLI call                     |
| API Calls                | 1 (base) or 2 (with `include_blob_properties`) |

### Required Azure Permissions

`Reader` role at subscription, RG, or account scope. That's it. No
data-plane role (`Storage Blob Data Reader`, `Storage Account Key Operator`,
etc.) is ever needed or used — this CTN is read-only by design and never
enumerates or reads blobs, containers, queues, tables, file shares, or
access keys.

---

## ESP Examples

### Baseline hardening check (transport + auth + replication)

```esp
OBJECT storage_logs
    name `stlogsprooflayerdemog71v`
    resource_group `rg-prooflayer-demo-eastus`
OBJECT_END

STATE storage_baseline
    found boolean = true
    provisioning_state string = `Succeeded`
    enable_https_traffic_only boolean = true
    minimum_tls_version string = `TLS1_2`
    allow_blob_public_access boolean = false
    allow_cross_tenant_replication boolean = false
    blob_encryption_enabled boolean = true
    file_encryption_enabled boolean = true
STATE_END

CTN az_storage_account
    TEST all all AND
    STATE_REF storage_baseline
    OBJECT_REF storage_logs
CTN_END
```

### Network isolation check (requires Deny + private endpoints)

```esp
STATE storage_network_locked_down
    found boolean = true
    public_network_access string = `Disabled`
    network_default_action string = `Deny`
    has_network_acls boolean = true
    has_private_endpoints boolean = true
    private_endpoint_count int >= 1
STATE_END
```

### OAuth-only (no shared-key auth)

```esp
STATE storage_oauth_only
    found boolean = true
    allow_shared_key_access boolean = false
    default_to_oauth_authentication boolean = true
STATE_END
```

### CMK + infrastructure encryption

```esp
STATE storage_cmk_with_double_encryption
    found boolean = true
    cmk_enabled boolean = true
    encryption_key_source string = `Microsoft.Keyvault`
    require_infrastructure_encryption boolean = true
    record
        field encryption.keyVaultProperties.keyName string = `storage-cmk`
    record_end
STATE_END
```

### Required KSI tags via record_checks

```esp
STATE storage_tagged_for_ksi
    found boolean = true
    record
        field tags.ksi-ksi-mla-let string = `Logging Event Types`
        field tags.ksi-ksi-cmt-lmc string = `Logging Changes`
    record_end
STATE_END
```

### Data protection via behavior modifier (soft delete + versioning)

```esp
OBJECT sa_logs
    name `stlogsprooflayerdemog71v`
    resource_group `rg-prooflayer-demo-eastus`
    behavior include_blob_properties true
OBJECT_END

STATE sa_data_protection
    found boolean = true
    immutable_storage_enabled boolean = false
    blob_soft_delete_enabled boolean = false
    container_soft_delete_enabled boolean = false
    versioning_enabled boolean = true
    change_feed_enabled boolean = false
STATE_END

CTN az_storage_account
    TEST all all AND
    STATE_REF sa_data_protection
    OBJECT_REF sa_logs
CTN_END
```

Note: the `behavior` directive must be inside the OBJECT block, not the CTN
block. This is per ESP grammar -- `behavior_spec` is an `object_element`.
Without the behavior modifier, the blob-service-properties fields are absent
and STATE assertions against them produce Error (field missing).

### NotFound path - account must not exist

```esp
STATE storage_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                        | Error Type                   | Outcome                          |
| ------------------------------------------------ | ---------------------------- | -------------------------------- |
| Account not found (real RG, missing/malformed name) | N/A (not an error)        | `found=false` via `ResourceNotFound` |
| Account not found (fake or inaccessible RG)      | N/A (not an error)           | `found=false` via `AuthorizationFailed` scoped to storageAccounts |
| `name` missing from OBJECT                       | `InvalidObjectConfiguration` | Error                            |
| `resource_group` missing from OBJECT             | `InvalidObjectConfiguration` | Error                            |
| Azure CLI binary not on PATH                     | `CollectionFailed`           | Error                            |
| Azure CLI authentication failure                 | `CollectionFailed`           | Error                            |
| `AuthorizationFailed` on non-storageAccounts scope | `CollectionFailed`         | Error (not treated as NotFound)  |
| Stdout is not valid JSON                         | `CollectionFailed`           | Error                            |
| Incompatible CTN type                            | `CtnContractValidation`      | Error                            |
| Blob-service-properties call fails (behavior on) | N/A (non-fatal)              | Base collection succeeds; behavior-gated fields absent |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr
matches either:

1. `(ResourceNotFound)` / `Code: ResourceNotFound` - covers real RG with
   missing or malformed account name (exit code 3). Azure does no
   client-side name validation, so single-char names, hyphens, uppercase,
   and any other malformed input all land here.
2. `(AuthorizationFailed)` **and** the scope string contains
   `/storageAccounts/` - covers fake or inaccessible RG (exit code 1).
   This is the same RBAC-opacity pattern seen in `az_resource_group`: Azure
   cannot distinguish "RG does not exist" from "caller has no access to
   RG" when the caller is scoped narrowly.

Note the two cases use different exit codes (3 vs 1), so the collector
matches on stderr content rather than exit code. An `AuthorizationFailed`
that does NOT mention `/storageAccounts/` is treated as a real error
(probably a broken pipeline or misconfigured RBAC elsewhere), not a NotFound.

---

## Non-Goals (what this CTN will never do)

Compliance-scanning CTNs must stay read-only and minimal-permission. The
following are out of scope permanently:

- **No data-plane enumeration.** The CTN will never call
  `az storage blob list/show`, `az storage container list/show`,
  `az storage queue list`, `az storage table list`, `az storage share list`,
  or any other data-plane read. It will never require `Storage Blob Data
  Reader`, `Storage Queue Data Reader`, `Storage File Data SMB Share Reader`,
  or any other data-plane role.
- **No key or SAS token reads.** No `az storage account keys list`, no
  `az storage account show-connection-string`, no SAS generation. Account
  keys are the single highest-value secret on a storage account; the
  scanner's operating principle is it never sees them.
- **No reading of blob/queue/table/share contents** - even metadata about
  individual items inside a container (blob names, sizes, ETags, tier,
  lease status) is off-limits. Account-level counts are fine; per-item
  enumeration is not.
- **No mutation of any kind.** No create, update, delete, key rotation,
  tag writes, lifecycle policy changes, SAS revocations. The CTN only
  runs `az storage account show` (GET).
- **No network probes.** No connectivity tests to `*.blob.core.windows.net`,
  `*.file.core.windows.net`, etc. No DNS resolution checks, no TLS
  handshakes, no anonymous-access probing.

If a compliance control requires evidence about the contents of a storage
account (e.g. "no public containers", "no blobs older than 90 days",
"all SAS tokens expire within 7 days"), that evidence must come from a
separate system with its own auditable access path — typically Azure
Policy, Azure Storage's own diagnostic logs, or a storage-lifecycle
management feature — not from the scanner.

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the account (tag inheritance reference point) |
| `az_key_vault`                    | Holds the CMK when `encryption_key_source == Microsoft.Keyvault`|
| `az_role_assignment`              | RBAC at account scope for OAuth auth enforcement                |
| `az_diagnostic_setting` (future)  | Log routing for storage operations (blob, queue, file audit)    |
| `az_nsg` (future)                 | Complements `networkRuleSet` with subnet-side filtering         |
