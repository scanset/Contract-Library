# az_disk_encryption_set CTN Contract

**CTN Type:** `az_disk_encryption_set`
**Platform:** Azure
**Category:** Compute / Encryption (Control-Plane)
**CLI Command:** `az disk-encryption-set show`

---

## Overview

The `az_disk_encryption_set` CTN collects and validates Azure Disk Encryption Set
(DES) resources. It queries a single DES by name and resource group, returning
scalar fields for encryption type, managed identity, auto key rotation, active
key URL with parsed vault/key/version components, and the full JSON response
as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                      |
|------------------|--------|----------|----------------------------------|
| `name`           | string | Yes      | Disk encryption set name         |
| `resource_group` | string | Yes      | Resource group owning the DES    |
| `subscription`   | string | No       | Subscription ID override         |

### Example OBJECT Block

```
OBJECT des_prod
    name `des-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops    | Description                              |
|---------|---------|--------|------------------------------------------|
| `found` | boolean | `= !=` | Whether the disk encryption set was found|

### Identity and Location

| Field               | Type   | Ops        | Description              | Example                                                |
|---------------------|--------|------------|--------------------------|--------------------------------------------------------|
| `name`              | string | `= != ~ ^` | DES name                 | `des-example-prod`                                     |
| `id`                | string | `= != ~ ^` | Full ARM resource ID     | `/subscriptions/00000000-.../diskEncryptionSets/des-example-prod` |
| `type`              | string | `= !=`     | ARM resource type        | `Microsoft.Compute/diskEncryptionSets`                 |
| `location`          | string | `= !=`     | Azure region             | `eastus`                                               |
| `resource_group`    | string | `= != ~ ^` | Resource group name      | `rg-example-eastus`                                    |
| `provisioning_state`| string | `= !=`     | Provisioning state       | `Succeeded`                                            |

### Encryption Configuration

| Field              | Type   | Ops    | Description                    | Example                                  |
|--------------------|--------|--------|--------------------------------|------------------------------------------|
| `encryption_type`  | string | `= !=` | Encryption type                | `EncryptionAtRestWithCustomerKey`        |
| `identity_type`    | string | `= !=` | Managed identity type          | `SystemAssigned`                         |

### Key Information (parsed from active key URL)

| Field            | Type   | Ops        | Description                              | Example                                                              |
|------------------|--------|------------|------------------------------------------|----------------------------------------------------------------------|
| `active_key_url` | string | `= != ~ ^` | Full Key Vault key URL                   | `https://kv-example.vault.azure.net/keys/my-cmk/abc123`             |
| `key_vault_name` | string | `= != ~ ^` | Key Vault name (parsed from URL)         | `kv-example`                                                        |
| `key_name`       | string | `= != ~ ^` | Key name (parsed from URL)               | `my-cmk`                                                            |
| `key_version`    | string | `= != ~ ^` | Key version (parsed from URL)            | `abc123def456`                                                      |

### Booleans

| Field                       | Type    | Ops    | Description                                    | Notes                                                    |
|-----------------------------|---------|--------|------------------------------------------------|----------------------------------------------------------|
| `auto_key_rotation_enabled` | boolean | `= !=` | Whether automatic key version rotation enabled | Maps to rotationToLatestKeyVersionEnabled. Default false. |

### RecordData

| Field    | Type       | Ops | Description                                    |
|----------|------------|-----|------------------------------------------------|
| `record` | RecordData | `=` | Full Disk Encryption Set object as RecordData  |

---

## Operators Legend

| Symbol | Operation          |
|--------|--------------------|
| `=`    | Equals             |
| `!=`   | NotEqual           |
| `~`    | Contains           |
| `^`    | StartsWith         |

---

## CLI Command

```bash
az disk-encryption-set show \
    --name <des-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to diskEncryptionSets** - stderr contains `(AuthorizationFailed)` and the scope path includes `/diskEncryptionSets/`

Any other non-zero exit code raises a `CollectionFailed` error.

---

## Environment Variables

| Variable                | Required | Description                                                |
|-------------------------|----------|------------------------------------------------------------|
| `AZURE_SUBSCRIPTION_ID` | No      | Default subscription if not set in OBJECT                  |
| `AZURE_TENANT_ID`       | No      | Tenant context for authentication                          |
| `AZURE_CLIENT_ID`       | No      | Service principal client ID (non-interactive auth)         |
| `AZURE_CLIENT_SECRET`   | No      | Service principal client secret (non-interactive auth)     |
| `AZURE_AUTHORITY_HOST`  | No      | Authority host (sovereign clouds)                          |
| `AZURE_CLOUD_NAME`      | No      | Cloud environment name (AzureCloud, AzureUSGovernment)     |
| `HTTPS_PROXY`           | No      | HTTPS proxy for CLI traffic                                |

---

## Example ESP Policies

### CMK with Auto Rotation Enforcement

```
META
    esp_id `az-des-cmk-rotation-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `SC:DES-001`
    title `Azure DES CMK with auto key rotation`
    description `Ensures DES uses CMK with SystemAssigned identity and auto rotation`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT des_prod
        name `des-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_cmk
        found boolean = true
        encryption_type string = `EncryptionAtRestWithCustomerKey`
        identity_type string = `SystemAssigned`
        auto_key_rotation_enabled boolean = true
    STATE_END

    CRI AND
        CTN az_disk_encryption_set
            TEST all all AND
            STATE_REF st_cmk
            OBJECT_REF des_prod
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-des-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `SC:DES-002`
    title `Azure DES not-found path validation`
    description `Validates that non-existent DES returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT des_missing
        name `des-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_disk_encryption_set
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF des_missing
        CTN_END
    CRI_END
DEF_END
```

---

## Source Files

| File | Description |
|------|-------------|
| `az_disk_encryption_set_collector.rs` | Data collector - queries `az disk-encryption-set show` |
| `az_disk_encryption_set_contract.rs`  | CTN contract - field specs, mappings, strategy         |
| `az_disk_encryption_set_executor.rs`  | Executor - validates collected data against state      |

---

## Field Count Summary

| Category   | Count |
|------------|-------|
| Strings    | 12    |
| Booleans   | 2     |
| Integers   | 0     |
| RecordData | 1     |
| **Total**  | **15**|
