# az_managed_disk CTN Contract

**CTN Type:** `az_managed_disk`
**Platform:** Azure
**Category:** Compute / Storage (Control-Plane)
**CLI Command:** `az disk show`

---

## Overview

The `az_managed_disk` CTN collects and validates Azure Managed Disk resources.
It queries a single disk by name and resource group, returning scalar fields
for SKU, disk size, state, encryption type, disk encryption set presence,
network access policy, OS type, performance tier, IOPS/throughput, zone count,
and the full JSON response as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                        |
|------------------|--------|----------|------------------------------------|
| `name`           | string | Yes      | Managed disk name                  |
| `resource_group` | string | Yes      | Resource group owning the disk     |
| `subscription`   | string | No       | Subscription ID override           |

### Example OBJECT Block

```
OBJECT disk_data
    name `disk-example-data`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops    | Description                       |
|---------|---------|--------|-----------------------------------|
| `found` | boolean | `= !=` | Whether the managed disk was found|

### Identity and Location

| Field               | Type   | Ops        | Description              | Example                                     |
|---------------------|--------|------------|--------------------------|---------------------------------------------|
| `name`              | string | `= != ~ ^` | Managed disk name        | `disk-example-data`                         |
| `id`                | string | `= != ~ ^` | Full ARM resource ID     | `/subscriptions/00000000-.../disks/disk-example-data` |
| `type`              | string | `= !=`     | ARM resource type        | `Microsoft.Compute/disks`                   |
| `location`          | string | `= !=`     | Azure region             | `eastus`                                    |
| `resource_group`    | string | `= != ~ ^` | Resource group name      | `rg-example-eastus`                         |
| `provisioning_state`| string | `= !=`     | Provisioning state       | `Succeeded`                                 |

### Disk Properties

| Field                  | Type   | Ops    | Description                                           | Example                              |
|------------------------|--------|--------|-------------------------------------------------------|--------------------------------------|
| `disk_state`           | string | `= !=` | Disk state (Attached, Unattached, Reserved, etc.)     | `Attached`                           |
| `sku_name`             | string | `= !=` | SKU name (Premium_LRS, Standard_LRS, etc.)            | `Premium_LRS`                        |
| `sku_tier`             | string | `= !=` | SKU tier (Premium, Standard, etc.)                    | `Premium`                            |
| `performance_tier`     | string | `= != ~ ^` | Performance tier (P3, P6, P10, etc.)             | `P6`                                 |
| `create_option`        | string | `= !=` | Creation option (Empty, FromImage, Copy, etc.)        | `Empty`                              |
| `os_type`              | string | `= !=` | OS type - absent on data disks                        | `Linux`                              |
| `hyper_v_generation`   | string | `= !=` | Hyper-V generation - absent on data disks             | `V2`                                 |

### Encryption

| Field                     | Type    | Ops    | Description                                   | Example                                  |
|---------------------------|---------|--------|-----------------------------------------------|------------------------------------------|
| `encryption_type`         | string  | `= !=` | Encryption type                               | `EncryptionAtRestWithCustomerKey`        |
| `has_disk_encryption_set` | boolean | `= !=` | Whether a disk encryption set is configured   | `true`                                   |

### Network Access

| Field                   | Type   | Ops    | Description              | Example      |
|-------------------------|--------|--------|--------------------------|--------------|
| `network_access_policy` | string | `= !=` | Network access policy    | `AllowAll`   |
| `public_network_access` | string | `= !=` | Public network access    | `Enabled`    |

### Derived Booleans

| Field         | Type    | Ops    | Description                          | Notes                                |
|---------------|---------|--------|--------------------------------------|--------------------------------------|
| `is_attached` | boolean | `= !=` | Whether the disk is attached to a VM | Derived: true when managedBy present |

### Integers

| Field                  | Type | Ops              | Description                      |
|------------------------|------|------------------|----------------------------------|
| `disk_size_gb`         | int  | `= != > >= < <=` | Disk size in GB                  |
| `disk_iops_read_write` | int  | `= != > >= < <=` | Provisioned IOPS for read/write  |
| `disk_mbps_read_write` | int  | `= != > >= < <=` | Provisioned throughput in MBps   |
| `zone_count`           | int  | `= != > >= < <=` | Number of availability zones     |

### RecordData

| Field    | Type       | Ops | Description                            |
|----------|------------|-----|----------------------------------------|
| `record` | RecordData | `=` | Full Managed Disk object as RecordData |

---

## Operators Legend

| Symbol | Operation          |
|--------|--------------------|
| `=`    | Equals             |
| `!=`   | NotEqual           |
| `~`    | Contains           |
| `^`    | StartsWith         |
| `>`    | GreaterThan        |
| `>=`   | GreaterThanOrEqual |
| `<`    | LessThan           |
| `<=`   | LessThanOrEqual    |

---

## CLI Command

```bash
az disk show \
    --name <disk-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to disks** - stderr contains `(AuthorizationFailed)` and the scope path includes `/disks/`

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

### CMK Encryption Enforcement

```
META
    esp_id `az-disk-cmk-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `SC:DISK-001`
    title `Azure Managed Disk CMK encryption enforcement`
    description `Ensures disk uses customer-managed key encryption with DES`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT disk_target
        name `disk-example-data`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_cmk
        found boolean = true
        encryption_type string = `EncryptionAtRestWithCustomerKey`
        has_disk_encryption_set boolean = true
    STATE_END

    CRI AND
        CTN az_managed_disk
            TEST all all AND
            STATE_REF st_cmk
            OBJECT_REF disk_target
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-disk-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `SC:DISK-002`
    title `Azure Managed Disk not-found path validation`
    description `Validates that non-existent disk returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT disk_missing
        name `disk-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_managed_disk
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF disk_missing
        CTN_END
    CRI_END
DEF_END
```

---

## Source Files

| File | Description |
|------|-------------|
| `az_managed_disk_collector.rs` | Data collector - queries `az disk show`         |
| `az_managed_disk_contract.rs`  | CTN contract - field specs, mappings, strategy  |
| `az_managed_disk_executor.rs`  | Executor - validates collected data against state|

---

## Field Count Summary

| Category   | Count |
|------------|-------|
| Strings    | 16    |
| Booleans   | 3     |
| Integers   | 4     |
| RecordData | 1     |
| **Total**  | **24**|
