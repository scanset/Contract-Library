# az_bastion_host CTN Contract

**CTN Type:** `az_bastion_host`
**Platform:** Azure
**Category:** Network Security (Control-Plane)
**CLI Command:** `az network bastion show`

---

## Overview

The `az_bastion_host` CTN collects and validates Azure Bastion Host resources.
It queries a single bastion host by name and resource group, returning scalar
fields for SKU, scale units, feature flags (file copy, tunneling, IP connect,
shareable link), DNS name, IP configuration count, and the full JSON response
as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                          |
|------------------|--------|----------|--------------------------------------|
| `name`           | string | Yes      | Bastion host name                    |
| `resource_group` | string | Yes      | Resource group owning the bastion    |
| `subscription`   | string | No       | Subscription ID override             |

### Example OBJECT Block

```
OBJECT bas_prod
    name `bas-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops        | Description                        |
|---------|---------|------------|------------------------------------|
| `found` | boolean | `= != `   | Whether the bastion host was found |

### Identity and Location

| Field               | Type   | Ops              | Description              | Example                                                                                  |
|---------------------|--------|------------------|--------------------------|------------------------------------------------------------------------------------------|
| `name`              | string | `= != ~ ^`       | Bastion host name        | `bas-example-prod`                                                                       |
| `id`                | string | `= != ~ ^`       | Full ARM resource ID     | `/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-example/providers/Microsoft.Network/bastionHosts/bas-example-prod` |
| `type`              | string | `= !=`            | ARM resource type        | `Microsoft.Network/bastionHosts`                                                         |
| `location`          | string | `= !=`            | Azure region             | `eastus`                                                                                 |
| `resource_group`    | string | `= != ~ ^`       | Resource group name      | `rg-example-eastus`                                                                      |
| `provisioning_state`| string | `= !=`            | Provisioning state       | `Succeeded`                                                                              |
| `dns_name`          | string | `= != ~ ^`       | Bastion DNS name         | `bst-00000000-0000-0000-0000-000000000000.bastion.azure.com`                             |
| `sku_name`          | string | `= !=`            | SKU (Basic or Standard)  | `Standard`                                                                               |

### Feature Flags

| Field                  | Type    | Ops      | Description                              | Notes                                        |
|------------------------|---------|----------|------------------------------------------|----------------------------------------------|
| `enable_file_copy`     | boolean | `= !=`   | File copy (upload/download) enabled      | Requires Standard SKU. False on Basic.       |
| `enable_ip_connect`    | boolean | `= !=`   | IP-based connect enabled                 | Requires Standard SKU.                       |
| `enable_tunneling`     | boolean | `= !=`   | Native client tunneling enabled          | Requires Standard SKU.                       |
| `enable_shareable_link`| boolean | `= !=`   | Shareable link feature enabled           | Defaults false when absent from response.    |

### Scale and Configuration

| Field                    | Type | Ops              | Description                                  | Notes                                       |
|--------------------------|------|------------------|----------------------------------------------|---------------------------------------------|
| `scale_units`            | int  | `= != > >= < <=` | Scale units (each = 25 concurrent sessions)  | Standard: 2-50. Basic: always 2.            |
| `ip_configuration_count` | int  | `= != > >= < <=` | Number of IP configurations                  |                                             |

### RecordData

| Field    | Type       | Ops | Description                              |
|----------|------------|-----|------------------------------------------|
| `record` | RecordData | `=` | Full Bastion Host object as RecordData   |

---

## Operators Legend

| Symbol | Operation              |
|--------|------------------------|
| `=`    | Equals                 |
| `!=`   | NotEqual               |
| `~`    | Contains               |
| `^`    | StartsWith             |
| `>`    | GreaterThan            |
| `>=`   | GreaterThanOrEqual     |
| `<`    | LessThan               |
| `<=`   | LessThanOrEqual        |

---

## CLI Command

```bash
az network bastion show \
    --name <bastion-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to bastionHosts** - stderr contains `(AuthorizationFailed)` and the scope path includes `/bastionHosts/`

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

### Baseline Validation

```
META
    esp_id `az-bastion-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:BASTION-001`
    title `Azure Bastion baseline validation`
    description `Validates bastion host SKU, features, and provisioning state`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT bas_prod
        name `bas-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        location string = `eastus`
        sku_name string = `Standard`
        scale_units int = 2
        enable_file_copy boolean = true
        enable_ip_connect boolean = true
        enable_tunneling boolean = true
        enable_shareable_link boolean = false
        ip_configuration_count int = 1
    STATE_END

    CRI AND
        CTN az_bastion_host
            TEST all all AND
            STATE_REF st_baseline
            OBJECT_REF bas_prod
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-bastion-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `NET:BASTION-002`
    title `Azure Bastion not-found path validation`
    description `Validates that non-existent bastion returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT bas_missing
        name `bas-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_bastion_host
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF bas_missing
        CTN_END
    CRI_END
DEF_END
```

### Standard SKU Enforcement

```
META
    esp_id `az-bastion-standard-sku-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:BASTION-003`
    title `Azure Bastion Standard SKU enforcement`
    description `Ensures bastion uses Standard SKU with tunneling enabled`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT bas_target
        name `bas-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_standard
        found boolean = true
        sku_name string = `Standard`
        enable_tunneling boolean = true
        scale_units int >= 2
    STATE_END

    CRI AND
        CTN az_bastion_host
            TEST all all AND
            STATE_REF st_standard
            OBJECT_REF bas_target
        CTN_END
    CRI_END
DEF_END
```

---

## SKU Comparison

| Feature              | Basic SKU | Standard SKU |
|----------------------|-----------|--------------|
| File Copy            | No        | Yes          |
| IP Connect           | No        | Yes          |
| Native Tunneling     | No        | Yes          |
| Shareable Link       | No        | Optional     |
| Scale Units          | Fixed (2) | 2-50         |
| Kerberos Auth        | No        | Yes          |

---

## Source Files

| File | Description |
|------|-------------|
| `az_bastion_host_collector.rs` | Data collector - queries `az network bastion show` |
| `az_bastion_host_contract.rs`  | CTN contract - field specs, mappings, strategy     |
| `az_bastion_host_executor.rs`  | Executor - validates collected data against state  |

---

## Field Count Summary

| Category | Count |
|----------|-------|
| Strings  | 8     |
| Booleans | 5     |
| Integers | 2     |
| RecordData | 1   |
| **Total**  | **16** |
