# az_public_ip CTN Contract

**CTN Type:** `az_public_ip`
**Platform:** Azure
**Category:** Network (Control-Plane)
**CLI Command:** `az network public-ip show`

---

## Overview

The `az_public_ip` CTN collects and validates Azure Public IP Address resources.
It queries a single public IP by name and resource group, returning scalar
fields for allocation method, IP version, SKU, DDoS protection mode, idle
timeout, zone redundancy, association status, DNS settings, and the full JSON
response as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                          |
|------------------|--------|----------|--------------------------------------|
| `name`           | string | Yes      | Public IP resource name              |
| `resource_group` | string | Yes      | Resource group owning the public IP  |
| `subscription`   | string | No       | Subscription ID override             |

### Example OBJECT Block

```
OBJECT pip_prod
    name `pip-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops      | Description                      |
|---------|---------|----------|----------------------------------|
| `found` | boolean | `= !=`   | Whether the public IP was found  |

### Identity and Location

| Field               | Type   | Ops        | Description              | Example                                                  |
|---------------------|--------|------------|--------------------------|----------------------------------------------------------|
| `name`              | string | `= != ~ ^` | Public IP resource name  | `pip-example-prod`                                       |
| `id`                | string | `= != ~ ^` | Full ARM resource ID     | `/subscriptions/00000000-.../publicIPAddresses/pip-example-prod` |
| `type`              | string | `= !=`     | ARM resource type        | `Microsoft.Network/publicIPAddresses`                    |
| `location`          | string | `= !=`     | Azure region             | `eastus`                                                 |
| `resource_group`    | string | `= != ~ ^` | Resource group name      | `rg-example-eastus`                                      |
| `provisioning_state`| string | `= !=`     | Provisioning state       | `Succeeded`                                              |

### IP Configuration

| Field               | Type   | Ops        | Description                             | Example    |
|---------------------|--------|------------|-----------------------------------------|------------|
| `ip_address`        | string | `= != ~ ^` | Assigned IP address                     | `10.0.0.1` |
| `allocation_method` | string | `= !=`     | Allocation method (Static or Dynamic)   | `Static`   |
| `ip_version`        | string | `= !=`     | IP version (IPv4 or IPv6)               | `IPv4`     |

### SKU

| Field      | Type   | Ops    | Description                          | Example    |
|------------|--------|--------|--------------------------------------|------------|
| `sku_name` | string | `= !=` | SKU name (Basic or Standard)         | `Standard` |
| `sku_tier` | string | `= !=` | SKU tier (Regional or Global)        | `Regional` |

### Security

| Field                 | Type   | Ops    | Description           | Example                      |
|-----------------------|--------|--------|-----------------------|------------------------------|
| `ddos_protection_mode`| string | `= !=` | DDoS protection mode  | `VirtualNetworkInherited`    |

### DNS Settings

| Field              | Type   | Ops        | Description                    | Example                                  |
|--------------------|--------|------------|--------------------------------|------------------------------------------|
| `dns_fqdn`         | string | `= != ~ ^` | DNS fully qualified domain name| `example.eastus.cloudapp.azure.com`      |
| `dns_domain_label`  | string | `= != ~ ^` | DNS domain name label          | `example`                                |

### Derived Booleans

| Field            | Type    | Ops    | Description                                    | Notes                                          |
|------------------|---------|--------|------------------------------------------------|-------------------------------------------------|
| `zone_redundant` | boolean | `= !=` | Deployed across multiple availability zones    | Derived: true when zones array length > 1       |
| `is_associated`  | boolean | `= !=` | Attached to a resource (LB, AppGW, VM, etc.)  | True when ipConfiguration or natGateway present |

### Integers

| Field                  | Type | Ops              | Description                  | Notes                     |
|------------------------|------|------------------|------------------------------|---------------------------|
| `idle_timeout_minutes` | int  | `= != > >= < <=` | Idle timeout in minutes      | Default 4. Range 4-30.    |
| `zone_count`           | int  | `= != > >= < <=` | Number of availability zones | 0 when no zones assigned  |

### RecordData

| Field    | Type       | Ops | Description                            |
|----------|------------|-----|----------------------------------------|
| `record` | RecordData | `=` | Full Public IP object as RecordData    |

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
az network public-ip show \
    --name <pip-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to publicIPAddresses** - stderr contains `(AuthorizationFailed)` and the scope path includes `/publicIPAddresses/`

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
    esp_id `az-public-ip-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:PUBIP-001`
    title `Azure Public IP baseline validation`
    description `Validates public IP SKU, allocation, zones, and association`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT pip_prod
        name `pip-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        location string = `eastus`
        allocation_method string = `Static`
        ip_version string = `IPv4`
        sku_name string = `Standard`
        sku_tier string = `Regional`
        ddos_protection_mode string = `VirtualNetworkInherited`
        idle_timeout_minutes int = 4
        zone_count int = 3
        zone_redundant boolean = true
        is_associated boolean = true
    STATE_END

    CRI AND
        CTN az_public_ip
            TEST all all AND
            STATE_REF st_baseline
            OBJECT_REF pip_prod
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-public-ip-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `NET:PUBIP-002`
    title `Azure Public IP not-found path validation`
    description `Validates that non-existent public IP returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT pip_missing
        name `pip-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_public_ip
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF pip_missing
        CTN_END
    CRI_END
DEF_END
```

### Standard SKU Enforcement

```
META
    esp_id `az-public-ip-standard-sku-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:PUBIP-003`
    title `Azure Public IP Standard SKU enforcement`
    description `Ensures public IP uses Standard SKU with static allocation`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT pip_target
        name `pip-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_standard
        found boolean = true
        sku_name string = `Standard`
        allocation_method string = `Static`
        zone_redundant boolean = true
    STATE_END

    CRI AND
        CTN az_public_ip
            TEST all all AND
            STATE_REF st_standard
            OBJECT_REF pip_target
        CTN_END
    CRI_END
DEF_END
```

---

## SKU Comparison

| Feature                  | Basic SKU        | Standard SKU     |
|--------------------------|------------------|------------------|
| Allocation methods       | Static, Dynamic  | Static only      |
| Zone redundancy          | No               | Yes              |
| Availability zones       | Not supported    | Supported        |
| Global tier              | No               | Yes              |
| Routing preference       | No               | Yes              |
| Standard Load Balancer   | No               | Yes (required)   |

---

## Source Files

| File | Description |
|------|-------------|
| `az_public_ip_collector.rs` | Data collector - queries `az network public-ip show` |
| `az_public_ip_contract.rs`  | CTN contract - field specs, mappings, strategy       |
| `az_public_ip_executor.rs`  | Executor - validates collected data against state    |

---

## Field Count Summary

| Category   | Count |
|------------|-------|
| Strings    | 14    |
| Booleans   | 3     |
| Integers   | 2     |
| RecordData | 1     |
| **Total**  | **20**|
