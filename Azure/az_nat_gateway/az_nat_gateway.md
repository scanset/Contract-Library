# az_nat_gateway CTN Contract

**CTN Type:** `az_nat_gateway`
**Platform:** Azure
**Category:** Network (Control-Plane)
**CLI Command:** `az network nat gateway show`

---

## Overview

The `az_nat_gateway` CTN collects and validates Azure NAT Gateway resources.
It queries a single NAT gateway by name and resource group, returning scalar
fields for SKU, idle timeout, public IP count, public IP prefix count, subnet
count, zone redundancy, and the full JSON response as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                            |
|------------------|--------|----------|----------------------------------------|
| `name`           | string | Yes      | NAT gateway name                       |
| `resource_group` | string | Yes      | Resource group owning the NAT gateway  |
| `subscription`   | string | No       | Subscription ID override               |

### Example OBJECT Block

```
OBJECT natgw_prod
    name `natgw-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops    | Description                        |
|---------|---------|--------|------------------------------------|
| `found` | boolean | `= !=` | Whether the NAT gateway was found  |

### Identity and Location

| Field               | Type   | Ops        | Description              | Example                                        |
|---------------------|--------|------------|--------------------------|------------------------------------------------|
| `name`              | string | `= != ~ ^` | NAT gateway name         | `natgw-example-prod`                           |
| `id`                | string | `= != ~ ^` | Full ARM resource ID     | `/subscriptions/00000000-.../natGateways/natgw-example-prod` |
| `type`              | string | `= !=`     | ARM resource type        | `Microsoft.Network/natGateways`                |
| `location`          | string | `= !=`     | Azure region             | `eastus`                                       |
| `resource_group`    | string | `= != ~ ^` | Resource group name      | `rg-example-eastus`                            |
| `provisioning_state`| string | `= !=`     | Provisioning state       | `Succeeded`                                    |
| `sku_name`          | string | `= !=`     | SKU name (always Standard)| `Standard`                                    |

### Derived Booleans

| Field            | Type    | Ops    | Description                                  | Notes                                    |
|------------------|---------|--------|----------------------------------------------|------------------------------------------|
| `zone_redundant` | boolean | `= !=` | Whether the gateway spans multiple zones     | Derived: true when zones array length > 1|

### Counts

| Field                    | Type | Ops              | Description                          | Notes                        |
|--------------------------|------|------------------|--------------------------------------|------------------------------|
| `idle_timeout_minutes`   | int  | `= != > >= < <=` | Idle timeout in minutes              | Default 4. Range 4-120.      |
| `public_ip_count`        | int  | `= != > >= < <=` | Number of attached public IPs        |                              |
| `public_ip_prefix_count` | int  | `= != > >= < <=` | Number of attached public IP prefixes|                              |
| `subnet_count`           | int  | `= != > >= < <=` | Number of associated subnets         |                              |
| `zone_count`             | int  | `= != > >= < <=` | Number of availability zones         |                              |

### RecordData

| Field    | Type       | Ops | Description                            |
|----------|------------|-----|----------------------------------------|
| `record` | RecordData | `=` | Full NAT Gateway object as RecordData  |

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
az network nat gateway show \
    --name <natgw-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to natGateways** - stderr contains `(AuthorizationFailed)` and the scope path includes `/natGateways/`

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
    esp_id `az-natgw-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:NATGW-001`
    title `Azure NAT Gateway baseline validation`
    description `Validates NAT gateway SKU, timeout, and attached resources`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT natgw_prod
        name `natgw-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        sku_name string = `Standard`
        idle_timeout_minutes int = 10
        public_ip_count int >= 1
        subnet_count int >= 1
    STATE_END

    CRI AND
        CTN az_nat_gateway
            TEST all all AND
            STATE_REF st_baseline
            OBJECT_REF natgw_prod
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-natgw-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `NET:NATGW-002`
    title `Azure NAT Gateway not-found path validation`
    description `Validates that non-existent NAT gateway returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT natgw_missing
        name `natgw-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_nat_gateway
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF natgw_missing
        CTN_END
    CRI_END
DEF_END
```

---

## Source Files

| File | Description |
|------|-------------|
| `az_nat_gateway_collector.rs` | Data collector - queries `az network nat gateway show` |
| `az_nat_gateway_contract.rs`  | CTN contract - field specs, mappings, strategy         |
| `az_nat_gateway_executor.rs`  | Executor - validates collected data against state      |

---

## Field Count Summary

| Category   | Count |
|------------|-------|
| Strings    | 7     |
| Booleans   | 2     |
| Integers   | 5     |
| RecordData | 1     |
| **Total**  | **15**|
