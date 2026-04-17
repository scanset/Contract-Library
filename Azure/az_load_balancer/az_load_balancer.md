# az_load_balancer CTN Contract

**CTN Type:** `az_load_balancer`
**Platform:** Azure
**Category:** Network (Control-Plane)
**CLI Command:** `az network lb show`

---

## Overview

The `az_load_balancer` CTN collects and validates Azure Load Balancer resources.
It queries a single load balancer by name and resource group, returning scalar
fields for SKU, frontend/backend/rule/probe/NAT counts, public frontend
detection, and the full JSON response as RecordData.

---

## Object Requirements

| Field            | Type   | Required | Description                              |
|------------------|--------|----------|------------------------------------------|
| `name`           | string | Yes      | Load balancer name                       |
| `resource_group` | string | Yes      | Resource group owning the load balancer  |
| `subscription`   | string | No       | Subscription ID override                 |

### Example OBJECT Block

```
OBJECT lb_prod
    name `lb-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END
```

---

## State Fields

### Existence

| Field   | Type    | Ops    | Description                          |
|---------|---------|--------|--------------------------------------|
| `found` | boolean | `= !=` | Whether the load balancer was found  |

### Identity and Location

| Field               | Type   | Ops        | Description              | Example                                       |
|---------------------|--------|------------|--------------------------|------------------------------------------------|
| `name`              | string | `= != ~ ^` | Load balancer name       | `lb-example-prod`                              |
| `id`                | string | `= != ~ ^` | Full ARM resource ID     | `/subscriptions/00000000-.../loadBalancers/lb-example-prod` |
| `type`              | string | `= !=`     | ARM resource type        | `Microsoft.Network/loadBalancers`              |
| `location`          | string | `= !=`     | Azure region             | `eastus`                                       |
| `resource_group`    | string | `= != ~ ^` | Resource group name      | `rg-example-eastus`                            |
| `provisioning_state`| string | `= !=`     | Provisioning state       | `Succeeded`                                    |

### SKU

| Field      | Type   | Ops    | Description                                  | Example    |
|------------|--------|--------|----------------------------------------------|------------|
| `sku_name` | string | `= !=` | SKU name (Basic, Standard, or Gateway)       | `Standard` |
| `sku_tier` | string | `= !=` | SKU tier (Regional or Global)                | `Regional` |

### Derived Booleans

| Field                | Type    | Ops    | Description                                  | Notes                                                  |
|----------------------|---------|--------|----------------------------------------------|--------------------------------------------------------|
| `has_public_frontend`| boolean | `= !=` | Whether any frontend has a public IP attached| True when any frontendIPConfigurations has publicIPAddress |

### Counts

| Field                       | Type | Ops              | Description                        | Notes                              |
|-----------------------------|------|------------------|------------------------------------|------------------------------------|
| `frontend_ip_count`         | int  | `= != > >= < <=` | Frontend IP configurations         |                                    |
| `backend_pool_count`        | int  | `= != > >= < <=` | Backend address pools              |                                    |
| `load_balancing_rule_count` | int  | `= != > >= < <=` | Load balancing rules               |                                    |
| `probe_count`               | int  | `= != > >= < <=` | Health probes                      |                                    |
| `inbound_nat_rule_count`    | int  | `= != > >= < <=` | Inbound NAT rules                  |                                    |
| `outbound_rule_count`       | int  | `= != > >= < <=` | Outbound rules                     |                                    |
| `inbound_nat_pool_count`    | int  | `= != > >= < <=` | Inbound NAT pools                  | Legacy VMSS feature. Typically 0.  |

### RecordData

| Field    | Type       | Ops | Description                              |
|----------|------------|-----|------------------------------------------|
| `record` | RecordData | `=` | Full Load Balancer object as RecordData  |

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
az network lb show \
    --name <lb-name> \
    --resource-group <resource-group> \
    [--subscription <subscription-id>] \
    --output json
```

---

## NotFound Detection

The collector returns `found = false` when either:

1. **ResourceNotFound** - stderr contains `(ResourceNotFound)` or `Code: ResourceNotFound`
2. **AuthorizationFailed scoped to loadBalancers** - stderr contains `(AuthorizationFailed)` and the scope path includes `/loadBalancers/`

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
    esp_id `az-lb-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `NET:LB-001`
    title `Azure Load Balancer baseline validation`
    description `Validates LB SKU, frontend, rules, and probes`
    author `security-team`
    assessment_method `AUTOMATED`
    implementation_status `implemented`
META_END

DEF
    OBJECT lb_prod
        name `lb-example-prod`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        sku_name string = `Standard`
        sku_tier string = `Regional`
        has_public_frontend boolean = true
        frontend_ip_count int = 1
        backend_pool_count int >= 1
        load_balancing_rule_count int >= 1
        probe_count int >= 1
    STATE_END

    CRI AND
        CTN az_load_balancer
            TEST all all AND
            STATE_REF st_baseline
            OBJECT_REF lb_prod
        CTN_END
    CRI_END
DEF_END
```

### Not-Found Detection

```
META
    esp_id `az-lb-notfound-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `low`
    control_mapping `NET:LB-002`
    title `Azure Load Balancer not-found path validation`
    description `Validates that non-existent LB returns found=false`
    author `security-team`
    assessment_method `TEST`
    implementation_status `implemented`
META_END

DEF
    OBJECT lb_missing
        name `lb-does-not-exist-xyz-99`
        resource_group `rg-example-eastus`
    OBJECT_END

    STATE st_absent
        found boolean = false
    STATE_END

    CRI AND
        CTN az_load_balancer
            TEST all all AND
            STATE_REF st_absent
            OBJECT_REF lb_missing
        CTN_END
    CRI_END
DEF_END
```

---

## SKU Comparison

| Feature                    | Basic SKU  | Standard SKU | Gateway SKU |
|----------------------------|------------|--------------|-------------|
| Backend pool size          | Up to 300  | Up to 1000   | Up to 100   |
| Health probes              | TCP, HTTP  | TCP, HTTP, HTTPS | All    |
| Zone redundancy            | No         | Yes          | No          |
| HA Ports                   | No         | Yes          | Yes         |
| Outbound rules             | No         | Yes          | No          |
| Multiple frontends         | No         | Yes          | Yes         |
| SLA                        | N/A        | 99.99%       | 99.99%      |

---

## Source Files

| File | Description |
|------|-------------|
| `az_load_balancer_collector.rs` | Data collector - queries `az network lb show`     |
| `az_load_balancer_contract.rs`  | CTN contract - field specs, mappings, strategy    |
| `az_load_balancer_executor.rs`  | Executor - validates collected data against state |

---

## Field Count Summary

| Category   | Count |
|------------|-------|
| Strings    | 8     |
| Booleans   | 2     |
| Integers   | 7     |
| RecordData | 1     |
| **Total**  | **18**|
