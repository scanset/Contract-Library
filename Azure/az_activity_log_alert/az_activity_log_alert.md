# az_activity_log_alert CTN

## Overview

Validates Azure Activity Log Alert rules via `az monitor activity-log alert show`.

**CLI command:** `az monitor activity-log alert show --name <name> --resource-group <rg> [--subscription <id>] --output json`

---

## OBJECT Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Activity log alert rule name |
| `resource_group` | string | Yes | Resource group that owns the alert |
| `subscription` | string | No | Subscription ID override |

---

## STATE Fields

### String Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `name` | = != contains startswith | Alert rule name | `alert-policy-assignment-write` |
| `id` | = != contains startswith | Full ARM resource ID | `/subscriptions/.../activityLogAlerts/alert-example` |
| `type` | = != | ARM resource type | `Microsoft.Insights/ActivityLogAlerts` |
| `location` | = != | Azure region | `Global` |
| `description` | = != contains startswith | Alert description | `Alert on policy assignment changes` |
| `resource_group` | = != contains startswith | Resource group | `rg-example-eastus` |
| `operation_name` | = != contains startswith | Monitored operation (extracted from conditions) | `Microsoft.Authorization/policyAssignments/write` |
| `category` | = != | Activity log category (extracted from conditions) | `Administrative` |

### Boolean Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `found` | = != | Whether the alert rule was found | `true` |
| `enabled` | = != | Whether the alert rule is enabled | `true` |
| `has_action_groups` | = != | Whether action groups are configured | `true` |

### Integer Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `scope_count` | = != > >= < <= | Number of scopes monitored | `1` |
| `condition_count` | = != > >= < <= | Number of conditions in allOf | `2` |
| `action_group_count` | = != > >= < <= | Number of action groups attached | `1` |

### RecordData

| Field | Ops | Description |
|-------|-----|-------------|
| `record` | = | Full alert object as RecordData (use record_checks for condition/action details) |

---

## NotFound Handling

- `(ResourceNotFound)` with exit code 3 -- standard ARM pattern
- `(AuthorizationFailed)` scoped to activityLogAlerts -- treated as not found

---

## CIS Azure Benchmark Mappings

| CIS Control | Operation Name | Description |
|-------------|----------------|-------------|
| 5.2.1 | `Microsoft.Authorization/policyAssignments/write` | Create/update policy assignment |
| 5.2.2 | `Microsoft.Authorization/policyAssignments/delete` | Delete policy assignment |
| 5.2.3 | `Microsoft.Network/networkSecurityGroups/write` | Create/update NSG |
| 5.2.4 | `Microsoft.Network/networkSecurityGroups/delete` | Delete NSG |
| 5.2.5 | `Microsoft.Security/securitySolutions/write` | Create/update security solution |
| 5.2.6 | `Microsoft.Security/securitySolutions/delete` | Delete security solution |
| 5.2.7 | `Microsoft.Sql/servers/firewallRules/write` | Create/update SQL firewall rule |
| 5.2.8 | `Microsoft.Security/policies/write` | Create/update security policy |
| 5.2.9 | `Microsoft.Network/publicIPAddresses/write` | Create/update public IP |

---

## Example ESP Policy

```esp
OBJECT alert_nsg_write
    name `alert-nsg-write`
    resource_group `rg-example-eastus`
OBJECT_END

STATE st_alert_active
    found boolean = true
    enabled boolean = true
    category string = `Administrative`
    operation_name string = `Microsoft.Network/networkSecurityGroups/write`
    has_action_groups boolean = true
    action_group_count int >= 1
STATE_END

CRI AND
    CTN az_activity_log_alert
        TEST all all AND
        STATE_REF st_alert_active
        OBJECT_REF alert_nsg_write
    CTN_END
CRI_END
```

---

## Notes

- Alert location is always `Global`
- `operation_name` and `category` are extracted from `condition.allOf` for easy assertion
- For complex condition matching (multiple operations, containsAny), use record_checks
- Scopes are typically subscription IDs -- the alert monitors the entire subscription
- Each CIS control requires a separate alert rule with a specific operationName
