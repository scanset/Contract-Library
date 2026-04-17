# az_auto_provisioning CTN

## Overview

Validates Azure Security Center auto-provisioning setting via `az security auto-provisioning-setting show`.

**CLI command:** `az security auto-provisioning-setting show --name <name> [--subscription <id>] --output json`

**Scope:** Subscription-level (no resource group required)

---

## OBJECT Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Setting name (only 'default' is valid) |
| `subscription` | string | No | Subscription ID override |

---

## STATE Fields

### String Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `name` | = != | Setting name | `default` |
| `id` | = != contains startswith | Full ARM resource ID | `/subscriptions/.../autoProvisioningSettings/default` |
| `type` | = != | ARM resource type | `Microsoft.Security/autoProvisioningSettings` |
| `auto_provision` | = != | Auto-provisioning state | `On` or `Off` |

### Boolean Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `found` | = != | Whether the setting was found | `true` |
| `is_enabled` | = != | Whether auto-provisioning is On | `true` |

### RecordData

| Field | Ops | Description |
|-------|-----|-------------|
| `record` | = | Full setting object as RecordData |

---

## NotFound Handling

- `(Setting name error)` with exit code 3 -- invalid setting name
- Only `default` is a valid setting name

---

## Example ESP Policy

```esp
OBJECT autoprov_default
    name `default`
OBJECT_END

STATE st_autoprov_on
    found boolean = true
    auto_provision string = `On`
    is_enabled boolean = true
STATE_END

CRI AND
    CTN az_auto_provisioning
        TEST all all AND
        STATE_REF st_autoprov_on
        OBJECT_REF autoprov_default
    CTN_END
CRI_END
```

---

## Notes

- Only `default` is a valid auto-provisioning setting name
- CIS Azure 2.1.15: Ensure auto-provisioning of monitoring agent is set to On
- `auto_provision` values: `On` or `Off`
- `is_enabled` is a convenience boolean derived from `auto_provision == "On"`
- Controls whether the Log Analytics agent is auto-deployed to VMs
