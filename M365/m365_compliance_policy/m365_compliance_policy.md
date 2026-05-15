# m365_compliance_policy

## Overview

Resource-shape reference for an Intune device compliance policy discovered via `m365_graph_query` against `/deviceManagement/deviceCompliancePolicies`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

Compliance policies are the rules that drive `complianceState` on each [`m365_managed_device`](../m365_managed_device/m365_managed_device.md). Different platforms get different policy subtypes (`windows10CompliancePolicy`, `macOSCompliancePolicy`, `iosCompliancePolicy`, `androidWorkProfileCompliancePolicy`, etc) — Graph discriminates with the `@odata.type` field.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::CompliancePolicy`
**Required permission:** `DeviceManagementConfiguration.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                            | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `deviceManagement/deviceCompliancePolicies`.                   | `deviceManagement/deviceCompliancePolicies`                        |
| `select` | string | No       | Typically omitted — subtype-specific fields vary widely.               | (none)                                                             |
| `filter` | string | No       | OData `$filter`. Less useful here; typically take the full list.       | (none)                                                             |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single Windows policy, abbreviated):**

```json
{
  "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "Win10/11 Baseline Compliance",
  "description": "FedRAMP Moderate baseline",
  "version": 3,
  "createdDateTime": "2024-08-01T10:00:00Z",
  "lastModifiedDateTime": "2026-03-12T14:30:00Z",
  "passwordRequired": true,
  "passwordMinimumLength": 12,
  "osMinimumVersion": "10.0.19045",
  "bitLockerEnabled": true,
  "secureBootEnabled": true,
  "codeIntegrityEnabled": true,
  "storageRequireEncryption": true
}
```

---

## Collected Data Fields

Inside `rows.*`:

| Field                            | Type    | Description                                                                                |
| -------------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| `rows.*.id`                      | string  | Compliance policy id.                                                                      |
| `rows.*.@odata.type`             | string  | Subtype discriminator — e.g. `#microsoft.graph.windows10CompliancePolicy`.                |
| `rows.*.displayName`             | string  | Policy name.                                                                               |
| `rows.*.description`             | string  | Description.                                                                               |
| `rows.*.version`                 | int     | Monotonic version counter.                                                                 |
| `rows.*.createdDateTime`         | string  | ISO-8601.                                                                                  |
| `rows.*.lastModifiedDateTime`    | string  | ISO-8601.                                                                                  |
| *(subtype-specific fields)*      | mixed   | E.g. `passwordRequired`, `osMinimumVersion`, `bitLockerEnabled` — varies per policy type. |

---


## ESP Examples

### Windows compliance policy must require BitLocker

```esp
OBJECT win_compliance
    path `deviceManagement/deviceCompliancePolicies`
    filter `isof('microsoft.graph.windows10CompliancePolicy')`
OBJECT_END

STATE bitlocker_required
    found boolean = true
    record
        field rows.*.bitLockerEnabled boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF bitlocker_required
    OBJECT_REF win_compliance
CTN_END
```

### A compliance policy must exist for every supported platform

```esp
OBJECT all_compliance
    path `deviceManagement/deviceCompliancePolicies`
OBJECT_END

STATE has_win_policy
    found boolean = true
    record
        field rows.*.@odata.type string = `#microsoft.graph.windows10CompliancePolicy` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_win_policy
    OBJECT_REF all_compliance
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Devices governed by these policies: [`m365_managed_device`](../m365_managed_device/m365_managed_device.md)
- Intune sibling for configuration profiles (non-compliance rules): [`m365_device_configuration`](../m365_device_configuration/m365_device_configuration.md)
