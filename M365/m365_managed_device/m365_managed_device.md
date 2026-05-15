# m365_managed_device

## Overview

Resource-shape reference for an Intune-managed device discovered via `m365_graph_query` against `/deviceManagement/managedDevices`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

Distinct from [`m365_device`](../m365_device/m365_device.md): the `/devices` endpoint returns the Entra-side device record (trustType, isCompliant flag); `/deviceManagement/managedDevices` returns the **Intune-side** record, which carries compliance state, OS detail, hardware inventory, last sync time, and the enrolled user. Cross-system join key is `azureADDeviceId` ↔ `m365_device.metadata.device_id`.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::ManagedDevice`
**Required permission:** `DeviceManagementManagedDevices.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                              | Example                                                                              |
| -------- | ------ | -------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `deviceManagement/managedDevices`.               | `deviceManagement/managedDevices`                                                    |
| `select` | string | No       | Reduce payload — use the field list below.               | `id,deviceName,operatingSystem,complianceState,managementAgent,userPrincipalName`    |
| `filter` | string | No       | OData `$filter`. Common: `complianceState eq 'noncompliant'`. | `complianceState eq 'noncompliant'`                                              |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row, corporate Windows device):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "deviceName": "DESKTOP-CORP-01",
  "operatingSystem": "Windows",
  "osVersion": "10.0.22631.3007",
  "complianceState": "compliant",
  "managementAgent": "mdm",
  "userPrincipalName": "alice@contoso.com",
  "userId": "22222222-2222-2222-2222-222222222222",
  "enrolledDateTime": "2025-08-15T14:00:00Z",
  "lastSyncDateTime": "2026-05-08T08:00:00Z",
  "serialNumber": "PF3XYZ123",
  "model": "ThinkPad X1 Carbon",
  "manufacturer": "Lenovo",
  "isEncrypted": true,
  "azureADDeviceId": "55555555-5555-5555-5555-555555555555",
  "joinType": "azureADJoined"
}
```

---

## Collected Data Fields

Inside `rows.*`:

| Field                                | Type    | Description                                                                              |
| ------------------------------------ | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                          | string  | Intune managed device id (primary key, not the same as Entra `id` or `deviceId`).        |
| `rows.*.deviceName`                  | string  | Hostname.                                                                                |
| `rows.*.operatingSystem`             | string  | `Windows`, `iOS`, `Android`, `macOS`, `Linux`.                                           |
| `rows.*.osVersion`                   | string  | OS build string.                                                                         |
| `rows.*.complianceState`             | string  | `compliant`, `noncompliant`, `conflict`, `error`, `inGracePeriod`, `configManager`, `unknown`. |
| `rows.*.managementAgent`             | string  | `mdm`, `eas`, `easMdm`, `intuneClient`, `easIntuneClient`, `configurationManagerClient`, etc. |
| `rows.*.userPrincipalName`           | string  | Primary user UPN.                                                                        |
| `rows.*.userId`                      | string  | Primary user Entra id.                                                                   |
| `rows.*.enrolledDateTime`            | string  | ISO-8601; first Intune enrollment.                                                       |
| `rows.*.lastSyncDateTime`            | string  | ISO-8601; last check-in. Stale = drifted device.                                         |
| `rows.*.serialNumber`                | string  | Hardware serial.                                                                         |
| `rows.*.model`, `manufacturer`       | string  | Hardware identifiers.                                                                    |
| `rows.*.isEncrypted`                 | boolean | Disk encryption status (BitLocker / FileVault / etc).                                    |
| `rows.*.azureADDeviceId`             | string  | Join key with `m365_device` (Entra side).                                                |
| `rows.*.azureADRegistered`           | boolean | Whether the device is registered with Entra. (v1.0 — `joinType` is beta only.)           |
| `rows.*.deviceEnrollmentType`        | string  | Enrollment flavor: `windowsAutoEnrollment`, `userEnrollment`, `azureDomainJoined`, `deviceEnrollmentManager`, etc. |
| `rows.*.managedDeviceOwnerType`      | string  | `company`, `personal`, or `unknown` — ownership classification.                          |

---


## ESP Examples

### Every managed device must be compliant

```esp
OBJECT all_managed
    path `deviceManagement/managedDevices`
    select `id,deviceName,complianceState`
OBJECT_END

STATE all_compliant
    found boolean = true
    record
        field rows.*.complianceState string = `compliant`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_compliant
    OBJECT_REF all_managed
CTN_END
```

### Every Windows device must have disk encryption on

```esp
OBJECT windows_devices
    path `deviceManagement/managedDevices`
    filter `operatingSystem eq 'Windows'`
    select `id,deviceName,isEncrypted`
OBJECT_END

STATE all_encrypted
    found boolean = true
    record
        field rows.*.isEncrypted boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_encrypted
    OBJECT_REF windows_devices
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Entra-side counterpart: [`m365_device`](../m365_device/m365_device.md) — join on `azureADDeviceId` ↔ `metadata.device_id`
- Intune sibling: [`m365_compliance_policy`](../m365_compliance_policy/m365_compliance_policy.md) — the policies governing `complianceState`
