# m365_device

## Overview

Resource-shape reference for an Entra ID device discovered via `m365_graph_query` against `/devices`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections. Covers Entra-joined (Azure AD joined), Hybrid-joined (Server AD + Entra), and Entra-registered (workplace / BYOD) devices.

**Critical distinction:** the `trustType` field separates corporate-managed from user-owned. **Entra-joined (`AzureAd`) devices have full management capability; registered (`Workplace`) devices are user-owned and typically have a much narrower compliance posture**. Most access-control assertions need to gate on this.

For Intune MDM-managed device detail (compliance state per policy, configuration profiles, encryption status, hardware inventory), use a separate `m365_graph_query` against `/deviceManagement/managedDevices` — that's a **richer record** and a Phase 3 asset type, not covered here.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::Device`

---

## Object Fields

For policies, use the standard `m365_graph_query` object fields with `path = /devices`:

| Field    | Type   | Required | Description                                                                  | Example                                                       |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `path`   | string | **Yes**  | Must be `/devices` (or `devices`) to land on this resource shape.            | `/devices`                                                    |
| `select` | string | No       | Reduce response payload. Use the schema fields below.                        | `id,displayName,trustType,operatingSystem,isCompliant`        |
| `filter` | string | No       | OData `$filter`. Common: `accountEnabled eq true`, `trustType eq 'AzureAd'`. | `trustType eq 'AzureAd'`                                      |

---

## Commands Executed

### Command 1: GET https://graph.microsoft.com/v1.0/devices

```
GET https://graph.microsoft.com/v1.0/devices?$select=id,deviceId,displayName,operatingSystem,trustType,isCompliant,isManaged&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row, corporate Entra-joined):**

```json
{
  "id": "44444444-4444-4444-4444-444444444444",
  "deviceId": "55555555-5555-5555-5555-555555555555",
  "displayName": "DESKTOP-CORP-01",
  "operatingSystem": "Windows",
  "operatingSystemVersion": "10.0.22631.3007",
  "trustType": "AzureAd",
  "accountEnabled": true,
  "isCompliant": true,
  "isManaged": true,
  "registrationDateTime": "2025-08-15T14:00:00Z",
  "approximateLastSignInDateTime": "2026-05-08T09:23:45Z"
}
```

**Sample response (single row, BYOD registered):**

```json
{
  "id": "66666666-6666-6666-6666-666666666666",
  "deviceId": "77777777-7777-7777-7777-777777777777",
  "displayName": "iPhone-15-Pro",
  "operatingSystem": "iOS",
  "operatingSystemVersion": "17.4.1",
  "trustType": "Workplace",
  "accountEnabled": true,
  "isCompliant": null,
  "isManaged": false,
  "registrationDateTime": "2026-01-20T10:00:00Z",
  "approximateLastSignInDateTime": "2026-05-08T07:11:22Z"
}
```

---

## Collected Data Fields

Returned via the parent `m365_graph_query` CTN. Inside `rows.*` you'll find:

| Field                                          | Type    | Always Present | Description                                                                              |
| ---------------------------------------------- | ------- | -------------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                    | string  | Yes            | Graph object id (UUID). The asset's primary key.                                         |
| `rows.*.deviceId`                              | string  | Yes            | Azure AD device GUID surfaced in claims. Use this for joins with sign-in logs / Intune.  |
| `rows.*.displayName`                           | string  | Yes            | Device name (hostname for Windows, model for mobile).                                    |
| `rows.*.operatingSystem`                       | string  | Yes            | `Windows`, `macOS`, `iOS`, `Android`, `Linux`.                                           |
| `rows.*.operatingSystemVersion`                | string  | Yes            | OS version string.                                                                       |
| `rows.*.trustType`                             | string  | Yes            | **`AzureAd`** = Entra-joined (corp). **`ServerAd`** = hybrid. **`Workplace`** = registered. |
| `rows.*.accountEnabled`                        | boolean | Yes            | Whether the device record is active.                                                     |
| `rows.*.isCompliant`                           | boolean | No             | From Intune; null if not Intune-managed.                                                 |
| `rows.*.isManaged`                             | boolean | Yes            | Has an MDM (typically Intune) enrolled.                                                  |
| `rows.*.registrationDateTime`                  | string  | Yes            | ISO-8601; when the device first registered.                                              |
| `rows.*.approximateLastSignInDateTime`         | string  | No             | ISO-8601; last user sign-in from this device.                                            |
| `rows.*.extensionAttributes`                   | object  | Yes (may be all-null) | Nested object with 15 named slots `extensionAttribute1` .. `extensionAttribute15`. Tenant-defined free-form strings; commonly used as the gating field for CA device-filter policies (e.g. `extensionAttribute1 = "FCI-handler"`). |

---


## ESP Examples

### Every Entra-joined device must be compliant

```esp
OBJECT entra_joined
    path `/devices`
    filter `trustType eq 'AzureAd' and accountEnabled eq true`
    select `id,displayName,trustType,isCompliant`
OBJECT_END

STATE all_compliant
    found boolean = true
    record
        field rows.*.isCompliant boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_compliant
    OBJECT_REF entra_joined
CTN_END
```

### Registered (BYOD) devices must run a supported OS version

```esp
OBJECT byod_devices
    path `/devices`
    filter `trustType eq 'Workplace'`
    select `id,displayName,operatingSystem,operatingSystemVersion`
OBJECT_END

STATE no_unsupported_os
    found boolean = true
    record
        field rows.*.operatingSystem string = `Windows` or
        field rows.*.operatingSystem string = `macOS` or
        field rows.*.operatingSystem string = `iOS` or
        field rows.*.operatingSystem string = `Android`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_unsupported_os
    OBJECT_REF byod_devices
CTN_END
```

### Every corporate device should be Intune-managed

```esp
OBJECT entra_joined_devices
    path `/devices`
    filter `trustType eq 'AzureAd'`
    select `id,displayName,isManaged`
OBJECT_END

STATE all_managed
    found boolean = true
    record
        field rows.*.isManaged boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_managed
    OBJECT_REF entra_joined_devices
CTN_END
```

---

## Required Permission

Microsoft Graph application permission **`Device.Read.All`** on the app registration, with admin consent granted.

For the richer Intune-managed device record, also grant **`DeviceManagementManagedDevices.Read.All`** and query `/deviceManagement/managedDevices`.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Other M365 resources: [`m365_user`](../m365_user/m365_user.md), [`m365_group`](../m365_group/m365_group.md)
- Future: `M365::ManagedDevice` (Phase 3) — Intune detail via `/deviceManagement/managedDevices`
