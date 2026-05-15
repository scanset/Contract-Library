# m365_app_protection_policy

## Overview

Resource-shape reference for an Intune App Protection Policy (MAM — Mobile Application Management) discovered via `m365_graph_query` against either `/deviceAppManagement/iosManagedAppProtections` or `/deviceAppManagement/androidManagedAppProtections`. **Not a standalone CTN.**

App Protection Policies enforce data-protection rules at the *application* level — encryption, copy-paste restrictions, sharing, PIN requirements — independent of whether the device is enrolled in Intune MDM. Critical for BYOD postures where the device isn't owned but the app handles corporate data. `MP-7` (media use) and `SC-7` (boundary protection) controls typically map here.

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::AppProtectionPolicy`
**Required permission:** `DeviceManagementApps.Read.All` (application, admin consent)

The discoverer pulls iOS and Android variants as **two separate paths** producing the same asset type — `metadata.platform` carries `iOS` or `Android` so policies can filter.

---

## Object Fields

| Field    | Type   | Required | Description                                                                          | Example                                                            |
| -------- | ------ | -------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Either `deviceAppManagement/iosManagedAppProtections` or `deviceAppManagement/androidManagedAppProtections`. | `deviceAppManagement/iosManagedAppProtections`              |
| `select` | string | No       | Many subtype-specific fields — typically take the full object.                       | (none)                                                             |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (iOS, abbreviated):**

```json
{
  "@odata.type": "#microsoft.graph.iosManagedAppProtection",
  "id": "T_11111111-...",
  "displayName": "iOS MAM — FCI handlers",
  "description": "Restrict data movement for FCI-handling apps on personal iOS",
  "createdDateTime": "2024-09-15T10:00:00Z",
  "lastModifiedDateTime": "2026-04-22T09:15:00Z",
  "appDataEncryptionType": "whenDeviceLocked",
  "minimumPinLength": 6,
  "pinRequired": true,
  "saveAsBlocked": true,
  "allowedOutboundDataTransferDestinations": "managedApps",
  "allowedInboundDataTransferSources": "managedApps"
}
```

---

## Collected Data Fields

| Field                                | Type    | Description                                                              |
| ------------------------------------ | ------- | ------------------------------------------------------------------------ |
| `rows.*.id`                          | string  | Policy id (note: iOS uses `T_` / Android uses `A_` prefix).              |
| `rows.*.@odata.type`                 | string  | `#microsoft.graph.iosManagedAppProtection` or `#microsoft.graph.androidManagedAppProtection`. |
| `rows.*.displayName`                 | string  | Policy name.                                                             |
| `rows.*.description`                 | string  | Description.                                                             |
| `rows.*.createdDateTime`             | string  | ISO-8601.                                                                |
| `rows.*.lastModifiedDateTime`        | string  | ISO-8601.                                                                |
| *(subtype-specific fields)*          | mixed   | `appDataEncryptionType`, `pinRequired`, `saveAsBlocked`, `allowedOutboundDataTransferDestinations`, etc. |

---


## ESP Example

```esp
OBJECT ios_mam
    path `deviceAppManagement/iosManagedAppProtections`
OBJECT_END

STATE strong_pin_enforced
    found boolean = true
    record
        field rows.*.pinRequired boolean = `true`
        field rows.*.minimumPinLength int >= `6`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF strong_pin_enforced
    OBJECT_REF ios_mam
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Intune MDM sibling: [`m365_compliance_policy`](../m365_compliance_policy/m365_compliance_policy.md), [`m365_device_configuration`](../m365_device_configuration/m365_device_configuration.md)
