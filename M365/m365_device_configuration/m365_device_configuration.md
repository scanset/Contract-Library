# m365_device_configuration

## Overview

Resource-shape reference for an Intune device configuration profile discovered via `m365_graph_query` against `/deviceManagement/deviceConfigurations`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

Configuration profiles are the **settings** Intune pushes to devices (Wi-Fi, VPN, certificate trust, kiosk mode, etc) — distinct from compliance policies, which are the **rules** evaluated against device state. Many profile subtypes exist; Graph discriminates with `@odata.type`.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::DeviceConfiguration`
**Required permission:** `DeviceManagementConfiguration.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                            | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `deviceManagement/deviceConfigurations`.                       | `deviceManagement/deviceConfigurations`                            |
| `select` | string | No       | Typically omitted — subtype fields vary too widely to project usefully. | (none)                                                             |
| `filter` | string | No       | OData `$filter`. Common: `isof('microsoft.graph.windows10GeneralConfiguration')`. | (see below)                                              |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single profile, abbreviated):**

```json
{
  "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "Win10 — Endpoint Hardening",
  "description": "Disable LM hash, require BitLocker recovery key",
  "version": 5,
  "createdDateTime": "2024-08-01T10:00:00Z",
  "lastModifiedDateTime": "2026-04-22T09:15:00Z",
  "smartScreenEnableInShell": true,
  "lockScreenAllowTimeoutConfiguration": false
}
```

---

## Collected Data Fields

Inside `rows.*`:

| Field                            | Type    | Description                                                                                |
| -------------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| `rows.*.id`                      | string  | Profile id.                                                                                |
| `rows.*.@odata.type`             | string  | Subtype discriminator — e.g. `#microsoft.graph.windows10GeneralConfiguration`.            |
| `rows.*.displayName`             | string  | Profile name.                                                                              |
| `rows.*.description`             | string  | Description.                                                                               |
| `rows.*.version`                 | int     | Monotonic version counter.                                                                 |
| `rows.*.createdDateTime`         | string  | ISO-8601.                                                                                  |
| `rows.*.lastModifiedDateTime`    | string  | ISO-8601.                                                                                  |
| *(subtype-specific fields)*      | mixed   | E.g. `smartScreenEnableInShell`, `wifiProfileType`, `passcodeRequired` — varies.          |

---


## ESP Examples

### Windows profiles must enable SmartScreen

```esp
OBJECT win_configs
    path `deviceManagement/deviceConfigurations`
    filter `isof('microsoft.graph.windows10GeneralConfiguration')`
OBJECT_END

STATE smartscreen_on
    found boolean = true
    record
        field rows.*.smartScreenEnableInShell boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF smartscreen_on
    OBJECT_REF win_configs
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Intune compliance sibling: [`m365_compliance_policy`](../m365_compliance_policy/m365_compliance_policy.md)
- Devices receiving profiles: [`m365_managed_device`](../m365_managed_device/m365_managed_device.md)
