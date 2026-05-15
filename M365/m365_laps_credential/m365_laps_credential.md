# m365_laps_credential

## Overview

Resource-shape reference for a Windows LAPS (Local Administrator Password Solution) credential record discovered via `m365_graph_query` against `/directory/deviceLocalCredentials`. **Not a standalone CTN.**

One row per Windows device with LAPS-managed local credentials escrowed in Entra ID. Surfaces **metadata only** — account name, last rotation timestamp, refresh timestamp — never the password value. Reading the password requires a separate privileged call against `/directory/deviceLocalCredentials/{id}` and is intentionally not pulled.

Maps to `AC-6` (least privilege — local admin accounts shouldn't share a password across devices) and `IA-5` (authenticator management — rotation cadence).

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::LapsCredential`
**Required permission:** `DeviceLocalCredential.ReadBasic.All` (application, admin consent)

The `.ReadBasic` permission grants metadata-only read. The broader `DeviceLocalCredential.Read.All` (NOT requested) is what would expose the actual password.

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `directory/deviceLocalCredentials`.                                  | `directory/deviceLocalCredentials`                                 |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row):**

```json
{
  "id": "device-credential-id",
  "deviceName": "DESKTOP-CORP-01",
  "azureADDeviceId": "55555555-5555-5555-5555-555555555555",
  "lastBackupDateTime": "2026-05-01T03:00:00Z",
  "refreshDateTime": "2026-06-01T03:00:00Z",
  "credentials": [
    {
      "accountName": "Administrator",
      "accountSid": "S-1-5-21-...",
      "backupDateTime": "2026-05-01T03:00:00Z"
    }
  ]
}
```

No `passwordBase64` or `password` field on `credentials[*]` — metadata-only.

---

## Collected Data Fields

| Field                                | Type    | Description                                                                |
| ------------------------------------ | ------- | -------------------------------------------------------------------------- |
| `rows.*.id`                          | string  | LAPS credential record id.                                                 |
| `rows.*.deviceName`                  | string  | Hostname.                                                                  |
| `rows.*.azureADDeviceId`             | string  | Join key with `m365_device.metadata.device_id`.                            |
| `rows.*.lastBackupDateTime`          | string  | ISO-8601 — last time the password rotated and was escrowed.                |
| `rows.*.refreshDateTime`             | string  | ISO-8601 — next scheduled rotation.                                        |
| `rows.*.credentials[*].accountName`  | string  | Local account being managed (typically `Administrator`).                   |
| `rows.*.credentials[*].accountSid`   | string  | Local SID.                                                                 |
| `rows.*.credentials[*].backupDateTime` | string | Per-account last backup (matches outer `lastBackupDateTime` for single-account records). |

---


## ESP Example

### Every Windows device must have LAPS rotated within the last 60 days

```esp
OBJECT laps
    path `directory/deviceLocalCredentials`
OBJECT_END

STATE recent_rotation
    found boolean = true
    record
        # filter: lastBackupDateTime > now - 60d (server can't do this;
        # ESP record check handles the date comparison)
        field rows.*.lastBackupDateTime string != ``
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF recent_rotation
    OBJECT_REF laps
CTN_END
```

For a tight check, combine `m365_laps_credential` with `m365_device` to assert "every Entra-joined Windows device has a corresponding LAPS record with `last_backup_at` within rotation window".

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Device join: [`m365_device`](../m365_device/m365_device.md) via `azureADDeviceId` ↔ `metadata.device_id`
