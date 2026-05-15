# m365_bitlocker_recovery_key

## Overview

Resource-shape reference for a BitLocker recovery key escrow record discovered via `m365_graph_query` against `/informationProtection/bitlocker/recoveryKeys`. **Not a standalone CTN.**

One row per *escrowed key* (not per device — a device can have multiple volumes, each with its own recovery key). The discovery surfaces **metadata only** — "is the key escrowed?" — never the key itself. Reading the actual key value requires a separate privileged call to `/recoveryKeys/{id}?$select=key` and is intentionally not pulled by discovery. Maps cleanly to `SC-28(1)` (cryptographic protection of data at rest).

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::BitlockerRecoveryKey`
**Required permission:** `BitlockerKey.ReadBasic.All` (application, admin consent)

The `.ReadBasic` permission grants the metadata-only read; the broader `BitlockerKey.Read.All` (NOT requested) is what would expose the key value.

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `informationProtection/bitlocker/recoveryKeys`.                      | `informationProtection/bitlocker/recoveryKeys`                     |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row):**

```json
{
  "id": "abc123de-f456-...",
  "createdDateTime": "2025-08-15T14:00:00Z",
  "volumeType": "operatingSystemVolume",
  "deviceId": "55555555-5555-5555-5555-555555555555"
}
```

Note the absence of any key material in the response.

---

## Collected Data Fields

| Field                          | Type    | Description                                                                              |
| ------------------------------ | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                    | string  | Recovery key escrow id (NOT the device id).                                              |
| `rows.*.createdDateTime`       | string  | ISO-8601 — when the key was escrowed.                                                    |
| `rows.*.volumeType`            | string  | `operatingSystemVolume`, `fixedDataVolume`, `removableDataVolume`, `unknownFutureValue`. |
| `rows.*.deviceId`              | string  | Azure AD device id — join key with `m365_device.metadata.device_id`.                    |

---


## ESP Example

### Every Windows OS volume must have an escrowed BitLocker key

```esp
OBJECT escrowed_keys
    path `informationProtection/bitlocker/recoveryKeys`
    filter `volumeType eq 'operatingSystemVolume'`
OBJECT_END

STATE all_os_volumes_escrowed
    found boolean = true
    row_count int > `0`
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_os_volumes_escrowed
    OBJECT_REF escrowed_keys
CTN_END
```

A more precise policy joins this against `m365_device` to assert "every Windows device with `operatingSystemVolume` ∈ escrowed-keys.deviceId".

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Device join: [`m365_device`](../m365_device/m365_device.md) via `device_id`
