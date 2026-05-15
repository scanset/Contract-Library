# m365_device_category

## Overview

Resource-shape reference for an Intune device category discovered via `m365_graph_query` against `/deviceManagement/deviceCategories`. **Not a standalone CTN.**

Device categories let an Intune admin classify enrolled devices into named buckets (e.g. *Kiosk*, *Engineering*, *FCI-handler*). They pair with `extensionAttributes` for dual-tagging schemes — a category from Intune + a custom attribute from Entra — which together drive richer CA conditions than either alone.

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::DeviceCategory`
**Required permission:** `DeviceManagementConfiguration.Read.All` (already granted)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `deviceManagement/deviceCategories`.                                 | `deviceManagement/deviceCategories`                                |
| `select` | string | No       | Schema is small — projection rarely needed.                                  | (none)                                                             |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response:**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "FCI-handler",
  "description": "Devices authorized to handle Federal Contract Information"
}
```

---

## Collected Data Fields

| Field                   | Type    | Description           |
| ----------------------- | ------- | --------------------- |
| `rows.*.id`             | string  | Category id (GUID).   |
| `rows.*.displayName`    | string  | Category name.        |
| `rows.*.description`    | string  | Free-form description. |

---


## ESP Example

```esp
OBJECT categories
    path `deviceManagement/deviceCategories`
OBJECT_END

STATE has_fci_handler_category
    found boolean = true
    record
        field rows.*.displayName string = `FCI-handler` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_fci_handler_category
    OBJECT_REF categories
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Devices using these categories: [`m365_managed_device`](../m365_managed_device/m365_managed_device.md) (`deviceCategoryDisplayName` field)
