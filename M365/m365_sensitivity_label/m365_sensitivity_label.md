# m365_sensitivity_label

## Overview

Resource-shape reference for a Microsoft Purview sensitivity label discovered via `m365_graph_query` against `/informationProtection/policy/labels`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

**Important:** this endpoint is **beta-only** as of 2026 — not yet in Graph `v1.0`. The discoverer passes `api_version: "beta"` on the OBJECT. Beta endpoints are subject to breaking changes from Microsoft without notice.

Sensitivity labels classify content (documents, emails, sites, containers) into tiers like *Public / General / Confidential / Highly Confidential* (the exact set is tenant-configured). They're the foundation of Purview Information Protection — encryption, watermarking, sharing restrictions, and DLP scope all hang off them.

**Platform:** Microsoft Graph (beta)
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::SensitivityLabel`
**Required permission:** `InformationProtectionPolicy.Read.All` (application, admin consent)

---

## Object Fields

| Field         | Type   | Required | Description                                                                  | Example                                                            |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`        | string | **Yes**  | Must be `informationProtection/policy/labels`.                               | `informationProtection/policy/labels`                              |
| `api_version` | string | **Yes**  | Must be `beta` — not in v1.0.                                                | `beta`                                                             |
| `select`      | string | No       | Typically omitted — labels have a flat shape, projection is rarely useful.   | (none)                                                             |
| `filter`      | string | No       | OData `$filter`. Common: `isActive eq true`.                                 | `isActive eq true`                                                 |

---

## Commands Executed

```
GET https://graph.microsoft.com/beta/informationProtection/policy/labels
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single label):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "name": "Confidential",
  "displayName": "Confidential — Internal Only",
  "description": "For internal use across the org",
  "color": "#FF6600",
  "isActive": true,
  "priority": 30,
  "sensitivity": 3
}
```

---

## Collected Data Fields

Inside `rows.*`:

| Field                  | Type    | Description                                                                              |
| ---------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`            | string  | Label id (GUID).                                                                         |
| `rows.*.name`          | string  | Internal short name.                                                                     |
| `rows.*.displayName`   | string  | Shown to users in Word / Excel / Outlook / SharePoint.                                   |
| `rows.*.description`   | string  | Description.                                                                             |
| `rows.*.color`         | string  | Hex color shown next to the label.                                                       |
| `rows.*.isActive`      | boolean | `true` = label is in use; `false` = published but not currently applicable.              |
| `rows.*.priority`      | int     | Sort order in the label picker. Lower = shown earlier.                                   |
| `rows.*.sensitivity`   | int     | Numeric sensitivity level (Microsoft-defined scale).                                     |

---


## ESP Examples

### Tenant must have at least one active label at each sensitivity tier

```esp
OBJECT labels
    path `informationProtection/policy/labels`
    api_version `beta`
OBJECT_END

STATE has_active_labels
    found boolean = true
    row_count int >= `3`
    record
        field rows.*.isActive boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_active_labels
    OBJECT_REF labels
CTN_END
```

### "Highly Confidential" tier label must be present and active

```esp
OBJECT all_labels
    path `informationProtection/policy/labels`
    api_version `beta`
OBJECT_END

STATE has_highly_confidential
    found boolean = true
    record
        field rows.*.displayName string = `Highly Confidential` at_least_one
        field rows.*.isActive boolean = `true` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_highly_confidential
    OBJECT_REF all_labels
CTN_END
```

---

## Caveats

- **Beta volatility.** Microsoft may rename fields, change pagination semantics, or move the endpoint to v1.0 with a different path. When this graduates, update the discoverer's `api_version: Some("beta")` to `None` (= v1.0) and adjust the path if needed.
- **Per-tenant variation.** Label sets are tenant-configured. ESP policies that assert on specific label `displayName` values are tenant-specific; consider asserting on `sensitivity` (the numeric tier) for tenant-portable policies.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
