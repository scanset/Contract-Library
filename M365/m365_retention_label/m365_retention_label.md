# m365_retention_label

## Overview

Resource-shape reference for a Purview retention label discovered via `m365_graph_query` against `/security/labels/retentionLabels`. **Not a standalone CTN.**

**Beta-only endpoint.** Same pattern as [`m365_sensitivity_label`](../m365_sensitivity_label/m365_sensitivity_label.md) — pass `api_version: "beta"` on the OBJECT.

Retention labels are the *records management* counterpart to sensitivity labels. Where sensitivity labels classify *who can access*, retention labels classify *how long to keep* (and what to do at end of life — retain, retain-as-record, delete). Maps directly to `AU-11` (audit record retention) and to FAR / DFARS records retention obligations.

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::RetentionLabel`
**Required permission:** `RecordsManagement.Read.All` (application, admin consent)

---

## Object Fields

| Field         | Type   | Required | Description                                                                  | Example                                                            |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`        | string | **Yes**  | Must be `security/labels/retentionLabels`.                                   | `security/labels/retentionLabels`                                  |
| `api_version` | string | **Yes**  | Must be `beta` — not in v1.0.                                                | `beta`                                                             |
| `top`         | int    | **Yes**  | **Must be `0`** — this endpoint returns `400 "Query option 'Top' is not allowed"` if `$top` is sent. The discoverer passes `top=0` automatically; if you author a policy against this path by hand, set it explicitly. | `0`                                                                |

---

## Commands Executed

```
GET https://graph.microsoft.com/beta/security/labels/retentionLabels
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single label):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "FCI Records — 7 Years",
  "description": "Federal contract information; retain for 7 years post-contract close",
  "behaviorDuringRetentionPeriod": "retainAsRecord",
  "actionAfterRetentionPeriod": "none",
  "retentionDuration": {
    "@odata.type": "#microsoft.graph.security.retentionDurationInDays",
    "days": 2555
  },
  "isInUse": true
}
```

---

## Collected Data Fields

| Field                                       | Type    | Description                                                                              |
| ------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                 | string  | Label id.                                                                                |
| `rows.*.displayName`                        | string  | Admin-facing label name.                                                                 |
| `rows.*.description`                        | string  | Description.                                                                             |
| `rows.*.behaviorDuringRetentionPeriod`      | string  | `retain`, `retainAsRecord`, `retainAsRegulatoryRecord`. "Record" mode locks the content. |
| `rows.*.actionAfterRetentionPeriod`         | string  | `none`, `delete`, `startDispositionReview`, `relabel`.                                   |
| `rows.*.retentionDuration`                  | object  | Nested — typed as `retentionDurationInDays` or `retentionDurationForever`.               |
| `rows.*.isInUse`                            | boolean | `true` if any retention policy currently references this label.                          |

---


## ESP Example

### FCI Records label must exist, be in use, and retain ≥ 7 years

```esp
OBJECT records_labels
    path `security/labels/retentionLabels`
    api_version `beta`
OBJECT_END

STATE fci_retention_compliant
    found boolean = true
    record
        field rows.*.displayName string = `FCI Records — 7 Years` at_least_one
        field rows.*.isInUse boolean = `true` at_least_one
        field rows.*.retentionDuration.days int >= `2555`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF fci_retention_compliant
    OBJECT_REF records_labels
CTN_END
```

---

## Caveats

- **Beta volatility.** Microsoft can rename fields or move the endpoint to v1.0 with a different shape; when that happens, update `api_version: Some("beta")` → `None` in the discoverer.
- **Labels vs policies.** This discovery covers retention **labels** (the classification). The **policies** that publish labels to locations (Exchange, SharePoint, OneDrive, Teams) are a separate endpoint not yet discovered — sibling asset type `M365::RetentionPolicy` would be a future addition.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Sibling beta resource: [`m365_sensitivity_label`](../m365_sensitivity_label/m365_sensitivity_label.md)
