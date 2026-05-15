# m365_team

## Overview

Resource-shape reference for a Microsoft Team discovered via `m365_graph_query` against `/teams`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

A Team is built on top of a Microsoft 365 Unified Group — the `id` is the same as the underlying [`m365_group`](../m365_group/m365_group.md). This endpoint adds Team-specific metadata (visibility, specialization, archive state) that the group endpoint doesn't carry.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::Team`
**Required permission:** `Team.ReadBasic.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `teams`.                                                             | `teams`                                                            |
| `select` | string | No       | Reduce payload.                                                              | `id,displayName,visibility,specialization,createdDateTime,isArchived` |
| `filter` | string | No       | OData `$filter`. Common: `isArchived eq false`.                              | `isArchived eq false`                                              |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/teams
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single team):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "Finance Team",
  "description": "Finance department collaboration",
  "visibility": "private",
  "specialization": "none",
  "createdDateTime": "2024-09-01T12:00:00Z",
  "isArchived": false
}
```

The `id` is the same value as the underlying group's id — `/groups/{id}` and `/teams/{id}` reference the same object, with `/teams/{id}` exposing Team-specific properties.

---

## Collected Data Fields

Inside `rows.*`:

| Field                          | Type    | Description                                                                              |
| ------------------------------ | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                    | string  | Team / underlying group id.                                                              |
| `rows.*.displayName`           | string  | Team name.                                                                               |
| `rows.*.description`           | string  | Description.                                                                             |
| `rows.*.visibility`            | string  | `public` / `private` / `hiddenmembership`.                                               |
| `rows.*.specialization`        | string  | `none` / `educationProfessionalLearningCommunity` / `educationClass` / `educationStaff` / `healthcareStandard` / `healthcareCareCoordination`. |
| `rows.*.createdDateTime`       | string  | ISO-8601.                                                                                |
| `rows.*.isArchived`            | boolean | `true` when the team is archived (read-only, no posts).                                  |

---


## ESP Examples

### No team should be public — production hygiene

```esp
OBJECT teams
    path `teams`
    filter `isArchived eq false`
    select `id,displayName,visibility`
OBJECT_END

STATE no_public_teams
    found boolean = true
    record
        field rows.*.visibility string != `public`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_public_teams
    OBJECT_REF teams
CTN_END
```

### Archived teams should not hold sensitive content

This is a paired check: archived teams shouldn't be a hiding spot for sensitive data. Combine with a sensitivity-label check on the underlying group's files. Out of scope for a single CTN — typically a policy that joins `m365_team` + `m365_sensitivity_label` evidence.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Underlying group: [`m365_group`](../m365_group/m365_group.md) — same `id`
- Collaboration sibling: [`m365_sharepoint_site`](../m365_sharepoint_site/m365_sharepoint_site.md)
