# m365_pim_role_eligibility

## Overview

Resource-shape reference for a PIM (Privileged Identity Management) role eligibility schedule discovered via `m365_graph_query` against `/roleManagement/directory/roleEligibilitySchedules`. **Not a standalone CTN.**

These records describe **who is eligible to activate which directory role**, when, and under what scope. Critical for `AC-2(7)` (privileged accounts) and `AC-6` (least privilege) — auditors specifically look for "are Global Administrators assigned just-in-time via PIM, or persistently?".

This endpoint returns *eligibility* (the right to activate). Sibling endpoint `/roleAssignmentSchedules` returns *active* assignments (current activated state). For a complete privilege picture you'd query both; this discoverer covers eligibility.

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::PimRoleEligibility`
**Required permission:** `RoleManagement.Read.Directory` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `roleManagement/directory/roleEligibilitySchedules`.                 | `roleManagement/directory/roleEligibilitySchedules`                |
| `filter` | string | No       | Common: `roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'` (Global Admin). | (see example)                                                |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row):**

```json
{
  "id": "11111111-...",
  "principalId": "22222222-2222-2222-2222-222222222222",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/",
  "memberType": "Direct",
  "status": "Provisioned",
  "scheduleInfo": {
    "startDateTime": "2025-08-15T14:00:00Z",
    "expiration": {
      "type": "noExpiration"
    }
  }
}
```

---

## Collected Data Fields

| Field                                          | Type    | Description                                                                              |
| ---------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                    | string  | Eligibility schedule id.                                                                 |
| `rows.*.principalId`                           | string  | Entra user / group / SP id that is eligible.                                             |
| `rows.*.roleDefinitionId`                      | string  | Built-in role id — e.g. `62e90394-69f5-4237-9190-012177145e10` is Global Administrator.  |
| `rows.*.directoryScopeId`                      | string  | `/` (tenant-wide) or a more specific scope.                                              |
| `rows.*.memberType`                            | string  | `Direct`, `Group`, or `Inherited` — how the eligibility was granted.                     |
| `rows.*.status`                                | string  | `Provisioned`, `Revoked`, `PendingProvisioning`, `Failed`.                               |
| `rows.*.scheduleInfo.startDateTime`            | string  | ISO-8601 — eligibility window opens.                                                     |
| `rows.*.scheduleInfo.expiration.type`          | string  | `noExpiration`, `afterDateTime`, `afterDuration`.                                        |
| `rows.*.scheduleInfo.expiration.endDateTime`   | string  | ISO-8601 (if applicable).                                                                |

---


## ESP Example

### No principal may be Global Administrator without expiration

```esp
OBJECT ga_eligible
    path `roleManagement/directory/roleEligibilitySchedules`
    filter `roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'`
OBJECT_END

STATE all_ga_time_bounded
    found boolean = true
    record
        field rows.*.scheduleInfo.expiration.type string != `noExpiration`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_ga_time_bounded
    OBJECT_REF ga_eligible
CTN_END
```

### Caveats

- **Eligibility ≠ activation.** A principal eligible for GA may rarely (or never) activate the role. Pair this with `/roleAssignmentSchedules` (active assignments) for a full picture. The eligibility-only check still catches "too many people are eligible" — which is the more common audit finding.
- **Group-based eligibility.** A row with `memberType: Group` means the eligibility flows through a group's members. Follow `principalId` to `/groups/{id}/members` to see who effectively inherits.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Future asset type: `M365::PimRoleAssignment` (active assignments) — same Graph surface, sibling endpoint
