# m365_role_assignment

## Overview

Resource-shape reference for an **active** Entra ID role assignment discovered via `m365_graph_query` against `/roleManagement/directory/roleAssignments`. **Not a standalone CTN.**

A `roleAssignment` is the *currently in effect* grant of a directory role to a principal. This is the companion to [`m365_pim_role_eligibility`](../m365_pim_role_eligibility/m365_pim_role_eligibility.md):

- **eligibility** = "Alice *can become* Global Administrator (must elevate via PIM, may require MFA / justification / approval)"
- **assignment** = "Alice *IS* Global Administrator right now" — the standing grant

In a healthy CMMC/FedRAMP-ish posture, the count of standing assignments on high-privilege roles should be **as small as possible** (ideally 0 for emergency-only roles), with most access fronted through PIM eligibility instead.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::RoleAssignment`
**Required permission:** `RoleManagement.Read.Directory` (application, admin consent — already granted)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                       |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `path`   | string | **Yes**  | Must be `roleManagement/directory/roleAssignments`.                          | `roleManagement/directory/roleAssignments`                    |
| `filter` | string | No       | OData `$filter`. Common: `roleDefinitionId eq '<id>'` to slice by role.      | `roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'`  |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single assignment):**

```json
{
  "id": "lAPpYvVpN0KRkAEhdxReEAo4u2L7yvNDmIUjxKfICCY-1",
  "principalId": "33333333-3333-3333-3333-333333333333",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/",
  "appScopeId": null
}
```

This says: principal `33333…` holds the role `62e90394-…` (Global Administrator) at root scope (`/` = tenant-wide).

---

## Collected Data Fields

| Field                         | Type    | Description                                                                              |
| ----------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                   | string  | Assignment id (opaque, base64-ish — not a UUID).                                         |
| `rows.*.principalId`          | string  | The grantee. UUID of user / group / service principal.                                   |
| `rows.*.roleDefinitionId`     | string  | The role definition id. **Matches `directoryRole.roleTemplateId`**, not `directoryRole.id`. |
| `rows.*.directoryScopeId`     | string  | Scope as a Graph path. `/` = tenant-wide. `/administrativeUnits/<id>` = AU-scoped. `/<resourceId>` = app-scoped (rare). |
| `rows.*.appScopeId`           | string  | Set if the assignment is app-scoped (custom RBAC); typically null.                       |

---


## ESP Examples

### Global Administrator role has at most 2 standing assignments

CMMC and Microsoft's own least-privilege guidance recommend ≤ 5 Global Administrators total; for a small org most should be PIM-eligible rather than standing.

```esp
OBJECT global_admin_active
    path `roleManagement/directory/roleAssignments`
    filter `roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'`
OBJECT_END

STATE bounded
    found boolean = true
    row_count int <= `2`
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF bounded
    OBJECT_REF global_admin_active
CTN_END
```

### No standing assignment at root scope for Privileged Role Administrator

`Privileged Role Administrator` (role template `e8611ab8-c189-46e8-94e1-60213ab1f814`) can grant ANY role — it should be PIM-eligible, never standing.

```esp
OBJECT pra_active
    path `roleManagement/directory/roleAssignments`
    filter `roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'`
OBJECT_END

STATE no_standing
    found boolean = true
    row_count int = `0`
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_standing
    OBJECT_REF pra_active
CTN_END
```

### All admin assignments must be tenant-scoped, not AU-scoped (or vice versa, depending on intent)

```esp
OBJECT admin_assignments
    path `roleManagement/directory/roleAssignments`
OBJECT_END

STATE tenant_scoped
    found boolean = true
    record
        field rows.*.directoryScopeId string = `/`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF tenant_scoped
    OBJECT_REF admin_assignments
CTN_END
```

*(Whether you want everything tenant-scoped or actively prefer AU-scoping depends on org structure — assert the shape you've decided on.)*

---

## Caveats

- **`roleDefinitionId` joins to `directoryRole.roleTemplateId`**, not `directoryRole.id`. This is the most common source of confusion when correlating roles by name. The unifiedRoleDefinition object space shares values with the role-template space.
- **Built-in vs custom roles.** A custom-RBAC role's `roleDefinitionId` will not match any directoryRoles row — those are tenant-defined `unifiedRoleDefinition` objects. Discovery of those (`/roleManagement/directory/roleDefinitions`) is a natural Phase 7+ extension.
- **PIM-eligible-then-activated is still an assignment.** When a user activates a PIM eligibility, Graph creates a *time-bounded* roleAssignment with an associated `roleAssignmentSchedule`. The default `/roleAssignments` endpoint includes these — so a user mid-elevation will appear. For "permanent only" inspection, query `/roleManagement/directory/roleAssignmentSchedules` and filter on `assignmentType eq 'Assigned'`.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- PIM eligibility counterpart: [`m365_pim_role_eligibility`](../m365_pim_role_eligibility/m365_pim_role_eligibility.md)
- Role definitions: [`m365_directory_role`](../m365_directory_role/m365_directory_role.md) — joins on `roleDefinitionId = roleTemplateId`
- Grantee resolution: [`m365_user`](../m365_user/m365_user.md), [`m365_group`](../m365_group/m365_group.md), [`m365_service_principal`](../m365_service_principal/m365_service_principal.md) — joins on `principalId = .id`
