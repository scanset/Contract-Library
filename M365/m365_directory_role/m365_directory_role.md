# m365_directory_role

## Overview

Resource-shape reference for an Entra ID directory role discovered via `m365_graph_query` against `/directoryRoles`. **Not a standalone CTN.**

A **directory role** is an *activated* tenant copy of a role template — e.g. "Global Administrator", "User Administrator", "Compliance Administrator". The role template is the global definition (same id across all tenants); the directory role is the tenant-local instance that holds the assignments.

**Important distinction:**
- `roleTemplateId` = stable, global, the same `62e90394-69f5-4237-9190-012177145e10` for Global Administrator in every tenant. Use this for cross-tenant identification.
- `id` = the directory role's per-tenant id. Use this only locally.
- The id space of `unifiedRoleDefinition` (used by `roleAssignments`) shares the `roleTemplateId` value, **not** the directoryRoles `id`. See [`m365_role_assignment`](../m365_role_assignment/m365_role_assignment.md) for the join shape.

This is the "directory of admin roles in the tenant" — companion to [`m365_role_assignment`](../m365_role_assignment/m365_role_assignment.md) (who holds them right now) and [`m365_pim_role_eligibility`](../m365_pim_role_eligibility/m365_pim_role_eligibility.md) (who can elevate into them).

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::DirectoryRole`
**Required permission:** `RoleManagement.Read.Directory` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                          | Example                       |
| -------- | ------ | -------- | ---------------------------------------------------- | ----------------------------- |
| `path`   | string | **Yes**  | Must be `/directoryRoles` (or `directoryRoles`).     | `directoryRoles`              |
| `top`    | int    | **Yes**  | **Must be `0`** — this endpoint returns `400 Request_UnsupportedQuery "This resource does not support custom page sizes"` if `$top` is sent. The discoverer passes `top=0` automatically; set it explicitly if you author a policy by hand. | `0`                           |

`/directoryRoles` does not accept `$select` or `$filter` server-side for most fields, so the discoverer relies on the default projection.

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/directoryRoles
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single role):**

```json
{
  "id": "22222222-2222-2222-2222-222222222222",
  "displayName": "Global Administrator",
  "description": "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities.",
  "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"
}
```

---

## Collected Data Fields

| Field                     | Type    | Description                                                                              |
| ------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`               | string  | Per-tenant directory role id.                                                            |
| `rows.*.displayName`      | string  | Human-readable name — e.g. `Global Administrator`.                                       |
| `rows.*.description`      | string  | What the role can do.                                                                    |
| `rows.*.roleTemplateId`   | string  | Stable global id of the role definition. Join key to `roleAssignments.roleDefinitionId`. |

---


## ESP Examples

### Global Administrator role must be activated in the tenant

If the role is not in `/directoryRoles`, it has never been used — a paradox most tenants resolve at first admin signup, but worth asserting.

```esp
OBJECT directory_roles
    path `directoryRoles`
OBJECT_END

STATE global_admin_activated
    found boolean = true
    record
        field rows.*.roleTemplateId string = `62e90394-69f5-4237-9190-012177145e10` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF global_admin_activated
    OBJECT_REF directory_roles
CTN_END
```

### No legacy "Company Administrator" naming should still be active

(`Company Administrator` is the old name of Global Administrator; new tenants display the new name.)

```esp
OBJECT directory_roles
    path `directoryRoles`
OBJECT_END

STATE modern_naming
    found boolean = true
    record
        field rows.*.displayName string != `Company Administrator`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF modern_naming
    OBJECT_REF directory_roles
CTN_END
```

---

## Caveats

- **`/directoryRoles` is only the *activated* roles.** A tenant has many more *template* roles in `/directoryRoleTemplates` that haven't been activated. This discoverer intentionally covers the activated subset — those are the ones that can hold assignments.
- **The role template id is the durable reference.** Build policies on `roleTemplateId`, not on `displayName` (which Microsoft has renamed several times — "Company Administrator" → "Global Administrator", and so on).
- Cross-resource referential integrity (every `roleAssignment.roleDefinitionId` resolves to a `directoryRole.roleTemplateId` or a known higher-privilege role) is a higher-level policy, not a single-CTN concern.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Active grants: [`m365_role_assignment`](../m365_role_assignment/m365_role_assignment.md) — joins on `roleDefinitionId = roleTemplateId`
- Eligible grants (PIM): [`m365_pim_role_eligibility`](../m365_pim_role_eligibility/m365_pim_role_eligibility.md) — same join
