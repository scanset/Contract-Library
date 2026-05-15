# m365_group

## Overview

Resource-shape reference for an Entra ID group discovered via `m365_graph_query` against `/groups`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections. Covers security groups, Microsoft 365 (Unified) groups, and mail-enabled distribution groups. Group membership is *not* pulled at discovery time; it's lazily collected via Graph during policy evaluation when needed.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::Group`

---

## Object Fields

For policies, use the standard `m365_graph_query` object fields with `path = /groups`:

| Field    | Type   | Required | Description                                                                  | Example                                                  |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | -------------------------------------------------------- |
| `path`   | string | **Yes**  | Must be `/groups` (or `groups`) to land on this resource shape.              | `/groups`                                                |
| `select` | string | No       | Reduce response payload. Use the schema fields below.                        | `id,displayName,visibility,groupTypes,securityEnabled`   |
| `filter` | string | No       | OData `$filter`. Common: `securityEnabled eq true`, `mailEnabled eq true`.   | `securityEnabled eq true`                                |

---

## Commands Executed

### Command 1: GET https://graph.microsoft.com/v1.0/groups

```
GET https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,visibility,groupTypes,mailEnabled,securityEnabled&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row, Microsoft 365 group):**

```json
{
  "id": "22222222-2222-2222-2222-222222222222",
  "displayName": "Finance Team",
  "description": "Finance department collaboration group",
  "mail": "finance@contoso.com",
  "mailEnabled": true,
  "securityEnabled": false,
  "groupTypes": ["Unified"],
  "visibility": "Private",
  "createdDateTime": "2024-09-01T12:00:00Z"
}
```

**Sample response (single row, security group):**

```json
{
  "id": "33333333-3333-3333-3333-333333333333",
  "displayName": "VPN-Users",
  "description": "Allowed VPN users",
  "mail": null,
  "mailEnabled": false,
  "securityEnabled": true,
  "groupTypes": [],
  "visibility": null,
  "createdDateTime": "2024-03-12T08:00:00Z"
}
```

---

## Collected Data Fields

Returned via the parent `m365_graph_query` CTN. Inside `rows.*` you'll find:

| Field                          | Type    | Always Present | Description                                                                              |
| ------------------------------ | ------- | -------------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                    | string  | Yes            | Graph object id (UUID).                                                                  |
| `rows.*.displayName`           | string  | Yes            | Group name.                                                                              |
| `rows.*.description`           | string  | No             | Free-form description.                                                                   |
| `rows.*.mail`                  | string  | No             | Primary SMTP for mail-enabled groups; null otherwise.                                    |
| `rows.*.mailEnabled`           | boolean | Yes            | Whether the group has a mailbox.                                                         |
| `rows.*.securityEnabled`       | boolean | Yes            | Whether the group can be used for access control (i.e. is a security principal).         |
| `rows.*.groupTypes`            | array   | Yes            | `["Unified"]` = Microsoft 365 group; `[]` = pure security group.                         |
| `rows.*.visibility`            | string  | No             | `Public`, `Private`, `Hiddenmembership`; null for security groups.                       |
| `rows.*.createdDateTime`       | string  | Yes            | ISO-8601 timestamp.                                                                      |

---


## ESP Examples

### No public Microsoft 365 groups holding sensitive content

```esp
OBJECT m365_unified_groups
    path `/groups`
    select `id,displayName,visibility,groupTypes`
OBJECT_END

STATE no_public_unified
    found boolean = true
    record
        field rows.*.groupTypes string = `Unified` at_least_one
        field rows.*.visibility string != `Public`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_public_unified
    OBJECT_REF m365_unified_groups
CTN_END
```

### Every security group must have a description

```esp
OBJECT security_groups
    path `/groups`
    filter `securityEnabled eq true`
    select `id,displayName,description`
OBJECT_END

STATE all_have_description
    found boolean = true
    record
        field rows.*.description string != ``
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_have_description
    OBJECT_REF security_groups
CTN_END
```

---

## Required Permission

Microsoft Graph application permission **`Group.Read.All`** on the app registration, with admin consent granted.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Other M365 resources: [`m365_user`](../m365_user/m365_user.md), [`m365_device`](../m365_device/m365_device.md)
