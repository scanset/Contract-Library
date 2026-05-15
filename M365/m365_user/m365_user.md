# m365_user

## Overview

Resource-shape reference for an Entra ID user discovered via `m365_graph_query` against `/users`. **Not a standalone CTN** — the single `m365_graph_query` CTN handles all Graph collections; this document describes the row shape returned for `/users`. Covers regular members, B2B guests, and service-principal-style identities surfaced as users.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::User`

---

## Object Fields

For policies, use the standard `m365_graph_query` object fields with `path = /users`:

| Field    | Type   | Required | Description                                                                  | Example                                                |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `/users` (or `users`) to land on this resource shape.                | `/users`                                               |
| `select` | string | No       | Reduce response payload. Use the schema fields below.                        | `id,displayName,userPrincipalName,accountEnabled`      |
| `filter` | string | No       | OData `$filter`. Common: `accountEnabled eq true`, `userType eq 'Guest'`.    | `accountEnabled eq true`                               |

---

## Commands Executed

### Command 1: GET https://graph.microsoft.com/v1.0/users

```
GET https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "Alice Example",
  "userPrincipalName": "alice@contoso.com",
  "mail": "alice@contoso.com",
  "accountEnabled": true,
  "userType": "Member",
  "createdDateTime": "2023-02-14T18:00:00Z",
  "signInActivity": {
    "lastSignInDateTime": "2026-05-07T14:32:11Z",
    "lastNonInteractiveSignInDateTime": "2026-05-08T03:00:00Z"
  }
}
```

---

## Collected Data Fields

Returned via the parent `m365_graph_query` CTN. Inside `rows.*` you'll find:

| Field                                              | Type    | Always Present | Description                                                              |
| -------------------------------------------------- | ------- | -------------- | ------------------------------------------------------------------------ |
| `rows.*.id`                                        | string  | Yes            | Graph object id (UUID, immutable).                                       |
| `rows.*.displayName`                               | string  | Yes            | Display name; may be blank for unprovisioned users.                      |
| `rows.*.userPrincipalName`                         | string  | Yes            | Login name (UPN).                                                        |
| `rows.*.mail`                                      | string  | No             | Primary SMTP; may differ from UPN.                                       |
| `rows.*.accountEnabled`                            | boolean | Yes            | Whether the account can sign in.                                         |
| `rows.*.userType`                                  | string  | Yes            | `Member` or `Guest` (B2B externally federated).                          |
| `rows.*.createdDateTime`                           | string  | Yes            | ISO-8601 timestamp; date the user was created.                           |
| `rows.*.signInActivity.lastSignInDateTime`         | string  | No             | ISO-8601; last interactive sign-in.                                      |
| `rows.*.signInActivity.lastNonInteractiveSignInDateTime` | string  | No        | ISO-8601; last non-interactive sign-in.                                  |
| `rows.*.assignedLicenses[*].skuId`                 | string  | Yes (empty if no licenses) | Array of license SKU GUIDs assigned to the user. Empty for unlicensed users (e.g. service-account-style identities). |
| `rows.*.assignedLicenses[*].disabledPlans`         | array   | No             | Per-license, the service plan GUIDs disabled within that SKU.            |

---


## ESP Examples

### Every user must be enabled

```esp
OBJECT all_users
    path `/users`
    select `id,displayName,accountEnabled`
OBJECT_END

STATE all_enabled
    found boolean = true
    record
        field rows.*.accountEnabled boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_enabled
    OBJECT_REF all_users
CTN_END
```

### No stale guest accounts (older than 90 days inactive)

```esp
OBJECT guests
    path `/users`
    filter `userType eq 'Guest'`
    select `id,displayName,userPrincipalName,signInActivity`
OBJECT_END

STATE no_stale_guests
    found boolean = true
    row_count int = `0`
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_stale_guests
    OBJECT_REF guests
CTN_END
```

*(Note: the filter here is illustrative; a true "stale" check requires a filter on `signInActivity.lastSignInDateTime` which Graph supports — `signInActivity/lastSignInDateTime le 2026-02-08T00:00:00Z`.)*

---

## Required Permission

Microsoft Graph application permission **`User.Read.All`** on the app registration, with admin consent granted.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Other M365 resources: [`m365_group`](../m365_group/m365_group.md), [`m365_device`](../m365_device/m365_device.md)
