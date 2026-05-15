# m365_authentication_context

## Overview

Resource-shape reference for a Conditional Access authentication context discovered via `m365_graph_query` against `/identity/conditionalAccess/authenticationContextClassReferences`. **Not a standalone CTN.**

Authentication contexts are *labeled trust tiers* (e.g. `c1` / `c2` / `c3`) that conditional access policies and sensitivity labels both reference. They're how Microsoft connects "this user/device is allowed to handle FCI" → "FCI sites/files require auth context c1" → "auth context c1 requires MFA + compliant device". Your **CA04 — Require FCI-handler device for FCI auth context** policy almost certainly gates on one of these.

**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::AuthenticationContext`
**Required permission:** `Policy.Read.All` (already granted)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `identity/conditionalAccess/authenticationContextClassReferences`.   | `identity/conditionalAccess/authenticationContextClassReferences`  |
| `top`    | int    | **Yes**  | **Must be `0`** — this endpoint returns `400 "Query option 'Top' is not allowed"` if `$top` is sent. The discoverer passes `top=0` automatically; if you author a policy against this path by hand, set it explicitly. | `0`                                                                |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row):**

```json
{
  "id": "c1",
  "displayName": "FCI handling required",
  "description": "Apply this context to resources that handle Federal Contract Information",
  "isAvailable": true
}
```

The `id` is the **2-character tag** (`c1` .. `c25`) that's referenced from CA policies and sensitivity labels — not a GUID.

---

## Collected Data Fields

| Field                | Type    | Description                                                              |
| -------------------- | ------- | ------------------------------------------------------------------------ |
| `rows.*.id`          | string  | Context tag — `c1` through `c25`.                                        |
| `rows.*.displayName` | string  | Admin-facing label.                                                      |
| `rows.*.description` | string  | Description.                                                             |
| `rows.*.isAvailable` | boolean | `true` = published / usable in policies; `false` = defined but inactive. |

---


## ESP Example

### The `c1` (FCI) context must exist and be available

```esp
OBJECT contexts
    path `identity/conditionalAccess/authenticationContextClassReferences`
OBJECT_END

STATE has_fci_context
    found boolean = true
    record
        field rows.*.id string = `c1` at_least_one
        field rows.*.isAvailable boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_fci_context
    OBJECT_REF contexts
CTN_END
```

### Cross-resource: CA policy must reference an existing context

This requires joining `m365_conditional_access_policy` (the policy that asserts on a context) with `m365_authentication_context` (the existing contexts) — out of scope for a single CTN. The pattern is: discover both, then a higher-level policy asserts referential integrity.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Policies that reference contexts: [`m365_conditional_access_policy`](../m365_conditional_access_policy/m365_conditional_access_policy.md) — look at `metadata.conditions.applications.includeAuthenticationContextClassReferences`
- Labels that elevate to contexts: [`m365_sensitivity_label`](../m365_sensitivity_label/m365_sensitivity_label.md) — Purview can require a specific context to apply a label
