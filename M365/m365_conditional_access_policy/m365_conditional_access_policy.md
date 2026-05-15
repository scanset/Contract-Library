# m365_conditional_access_policy

## Overview

Resource-shape reference for an Entra ID Conditional Access (CA) policy discovered via `m365_graph_query` against `/identity/conditionalAccess/policies`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

CA policies are *the* central access-control surface in Entra. Each policy is a `(conditions, controls)` tuple — "if signing in matches these conditions, then enforce these controls (MFA / compliant device / terms of use / block / etc)". Most identity-side compliance assertions (AC-2, AC-7, IA-2 series) ultimately reduce to "are the expected CA policies present, enabled, and configured correctly".

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::ConditionalAccessPolicy`
**Required permission:** `Policy.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `identity/conditionalAccess/policies`.                               | `identity/conditionalAccess/policies`                  |
| `select` | string | No       | Typically omitted — CA objects are deeply nested and projection is finicky.  | (none)                                                 |
| `filter` | string | No       | OData `$filter`. Common: `state eq 'enabled'`.                               | `state eq 'enabled'`                                   |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single policy):**

```json
{
  "id": "11111111-1111-1111-1111-111111111111",
  "displayName": "Require MFA for all users",
  "state": "enabled",
  "createdDateTime": "2024-08-01T10:00:00Z",
  "modifiedDateTime": "2026-03-12T14:30:00Z",
  "conditions": {
    "users": { "includeUsers": ["All"], "excludeGroups": ["..."] },
    "applications": { "includeApplications": ["All"] },
    "platforms": { "includePlatforms": ["all"] },
    "locations": null,
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  },
  "sessionControls": null
}
```

---

## Collected Data Fields

Inside `rows.*`:

| Field                       | Type    | Description                                                                              |
| --------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                 | string  | Graph object id.                                                                         |
| `rows.*.displayName`        | string  | Policy name shown in the portal.                                                         |
| `rows.*.state`              | string  | `enabled`, `disabled`, or `enabledForReportingButNotEnforced`.                          |
| `rows.*.conditions`         | object  | Nested: `users`, `applications`, `platforms`, `locations`, `clientAppTypes`, `userRiskLevels`, `signInRiskLevels`. |
| `rows.*.grantControls`      | object  | Nested: `operator` (AND / OR), `builtInControls` (mfa, compliantDevice, etc), `customAuthenticationFactors`, `termsOfUse`. |
| `rows.*.sessionControls`    | object  | Nested: `applicationEnforcedRestrictions`, `cloudAppSecurity`, `signInFrequency`, `persistentBrowser`. |
| `rows.*.createdDateTime`    | string  | ISO-8601.                                                                                |
| `rows.*.modifiedDateTime`   | string  | ISO-8601.                                                                                |

---


## ESP Examples

### At least one enabled MFA policy must exist

```esp
OBJECT mfa_policies
    path `identity/conditionalAccess/policies`
    filter `state eq 'enabled'`
OBJECT_END

STATE has_mfa_enforcement
    found boolean = true
    record
        field rows.*.grantControls.builtInControls.* string = `mfa` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_mfa_enforcement
    OBJECT_REF mfa_policies
CTN_END
```

### No CA policy may be in "report-only" mode in production

```esp
OBJECT all_ca
    path `identity/conditionalAccess/policies`
OBJECT_END

STATE no_report_only
    found boolean = true
    record
        field rows.*.state string != `enabledForReportingButNotEnforced`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_report_only
    OBJECT_REF all_ca
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
