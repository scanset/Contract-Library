# m365_ediscovery_case

## Overview

Resource-shape reference for a Microsoft Purview eDiscovery (Premium) case discovered via `m365_graph_query` against `/security/cases/ediscoveryCases`. **Not a standalone CTN.**

eDiscovery cases are *legal-hold containers*. Each carries one or more custodians (mailboxes, OneDrive accounts, Teams chats), one or more preservation locations, and the search/export operations that have been run. For audit purposes the case-level inventory usually proves what's needed: *"the org maintains forensic-evidence containers for incident-response and litigation hold."*

**Delegated credential.** Requires `M365DelegatedRefresh` credential — Microsoft gates this endpoint to user-context auth on Business Premium / Purview Suite for BP. The app-only `azure_spn` credential cannot reach this endpoint regardless of the application permissions granted; see the delegated-bootstrap docs.

**Platform:** Microsoft Graph (v1.0)
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::EdiscoveryCase`
**Required permission:** `eDiscovery.Read.All` (delegated, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                          |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | -------------------------------- |
| `path`   | string | **Yes**  | Must be `security/cases/ediscoveryCases`.                                    | `security/cases/ediscoveryCases` |
| `filter` | string | No       | OData `$filter`. Common: `status eq 'active'`.                               | `status eq 'active'`             |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases
Authorization: Bearer <delegated_token>
ConsistencyLevel: eventual
```

**Sample response (single case):**

```json
{
  "id": "ccccccc1-cccc-cccc-cccc-cccccccccccc",
  "displayName": "FCI Contract Termination — Acme",
  "description": "Preservation hold related to FCI contract termination Q2-2026",
  "status": "active",
  "externalId": "MATTER-2026-014",
  "createdDateTime": "2026-04-08T15:33:00Z",
  "lastModifiedDateTime": "2026-05-02T11:18:23Z",
  "createdBy": {
    "user": { "id": "11111111-...", "displayName": "Curtis Slone - Global Admin" }
  },
  "lastModifiedBy": {
    "user": { "id": "11111111-...", "displayName": "Curtis Slone - Global Admin" }
  }
}
```

---

## Collected Data Fields

| Field                          | Type    | Description                                                                |
| ------------------------------ | ------- | -------------------------------------------------------------------------- |
| `rows.*.id`                    | string  | Case id.                                                                   |
| `rows.*.displayName`           | string  | Case display name.                                                         |
| `rows.*.description`           | string  | Operator-provided description.                                             |
| `rows.*.status`                | string  | `active`, `closed`, `closing`, `reopening`.                                |
| `rows.*.externalId`            | string  | Org-defined external id (matter id, ticket id).                            |
| `rows.*.createdDateTime`       | string  | ISO-8601.                                                                  |
| `rows.*.lastModifiedDateTime`  | string  | ISO-8601.                                                                  |
| `rows.*.createdBy`             | object  | Nested `{user: {id, displayName}}` — verbatim.                             |
| `rows.*.lastModifiedBy`        | object  | Nested `{user: {id, displayName}}` — verbatim.                             |

---


## ESP Example

### Active eDiscovery cases must have an external_id (links to ticketing/matter system)

```esp
OBJECT active_cases
    path `security/cases/ediscoveryCases`
    filter `status eq 'active'`
OBJECT_END

STATE has_external_id
    found boolean = true
    record
        field rows.*.externalId string != ``
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_external_id
    OBJECT_REF active_cases
CTN_END
```

---

## Caveats

- **Premium feature.** Standard (non-Premium) eDiscovery cases use a different endpoint (`/compliance/ediscovery/cases` legacy). This collector targets Premium only.
- **Custodians / holds / searches are nested sub-resources** of each case. Discovering them would be Phase 9 work — separate GraphPaths against `/security/cases/ediscoveryCases/{id}/custodians`, etc.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Sibling delegated resources: [`m365_retention_label`](../m365_retention_label/m365_retention_label.md), [`m365_audit_log_query`](../m365_audit_log_query/m365_audit_log_query.md)
