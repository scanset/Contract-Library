# m365_audit_log_query

## Overview

Resource-shape reference for a saved Microsoft Purview audit-log search query discovered via `m365_graph_query` against `/security/auditLog/queries` (beta). **Not a standalone CTN.**

**Important: these are search-query DEFINITIONS, not audit-log entries themselves.** Each row represents a *saved or in-flight search* — its filter parameters, status, and operator. The actual audit-log data lives in the Unified Audit Log and is accessed via a separate flow (PowerShell `Search-UnifiedAuditLog` or the auditEvents Graph endpoints, neither of which is in scope here).

The audit value: when an org demonstrates AU-2 / AU-12 control implementation, "we have standing search queries that monitor for X, Y, Z event classes" is much stronger evidence than "we have a query box we could use to search." This collector inventories the standing queries.

**Delegated credential.** Requires `M365DelegatedRefresh`.

**Platform:** Microsoft Graph (beta)
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::AuditLogQuery`
**Required permission:** `AuditLogsQuery.Read.All` (delegated, admin consent)

---

## Object Fields

| Field         | Type   | Required | Description                                                                  | Example                       |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------- | ----------------------------- |
| `path`        | string | **Yes**  | Must be `security/auditLog/queries`.                                         | `security/auditLog/queries`   |
| `api_version` | string | **Yes**  | Must be `beta` — not in v1.0.                                                | `beta`                        |
| `top`         | int    | **Yes**  | Must be `0` — this beta endpoint rejects `$top`. The discoverer passes 0 automatically. | `0`                           |

---

## Commands Executed

```
GET https://graph.microsoft.com/beta/security/auditLog/queries
Authorization: Bearer <delegated_token>
```

**Sample response (single query):**

```json
{
  "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "displayName": "Weekly admin role-change audit",
  "filterStartDateTime": "2026-04-29T00:00:00Z",
  "filterEndDateTime": "2026-05-06T00:00:00Z",
  "recordTypeFilters": ["AzureActiveDirectoryRoleAdded", "AzureActiveDirectoryRoleRemoved"],
  "operationFilters": [],
  "userPrincipalNameFilters": [],
  "ipAddressFilters": [],
  "servicePrincipalIdFilters": [],
  "objectIdFilters": [],
  "administrativeUnitIdFilters": [],
  "status": "succeeded",
  "createdDateTime": "2026-04-29T08:00:00Z"
}
```

---

## Collected Data Fields

| Field                                       | Type    | Description                                                                              |
| ------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                 | string  | Query id.                                                                                |
| `rows.*.displayName`                        | string  | Operator-provided display name.                                                          |
| `rows.*.status`                             | string  | `notStarted` \| `running` \| `succeeded` \| `failed` \| `cancelled`.                     |
| `rows.*.filterStartDateTime`                | string  | ISO-8601 — query's start window.                                                         |
| `rows.*.filterEndDateTime`                  | string  | ISO-8601 — query's end window.                                                           |
| `rows.*.recordTypeFilters`                  | array   | Record types being matched (e.g. `AzureActiveDirectoryRoleAdded`).                       |
| `rows.*.operationFilters`                   | array   | Specific operations.                                                                     |
| `rows.*.userPrincipalNameFilters`           | array   | UPN allowlist for matched events.                                                        |
| `rows.*.ipAddressFilters`                   | array   | Source IP allowlist.                                                                     |
| `rows.*.servicePrincipalIdFilters`          | array   | SPN allowlist.                                                                           |
| `rows.*.objectIdFilters`                    | array   | Object id allowlist.                                                                     |
| `rows.*.administrativeUnitIdFilters`        | array   | AU id allowlist.                                                                         |
| `rows.*.createdDateTime`                    | string  | ISO-8601.                                                                                |

---


## ESP Example

### A query monitoring admin role changes must exist

```esp
OBJECT all_queries
    path `security/auditLog/queries`
    api_version `beta`
OBJECT_END

STATE admin_role_monitor_exists
    found boolean = true
    record
        field rows.*.recordTypeFilters string = `AzureActiveDirectoryRoleAdded` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF admin_role_monitor_exists
    OBJECT_REF all_queries
CTN_END
```

---

## Caveats

- **Beta endpoint.** Field names and shape may shift; the GA endpoint may land at a different path. Re-check the markdown alongside any apply that fails the schema.
- **One-shot vs standing queries:** the same endpoint returns BOTH one-off ad-hoc searches AND scheduled standing queries. Operators commonly filter by `displayName` pattern (e.g. policies require `name LIKE '%-MONITOR-%'`) to distinguish.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Sibling delegated resources: [`m365_retention_label`](../m365_retention_label/m365_retention_label.md), [`m365_ediscovery_case`](../m365_ediscovery_case/m365_ediscovery_case.md)
