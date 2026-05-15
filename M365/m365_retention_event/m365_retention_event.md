# m365_retention_event

## Overview

Resource-shape reference for a Purview *retention event* discovered via `m365_graph_query` against `/security/triggers/retentionEvents` (beta). **Not a standalone CTN.**

A retention event is a *reported instance* of a [retention event type](../m365_retention_event_type/m365_retention_event_type.md). When an operator declares "Acme Corp contract ended on 2026-04-15" as an event of type `FCI Contract End`, every retention label listening for that event type starts its retention clock on every piece of content carrying that label.

Audit value: the events are the *forensic trail* showing the retention regime was actually exercised. "We have FCI Contract End set up" is a posture claim; "we triggered FCI Contract End for matter MATTER-2026-014 on 2026-04-15, ticking retention on N records" is evidence the control fired.

**Delegated credential.** Requires `M365DelegatedRefresh`.

**Platform:** Microsoft Graph (beta)
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::RetentionEvent`
**Required permission:** `RecordsManagement.Read.All` (delegated, admin consent)

---

## Object Fields

| Field         | Type   | Required | Description                                                                  | Example                                |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------- | -------------------------------------- |
| `path`        | string | **Yes**  | Must be `security/triggers/retentionEvents`.                                 | `security/triggers/retentionEvents`    |
| `api_version` | string | **Yes**  | Must be `beta`.                                                              | `beta`                                 |
| `top`         | int    | **Yes**  | Must be `0` — endpoint rejects `$top`. Discoverer passes automatically.      | `0`                                    |

---

## Commands Executed

```
GET https://graph.microsoft.com/beta/security/triggers/retentionEvents
Authorization: Bearer <delegated_token>
```

**Sample response (single event):**

```json
{
  "id": "fff11111-ffff-ffff-ffff-ffffffffffff",
  "displayName": "Acme Corp contract end (MATTER-2026-014)",
  "description": "FCI contract end event triggered for Acme Corp matter",
  "eventTriggerDateTime": "2026-04-15T00:00:00Z",
  "lastStatusUpdateDateTime": "2026-04-15T00:05:11Z",
  "eventQueries": [
    { "queryType": "files", "query": "filename:contract* AND (FCI OR Acme)" }
  ],
  "eventStatus": { "status": "success", "error": null },
  "createdDateTime": "2026-04-15T00:00:00Z",
  "createdBy": {
    "user": { "id": "11111111-...", "displayName": "Curtis Slone - Global Admin" }
  }
}
```

---

## Collected Data Fields

| Field                                       | Type   | Description                                                                |
| ------------------------------------------- | ------ | -------------------------------------------------------------------------- |
| `rows.*.id`                                 | string | Event id.                                                                  |
| `rows.*.displayName`                        | string | Operator-provided name (often references matter / case id).                |
| `rows.*.description`                        | string | Description.                                                               |
| `rows.*.eventTriggerDateTime`               | string | ISO-8601 — when the event was reported as having occurred.                 |
| `rows.*.lastStatusUpdateDateTime`           | string | ISO-8601 — last time the propagation status was updated.                   |
| `rows.*.eventQueries`                       | array  | `[{queryType, query}]` — KQL queries identifying which content the event targets. |
| `rows.*.eventStatus`                        | object | `{status, error}` — propagation outcome.                                   |
| `rows.*.createdDateTime`                    | string | ISO-8601.                                                                  |
| `rows.*.createdBy`                          | object | `{user: {id, displayName}}` verbatim.                                      |

---


## ESP Example

### All retention events must have successfully propagated

```esp
OBJECT events
    path `security/triggers/retentionEvents`
    api_version `beta`
OBJECT_END

STATE all_succeeded
    found boolean = true
    record
        field rows.*.eventStatus.status string = `success`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_succeeded
    OBJECT_REF events
CTN_END
```

---

## Caveats

- **Propagation lag.** An event reported "now" may take minutes-to-hours to fully propagate across Exchange / SharePoint / OneDrive. Don't gate the policy on `eventStatus.status` for very recent events; pair with an `event_trigger_date_time >= X minutes ago` filter or accept brief windows of `pending`.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Definition (type catalog): [`m365_retention_event_type`](../m365_retention_event_type/m365_retention_event_type.md)
- Listener (labels): [`m365_retention_label`](../m365_retention_label/m365_retention_label.md)
