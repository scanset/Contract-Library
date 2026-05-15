# m365_retention_event_type

## Overview

Resource-shape reference for a Purview *retention event type* discovered via `m365_graph_query` against `/security/triggerTypes/retentionEventTypes` (beta). **Not a standalone CTN.**

A retention event type is a *named trigger category* that retention labels listen for. The typical pattern:

1. Admin defines an event type: e.g. `"FCI Contract End"` or `"Employee Termination"`.
2. Admin configures retention labels in "Trigger by event" mode pointing at that event type.
3. Later, an operator reports a concrete *retention event* of that type (covered by sibling [`m365_retention_event`](../m365_retention_event/m365_retention_event.md)).
4. The label's retention clock starts ticking on every piece of content carrying that label.

Discovering the event types is the *catalog* side — what event categories does the tenant know how to receive? Pairs with retention events (instances) and retention labels (the consumers).

**Delegated credential.** Requires `M365DelegatedRefresh`. The endpoint is Exchange-backed records-management surface, app-only auth doesn't reach it.

**Platform:** Microsoft Graph (beta)
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::RetentionEventType`
**Required permission:** `RecordsManagement.Read.All` (delegated, admin consent — same scope as retention labels)

---

## Object Fields

| Field         | Type   | Required | Description                                                                  | Example                                       |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------- | --------------------------------------------- |
| `path`        | string | **Yes**  | Must be `security/triggerTypes/retentionEventTypes`.                         | `security/triggerTypes/retentionEventTypes`   |
| `api_version` | string | **Yes**  | Must be `beta` — not in v1.0.                                                | `beta`                                        |
| `top`         | int    | **Yes**  | Must be `0` — this beta endpoint rejects `$top`. Discoverer passes 0 automatically. | `0`                                           |

---

## Commands Executed

```
GET https://graph.microsoft.com/beta/security/triggerTypes/retentionEventTypes
Authorization: Bearer <delegated_token>
```

**Sample response (single event type):**

```json
{
  "id": "ee111111-eeee-eeee-eeee-eeeeeeeeeeee",
  "displayName": "FCI Contract End",
  "description": "Triggers retention on FCI records when a contract closes",
  "createdDateTime": "2026-02-14T18:00:00Z",
  "lastModifiedDateTime": "2026-04-08T11:20:00Z",
  "createdBy": {
    "user": { "id": "11111111-...", "displayName": "Curtis Slone - Global Admin" }
  }
}
```

---

## Collected Data Fields

| Field                              | Type   | Description                                                              |
| ---------------------------------- | ------ | ------------------------------------------------------------------------ |
| `rows.*.id`                        | string | Event type id.                                                           |
| `rows.*.displayName`               | string | Admin-facing name.                                                       |
| `rows.*.description`               | string | Description.                                                             |
| `rows.*.createdDateTime`           | string | ISO-8601.                                                                |
| `rows.*.lastModifiedDateTime`      | string | ISO-8601.                                                                |
| `rows.*.createdBy`                 | object | `{user: {id, displayName}}` verbatim.                                    |

---


## ESP Example

### FCI Contract End event type must exist

```esp
OBJECT event_types
    path `security/triggerTypes/retentionEventTypes`
    api_version `beta`
OBJECT_END

STATE has_fci_contract_end
    found boolean = true
    record
        field rows.*.displayName string = `FCI Contract End` at_least_one
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_fci_contract_end
    OBJECT_REF event_types
CTN_END
```

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Companion (instances): [`m365_retention_event`](../m365_retention_event/m365_retention_event.md)
- Consumer (labels that listen): [`m365_retention_label`](../m365_retention_label/m365_retention_label.md)
