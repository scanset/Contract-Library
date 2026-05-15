# az_resource_graph_query

## Overview

Single-CTN discovery primitive: posts a KQL query to Azure Resource Graph and returns the result rows as a flat array. Replaces the per-resource-type `az_*_list` discovery contracts — one query, server-side joins, orders-of-magnitude fewer round-trips at scale. Typically used by a discovery orchestrator for bulk-asset-listing before per-resource enrichment CTNs fill in details.

**Platform:** Azure (requires `az` CLI binary or Azure SDK with `Microsoft.ResourceGraph/resources/read` permission)
**Collection Method:** Single Azure REST POST via `AzClient.resource_graph_query()`, paginated server-side

**Note:** A complex multi-join query against a 10K-resource tenant can run 1-3s and pagination adds ~200ms per extra page. Discovery wraps this in a 60s overall HTTP timeout.

---

## Object Fields

| Field           | Type   | Required | Description                                                                                | Example                                          |
| --------------- | ------ | -------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `query`         | string | **Yes**  | KQL query string. Posted as-is to `/providers/Microsoft.ResourceGraph/resources`.          | `Resources \| project id, name, type, location` |
| `subscriptions` | string | No       | Comma-separated subscription IDs to narrow to. Empty / unset = sweep every subscription the SPN can read | `00000000-0000-0000-0000-000000000000`           |

The query MUST use Resource Graph's KQL dialect and produce an objectArray result format — each row in the response is a flat JSON object whose keys come from the KQL `project` clause.

---

## Commands Executed

### Command 1: POST /providers/Microsoft.ResourceGraph/resources

Posts the KQL query and follows pagination tokens server-side until exhausted.

**Collector call:** `client.resource_graph_query(query, subscriptions)`

**Resulting command** (representative — actual call goes through Azure SDK / REST):

```
az graph query \
    --graph-query "Resources | project id, name, type, location" \
    --first 1000

# With subscription filter
az graph query \
    --graph-query "Resources | project id, name, type, location" \
    --subscriptions 00000000-0000-0000-0000-000000000000
```

**Sample response (REST shape):**

```json
{
  "totalRecords": 42,
  "count": 42,
  "data": [
    {
      "id": "/subscriptions/.../resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/foo",
      "name": "foo",
      "type": "microsoft.storage/storageaccounts",
      "location": "eastus2"
    }
  ],
  "resultTruncated": "false",
  "$skipToken": null
}
```

**Response parsing:**

- `data[*]` flattened across pagination into the `rows` array.
- Each row is a flat object whose keys come from the KQL `project` clause.
- `data.length` post-pagination → `row_count`.
- HTTP 2xx + valid JSON → `found=true`. Empty result still counts as "found" (just `row_count=0`).

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                                  |
| ----------- | ------- | -------------- | --------------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if query executed and parsed |
| `row_count` | int     | Yes            | `data.length` post-pagination           |

### RecordData Field

| Field  | Type       | Always Present | Description                                                  |
| ------ | ---------- | -------------- | ------------------------------------------------------------ |
| `rows` | RecordData | Yes            | Array of objects keyed by KQL `project` columns. Empty `[]` when no match |

---

## RecordData Structure

Path shape depends entirely on the KQL `project` clause. Common patterns:

| KQL projection                                                                       | Resulting `rows.*.X` keys                          |
| ------------------------------------------------------------------------------------ | -------------------------------------------------- |
| `project id, name, type, location`                                                  | `id`, `name`, `type`, `location`                   |
| `project id, properties.publicNetworkAccess, properties.minimumTlsVersion`         | `id`, `properties_publicNetworkAccess`, `properties_minimumTlsVersion` (Resource Graph flattens `.` to `_`) |
| `project id, tags["env"]`                                                           | `id`, `tags_env`                                   |

---

## State Fields

| State Field | Type       | Allowed Operations              | Maps To Collected Field |
| ----------- | ---------- | ------------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                       | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`             |
| `rows`      | RecordData | (record checks)                 | `rows`                  |

---

## Collection Strategy

| Property                     | Value                                   |
| ---------------------------- | --------------------------------------- |
| Collector ID                 | `az_resource_graph_query_collector`     |
| Collector Type               | `az_resource_graph_query`               |
| Collection Mode              | Metadata                                |
| Required Capabilities        | `azure_spn_env`, `resource_graph_reader` |
| Expected Collection Time     | ~800ms (single page typical; 1-3s for complex multi-join) |
| Memory Usage                 | ~8MB                                    |
| Network Intensive            | Yes                                     |
| CPU Intensive                | No                                      |
| Requires Elevated Privileges | No                                      |
| Batch Collection             | No                                      |

### Required Permissions

Azure RBAC: the SPN needs `Reader` (or `Microsoft.ResourceGraph/resources/read` action) at the scope the query covers.

---

## ESP Examples

### Bulk-list every storage account in the tenant

```esp
OBJECT all_storage_accounts
    query `Resources | where type =~ 'microsoft.storage/storageaccounts' | project id, name, location`
OBJECT_END

STATE has_storage
    found boolean = true
    row_count int > `0`
STATE_END

CTN az_resource_graph_query
    TEST all all AND
    STATE_REF has_storage
    OBJECT_REF all_storage_accounts
CTN_END
```

### Validate every storage account is in approved regions

```esp
OBJECT regional_storage_check
    query `Resources | where type =~ 'microsoft.storage/storageaccounts' | project id, name, location`
OBJECT_END

STATE only_approved_regions
    found boolean = true
    record
        field rows.*.location string = `eastus2`
    record_end
STATE_END

CTN az_resource_graph_query
    TEST all all AND
    STATE_REF only_approved_regions
    OBJECT_REF regional_storage_check
CTN_END
```

### Limit to a specific subscription

```esp
OBJECT prod_subscription_resources
    query `Resources | summarize count() by type`
    subscriptions `00000000-0000-0000-0000-000000000000`
OBJECT_END

STATE prod_has_resources
    found boolean = true
    row_count int >= `1`
STATE_END

CTN az_resource_graph_query
    TEST all all AND
    STATE_REF prod_has_resources
    OBJECT_REF prod_subscription_resources
CTN_END
```

---

## Error Conditions

| Condition                                            | Error Type              | Outcome                          |
| ---------------------------------------------------- | ----------------------- | -------------------------------- |
| `query` missing                                      | `InvalidObjectConfiguration` | Error                       |
| KQL syntax error                                     | `CollectionFailed`      | Error                            |
| Permission denied (SPN lacks Reader on scope)        | `CollectionFailed`      | Error                            |
| Empty result (valid query, no matches)               | N/A (not an error)      | `found=true`, `row_count=0`      |
| Pagination timeout (60s)                             | `CollectionFailed`      | Error                            |
| Query result truncated (>1000 rows + no pagination)  | N/A — pagination handles | All rows fetched                |
| Incompatible CTN type                                | `CtnContractValidation` | Error                            |

---

## Related CTN Types

| CTN Type                          | Relationship                                                                                |
| --------------------------------- | ------------------------------------------------------------------------------------------- |
| `aws_resource_explorer_query`     | AWS analogue — same single-query bulk discovery shape                                       |
| `az_storage_account`, `az_key_vault`, etc. | Per-resource-type enrichment CTNs — use this for bulk discovery, then those for detail |
| `az_role_assignment`              | RBAC sibling — Resource Graph can return assignment IDs for bulk lookup                     |
