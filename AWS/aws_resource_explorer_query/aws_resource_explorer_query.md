# aws_resource_explorer_query

## Overview

Single-CTN discovery primitive: posts a Search query to AWS Resource Explorer and returns the matched resources as a flat array. Mirrors the `az_resource_graph_query` shape — one query, server-side fan-out across regions and services, orders-of-magnitude fewer round-trips than per-service describe-* sweeps. Typically used by a discovery orchestrator for the bulk-asset-listing step before per-resource enrichment CTNs (like `aws_ec2_describe_instances`) fill in details.

**Platform:** AWS (requires `aws` CLI binary with `resource-explorer-2:Search` permission)
**Collection Method:** Single AWS CLI call via `AwsClient.resource_explorer_search()`, paginated server-side

**Note:** A wildcard sweep against an account with 5K resources runs ~2-4s including pagination. Discovery wraps this in a 60s overall timeout. Resource Explorer must be set up in the account first — the CTN won't auto-create indexes or views.

---

## Object Fields

| Field      | Type   | Required | Description                                                                                              | Example                                                        |
| ---------- | ------ | -------- | -------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `query`    | string | No       | Resource Explorer filter string. Empty / unset = match every resource the aggregator index has indexed   | `""`, `resourcetype:ec2:instance`, `region:us-east-1 service:s3` |
| `view_arn` | string | No       | ARN of a specific Resource Explorer view. Omit to use the region's default view                          | `arn:aws:resource-explorer-2:us-east-1:123456789012:view/...`   |

See https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html for full filter grammar.

---

## Commands Executed

### Command 1: resource-explorer-2 search

Posts a Search query and follows pagination until exhausted.

**Collector call:** `client.resource_explorer_search(query, view_arn)`

**Resulting commands:**

```
# Wildcard sweep (default view in resolved region)
aws resource-explorer-2 search --query-string ""

# Filter by resource type
aws resource-explorer-2 search --query-string "resourcetype:ec2:instance"

# Compound filter
aws resource-explorer-2 search --query-string "region:us-east-1 service:s3"

# With explicit view
aws resource-explorer-2 search \
    --query-string "" \
    --view-arn arn:aws:resource-explorer-2:us-east-1:123456789012:view/us-east-1/abc
```

**Sample response:**

```json
{
  "Resources": [
    {
      "Arn": "arn:aws:ec2:us-east-1:486027077516:instance/i-0abc1234",
      "ResourceType": "ec2:instance",
      "Region": "us-east-1",
      "OwningAccountId": "486027077516",
      "LastReportedAt": "2026-05-03T07:10:00Z",
      "Properties": [
        { "Name": "tags", "Data": [{"Key":"Name","Value":"prod-workload"}] }
      ]
    }
  ],
  "ViewArn": "arn:aws:resource-explorer-2:us-east-1:486027077516:view/all-resources/abc",
  "Count": { "TotalResources": 1, "Complete": true }
}
```

**Response parsing:**

- `Resources[*]` flattened across pagination into the `rows` array.
- Per-row fields: `arn`, `resource_type`, `region`, `owning_account_id`, `last_reported_at`.
- `Resources[*].Properties[]` flattened into row keys (default property: `tags`).
- `Resources.length` (post-pagination) → `row_count`.

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                                  |
| ----------- | ------- | -------------- | --------------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if Search succeeded    |
| `row_count` | int     | Yes            | `Resources.length` post-pagination      |

### RecordData Field

| Field  | Type       | Always Present | Description                                                  |
| ------ | ---------- | -------------- | ------------------------------------------------------------ |
| `rows` | RecordData | Yes            | Array of per-resource objects. Empty `[]` when none matched  |

---

## RecordData Structure

| Path                            | Type   | Example Value                                            |
| ------------------------------- | ------ | -------------------------------------------------------- |
| `rows.*.arn`                    | string | `"arn:aws:ec2:us-east-1:486027077516:instance/i-0abc1234"` |
| `rows.*.resource_type`          | string | `"ec2:instance"`                                         |
| `rows.*.region`                 | string | `"us-east-1"`                                            |
| `rows.*.owning_account_id`      | string | `"486027077516"`                                         |
| `rows.*.last_reported_at`       | string | `"2026-05-03T07:10:00Z"`                                 |
| `rows.*.tags`                   | object | `{"Name": "prod-workload"}` (when view includes tags)    |

---

## State Fields

| State Field | Type       | Allowed Operations              | Maps To Collected Field |
| ----------- | ---------- | ------------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                       | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`             |
| `rows`      | RecordData | (record checks)                 | `rows`                  |

---

## Collection Strategy

| Property                     | Value                                          |
| ---------------------------- | ---------------------------------------------- |
| Collector ID                 | `aws_resource_explorer_query_collector`        |
| Collector Type               | `aws_resource_explorer_query`                  |
| Collection Mode              | Metadata                                       |
| Required Capabilities        | `aws_credentials_env`, `resource_explorer_reader` |
| Expected Collection Time     | ~1000ms (varies — wildcard ~2-4s for 5K resources) |
| Memory Usage                 | ~8MB                                           |
| Network Intensive            | Yes                                            |
| CPU Intensive                | No                                             |
| Requires Elevated Privileges | No                                             |
| Batch Collection             | No                                             |

### Required Permissions

```json
{
  "Effect": "Allow",
  "Action": ["resource-explorer-2:Search", "resource-explorer-2:ListViews"],
  "Resource": "*"
}
```

Resource Explorer also requires an aggregator index in at least one region and a view that AssertCommand can use. See AWS docs for setup.

---

## ESP Examples

### Bulk-list every resource in the account

```esp
OBJECT account_wide_inventory
    query ``
OBJECT_END

STATE has_resources
    found boolean = true
    row_count int > `0`
STATE_END

CTN aws_resource_explorer_query
    TEST all all AND
    STATE_REF has_resources
    OBJECT_REF account_wide_inventory
CTN_END
```

### Verify all S3 buckets are in expected regions

```esp
OBJECT all_s3_buckets
    query `service:s3`
OBJECT_END

STATE only_in_approved_regions
    found boolean = true
    record
        field rows.*.region string = `us-east-1`
    record_end
STATE_END

CTN aws_resource_explorer_query
    TEST all all AND
    STATE_REF only_in_approved_regions
    OBJECT_REF all_s3_buckets
CTN_END
```

### Use a specific view for restricted scope

```esp
OBJECT scoped_inventory
    query `resourcetype:ec2:instance`
    view_arn `arn:aws:resource-explorer-2:us-east-1:486027077516:view/prod-only/abc`
OBJECT_END

STATE prod_instances_present
    found boolean = true
    row_count int >= `3`
STATE_END

CTN aws_resource_explorer_query
    TEST all all AND
    STATE_REF prod_instances_present
    OBJECT_REF scoped_inventory
CTN_END
```

---

## Error Conditions

| Condition                                                | Error Type              | Outcome                          |
| -------------------------------------------------------- | ----------------------- | -------------------------------- |
| No aggregator index set up in the account                | `CollectionFailed`      | Error                            |
| `view_arn` references a view the principal can't access  | `CollectionFailed`      | Error                            |
| Invalid query syntax                                     | `CollectionFailed`      | Error                            |
| Empty result (valid query, no matches)                   | N/A (not an error)      | `found=true`, `row_count=0`      |
| Pagination exceeds 60s timeout                           | `CollectionFailed`      | Error                            |
| Incompatible CTN type                                    | `CtnContractValidation` | Error                            |

---

## Related CTN Types

| CTN Type                         | Relationship                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| `aws_ec2_describe_instances`     | Downstream enrichment — gives EC2-specific fields Resource Explorer doesn't carry           |
| `aws_ec2_describe_images`        | Downstream enrichment for the AMI IDs found via instance enrichment                         |
| `az_resource_graph_query`        | Azure analogue — same single-query bulk discovery shape                                     |
