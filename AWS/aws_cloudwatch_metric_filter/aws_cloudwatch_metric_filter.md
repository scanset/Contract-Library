# aws_cloudwatch_metric_filter

## Overview

Validates AWS CloudWatch metric filter configuration via a single AWS CLI call using `describe-metric-filters`. Both `filter_name` and `log_group_name` are required. The collector uses `--filter-name-prefix` for the API call and applies an exact match on `filterName` in the results.

**Platform:** AWS (requires `aws` CLI binary with CloudWatch Logs read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

---

## Object Fields

| Field            | Type   | Required | Description                                | Example                       |
| ---------------- | ------ | -------- | ------------------------------------------ | ----------------------------- |
| `filter_name`    | string | **Yes**  | Metric filter name (exact match)           | `example-org-root-login`  |
| `log_group_name` | string | **Yes**  | Log group the filter is attached to        | `/example-org/cloudtrail` |
| `region`         | string | No       | AWS region override (passed as `--region`) | `us-east-1`                   |

---

## Commands Executed

### Command 1: describe-metric-filters

```
aws logs describe-metric-filters \
  --log-group-name /example-org/cloudtrail \
  --filter-name-prefix example-org-root-login \
  --output json
```

The collector then applies an exact match on `filterName == filter_name` from the results.

**Sample response:**

```json
{
  "metricFilters": [
    {
      "filterName": "example-org-root-login",
      "filterPattern": "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }",
      "metricTransformations": [
        {
          "metricName": "RootLoginCount",
          "metricNamespace": "ExampleOrg/Security",
          "metricValue": "1",
          "unit": "None"
        }
      ],
      "creationTime": 1774369676964,
      "logGroupName": "/example-org/cloudtrail",
      "applyOnTransformedLogs": false
    }
  ]
}
```

---

## Collected Data Fields

### Scalar Fields

| Field              | Type    | Always Present | Source                                      |
| ------------------ | ------- | -------------- | ------------------------------------------- |
| `found`            | boolean | Yes            | Derived — `true` if exact filter name match |
| `filter_name`      | string  | When found     | `filterName`                                |
| `log_group_name`   | string  | When found     | `logGroupName`                              |
| `filter_pattern`   | string  | When found     | `filterPattern`                             |
| `metric_name`      | string  | When found     | `metricTransformations[0].metricName`       |
| `metric_namespace` | string  | When found     | `metricTransformations[0].metricNamespace`  |

### RecordData Field

| Field      | Type       | Always Present | Description                                   |
| ---------- | ---------- | -------------- | --------------------------------------------- |
| `resource` | RecordData | Yes            | Full filter object. Empty `{}` when not found |

---

## RecordData Structure

```
filterName                                → "example-org-root-login"
logGroupName                              → "/example-org/cloudtrail"
filterPattern                             → "{ $.userIdentity.type = \"Root\" ... }"
metricTransformations.0.metricName        → "RootLoginCount"
metricTransformations.0.metricNamespace   → "ExampleOrg/Security"
metricTransformations.0.metricValue       → "1"
applyOnTransformedLogs                    → false
```

---

## State Fields

| State Field        | Type       | Allowed Operations              | Maps To Collected Field |
| ------------------ | ---------- | ------------------------------- | ----------------------- |
| `found`            | boolean    | `=`, `!=`                       | `found`                 |
| `filter_name`      | string     | `=`, `!=`                       | `filter_name`           |
| `log_group_name`   | string     | `=`, `!=`                       | `log_group_name`        |
| `filter_pattern`   | string     | `=`, `!=`, `contains`, `starts` | `filter_pattern`        |
| `metric_name`      | string     | `=`, `!=`                       | `metric_name`           |
| `metric_namespace` | string     | `=`, `!=`                       | `metric_namespace`      |
| `record`           | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                 | Value                                    |
| ------------------------ | ---------------------------------------- |
| Collector ID             | `aws_cloudwatch_metric_filter_collector` |
| Collector Type           | `aws_cloudwatch_metric_filter`           |
| Collection Mode          | Metadata                                 |
| Required Capabilities    | `aws_cli`, `cloudwatch_logs_read`        |
| Expected Collection Time | ~1500ms                                  |
| Memory Usage             | ~2MB                                     |
| Batch Collection         | No                                       |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["logs:DescribeMetricFilters"],
  "Resource": "*"
}
```

---

## ESP Examples

### Root login metric filter exists (KSI-MLA-OSM, KSI-CMT-LMC)

```esp
OBJECT root_login_filter
    filter_name `example-org-root-login`
    log_group_name `/example-org/cloudtrail`
    region `us-east-1`
OBJECT_END

STATE filter_compliant
    found boolean = true
    metric_name string = `RootLoginCount`
    metric_namespace string = `ExampleOrg/Security`
STATE_END

CTN aws_cloudwatch_metric_filter
    TEST all all AND
    STATE_REF filter_compliant
    OBJECT_REF root_login_filter
CTN_END
```

---

## Error Conditions

| Condition                            | Error Type                   | Outcome       |
| ------------------------------------ | ---------------------------- | ------------- |
| Filter not found                     | N/A (not an error)           | `found=false` |
| `filter_name` missing from object    | `InvalidObjectConfiguration` | Error         |
| `log_group_name` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied                    | `CollectionFailed`           | Error         |
| Incompatible CTN type                | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                      | Relationship                                               |
| ----------------------------- | ---------------------------------------------------------- |
| `aws_cloudwatch_metric_alarm` | Alarms fire based on metrics produced by these filters     |
| `aws_cloudwatch_log_group`    | Filters are attached to log groups                         |
| `aws_cloudtrail`              | CloudTrail delivers logs to the group this filter monitors |
