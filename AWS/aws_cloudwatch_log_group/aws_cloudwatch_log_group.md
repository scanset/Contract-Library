# aws_cloudwatch_log_group

## Overview

Validates AWS CloudWatch log group configuration via the AWS CLI. Makes a single API call using `describe-log-groups` with a name prefix filter to locate and validate the target log group.

**Platform:** AWS (requires `aws` CLI binary with CloudWatch Logs read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

---

## Object Fields

| Field            | Type   | Required | Description                                      | Example                              |
| ---------------- | ------ | -------- | ------------------------------------------------ | ------------------------------------ |
| `log_group_name` | string | **Yes**  | Log group name (used as exact prefix for lookup) | `/example-org/security/findings` |
| `region`         | string | No       | AWS region override (passed as `--region`)       | `us-east-1`                          |

- `log_group_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- The collector uses `--log-group-name-prefix` with the full name, then matches the first result where `logGroupName` equals the provided value exactly.
- If no exact match is found, `found` is set to `false`.

---

## Commands Executed

### Command 1: describe-log-groups

**Collector call:** `client.execute("logs", "describe-log-groups", &["--log-group-name-prefix", log_group_name])`

**Resulting command:**

```
aws logs describe-log-groups --log-group-name-prefix /example-org/security/findings --output json
```

**Sample response:**

```json
{
  "logGroups": [
    {
      "logGroupName": "/example-org/security/findings",
      "creationTime": 1774368167576,
      "retentionInDays": 365,
      "metricFilterCount": 0,
      "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings:*",
      "storedBytes": 304155,
      "logGroupClass": "STANDARD",
      "logGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings",
      "deletionProtectionEnabled": false
    }
  ]
}
```

**Response parsing:**

- Find first entry where `logGroupName == log_group_name` (exact match)
- `logGroupName` → `log_group_name` scalar
- `retentionInDays` → `retention_in_days` scalar (integer)
- `logGroupClass` → `log_group_class` scalar
- `logGroupArn` → `log_group_arn` scalar (without the `:*` suffix from `arn`)
- `storedBytes` → `stored_bytes` scalar (integer)
- `deletionProtectionEnabled` → `deletion_protection_enabled` scalar (boolean)
- `metricFilterCount` → `metric_filter_count` scalar (integer)

---

### Error Detection

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| Anything else                                | `AwsError::CommandFailed`    |

No log groups matching the prefix returns an empty `logGroups` array — collector sets `found = false`.

---

## Collected Data Fields

### Scalar Fields

| Field                         | Type    | Always Present | Source                                                |
| ----------------------------- | ------- | -------------- | ----------------------------------------------------- |
| `found`                       | boolean | Yes            | Derived — `true` if exact log group name match found  |
| `log_group_name`              | string  | When found     | `logGroupName`                                        |
| `log_group_arn`               | string  | When found     | `logGroupArn` (without `:*` suffix)                   |
| `retention_in_days`           | integer | When found     | `retentionInDays` (absent if no retention policy set) |
| `log_group_class`             | string  | When found     | `logGroupClass`                                       |
| `stored_bytes`                | integer | When found     | `storedBytes`                                         |
| `deletion_protection_enabled` | boolean | When found     | `deletionProtectionEnabled`                           |
| `metric_filter_count`         | integer | When found     | `metricFilterCount`                                   |

### RecordData Field

| Field      | Type       | Always Present | Description                                      |
| ---------- | ---------- | -------------- | ------------------------------------------------ |
| `resource` | RecordData | Yes            | Full log group object. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the full log group object from the API response.

| Path                        | Type    | Example Value                                                                        |
| --------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `logGroupName`              | string  | `"/example-org/security/findings"`                                               |
| `logGroupArn`               | string  | `"arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings"` |
| `retentionInDays`           | integer | `365`                                                                                |
| `logGroupClass`             | string  | `"STANDARD"`                                                                         |
| `storedBytes`               | integer | `304155`                                                                             |
| `deletionProtectionEnabled` | boolean | `false`                                                                              |
| `metricFilterCount`         | integer | `0`                                                                                  |

---

## State Fields

### Scalar State Fields

| State Field                   | Type    | Allowed Operations              | Maps To Collected Field       |
| ----------------------------- | ------- | ------------------------------- | ----------------------------- |
| `found`                       | boolean | `=`, `!=`                       | `found`                       |
| `log_group_name`              | string  | `=`, `!=`, `contains`, `starts` | `log_group_name`              |
| `log_group_arn`               | string  | `=`, `!=`, `contains`, `starts` | `log_group_arn`               |
| `retention_in_days`           | int     | `=`, `!=`, `>=`, `>`            | `retention_in_days`           |
| `log_group_class`             | string  | `=`, `!=`                       | `log_group_class`             |
| `stored_bytes`                | int     | `=`, `!=`, `>=`, `>`            | `stored_bytes`                |
| `deletion_protection_enabled` | boolean | `=`, `!=`                       | `deletion_protection_enabled` |
| `metric_filter_count`         | int     | `=`, `!=`, `>=`, `>`            | `metric_filter_count`         |

### Record Checks

| State Field | Maps To Collected Field | Description                              |
| ----------- | ----------------------- | ---------------------------------------- |
| `record`    | `resource`              | Deep inspection of full log group object |

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `aws_cloudwatch_log_group_collector` |
| Collector Type               | `aws_cloudwatch_log_group`           |
| Collection Mode              | Metadata                             |
| Required Capabilities        | `aws_cli`, `cloudwatch_logs_read`    |
| Expected Collection Time     | ~1500ms                              |
| Memory Usage                 | ~2MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["logs:DescribeLogGroups"],
  "Resource": "*"
}
```

---

## ESP Examples

### Security findings log group with 365-day retention

```esp
OBJECT security_log_group
    log_group_name `/example-org/security/findings`
    region `us-east-1`
OBJECT_END

STATE log_group_compliant
    found boolean = true
    retention_in_days int >= 365
    log_group_class string = `STANDARD`
STATE_END

CTN aws_cloudwatch_log_group
    TEST all all AND
    STATE_REF log_group_compliant
    OBJECT_REF security_log_group
CTN_END
```

---

## Error Conditions

| Condition                            | Error Type                   | Outcome       | Notes                                                        |
| ------------------------------------ | ---------------------------- | ------------- | ------------------------------------------------------------ |
| Log group not found                  | N/A (not an error)           | `found=false` | Empty `logGroups` array or no exact name match               |
| `log_group_name` missing from object | `InvalidObjectConfiguration` | Error         | Required field                                               |
| `aws` CLI binary not found           | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                         |
| IAM access denied                    | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`        |
| Incompatible CTN type                | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_cloudwatch_log_group"` |

---

## Related CTN Types

| CTN Type                    | Relationship                                                   |
| --------------------------- | -------------------------------------------------------------- |
| `aws_cloudwatch_event_rule` | EventBridge rules target this log group for findings delivery  |
| `aws_guardduty_detector`    | GuardDuty findings routed to this log group via EventBridge    |
| `aws_securityhub_account`   | Security Hub findings routed to this log group via EventBridge |
