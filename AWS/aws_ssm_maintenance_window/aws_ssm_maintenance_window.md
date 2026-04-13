# aws_ssm_maintenance_window

## Overview

Validates AWS SSM Maintenance Window configuration via the AWS CLI. Makes a single API call using `describe-maintenance-windows` with a `Key=Name` filter, then performs an exact name match in-process on the results.

**Platform:** AWS (requires `aws` CLI binary with SSM read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

---

## Object Fields

| Field         | Type   | Required | Description                                      | Example                       |
| ------------- | ------ | -------- | ------------------------------------------------ | ----------------------------- |
| `window_name` | string | **Yes**  | Maintenance window name (exact match via filter) | `example-org-backup-prep` |
| `region`      | string | No       | AWS region override (passed as `--region`)       | `us-east-1`                   |

- `window_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- The AWS CLI filter `Key=Name,Values=<window_name>` narrows results. An exact `Name` match is then enforced in-process since the filter may return prefix matches.

---

## Commands Executed

### Command 1: describe-maintenance-windows

**Collector call:** `client.execute("ssm", "describe-maintenance-windows", &["--filters", "Key=Name,Values=<window_name>"])`

**Resulting command:**

```
aws ssm describe-maintenance-windows --filters Key=Name,Values=example-org-backup-prep --output json
```

**Sample response:**

```json
{
  "WindowIdentities": [
    {
      "WindowId": "mw-0a4a75b49ee74fe35",
      "Name": "example-org-backup-prep",
      "Description": "Pre-backup PostgreSQL dump",
      "Enabled": true,
      "Duration": 1,
      "Cutoff": 0,
      "Schedule": "cron(0 2 * * ? *)",
      "NextExecutionTime": "2026-03-27T02:00Z"
    }
  ]
}
```

**Response parsing:**

- Find first entry where `Name == window_name` (exact match)
- `Name` → `window_name` scalar
- `WindowId` → `window_id` scalar
- `Enabled` → `enabled` scalar (boolean)
- `Duration` → `duration` scalar (integer, hours)
- `Cutoff` → `cutoff` scalar (integer, hours)
- `Schedule` → `schedule` scalar
- `Description` → `description` scalar
- Full window object stored as `resource` RecordData

If no exact match is found, `found = false`.

---

### Error Detection

| Stderr contains | Error variant             |
| --------------- | ------------------------- |
| `AccessDenied`  | `AwsError::AccessDenied`  |
| Anything else   | `AwsError::CommandFailed` |

An empty `WindowIdentities` array or no exact name match sets `found = false` — not an error.

---

## Collected Data Fields

### Scalar Fields

| Field         | Type    | Always Present | Source                               |
| ------------- | ------- | -------------- | ------------------------------------ |
| `found`       | boolean | Yes            | Derived — `true` if window found     |
| `window_name` | string  | When found     | `Name`                               |
| `window_id`   | string  | When found     | `WindowId`                           |
| `enabled`     | boolean | When found     | `Enabled`                            |
| `duration`    | integer | When found     | `Duration` (hours)                   |
| `cutoff`      | integer | When found     | `Cutoff` (hours before end)          |
| `schedule`    | string  | When found     | `Schedule` (cron or rate expression) |
| `description` | string  | When found     | `Description`                        |

### RecordData Field

| Field      | Type       | Always Present | Description                                   |
| ---------- | ---------- | -------------- | --------------------------------------------- |
| `resource` | RecordData | Yes            | Full window object. Empty `{}` when not found |

---

## RecordData Structure

| Path                | Type    | Example Value                   |
| ------------------- | ------- | ------------------------------- |
| `WindowId`          | string  | `"mw-0a4a75b49ee74fe35"`        |
| `Name`              | string  | `"example-org-backup-prep"` |
| `Enabled`           | boolean | `true`                          |
| `Duration`          | integer | `1`                             |
| `Cutoff`            | integer | `0`                             |
| `Schedule`          | string  | `"cron(0 2 * * ? *)"`           |
| `Description`       | string  | `"Pre-backup PostgreSQL dump"`  |
| `NextExecutionTime` | string  | `"2026-03-27T02:00Z"`           |

---

## State Fields

| State Field   | Type       | Allowed Operations              | Maps To Collected Field |
| ------------- | ---------- | ------------------------------- | ----------------------- |
| `found`       | boolean    | `=`, `!=`                       | `found`                 |
| `window_name` | string     | `=`, `!=`, `contains`, `starts` | `window_name`           |
| `window_id`   | string     | `=`, `!=`                       | `window_id`             |
| `enabled`     | boolean    | `=`, `!=`                       | `enabled`               |
| `duration`    | int        | `=`, `!=`, `>=`, `>`            | `duration`              |
| `cutoff`      | int        | `=`, `!=`                       | `cutoff`                |
| `schedule`    | string     | `=`, `!=`, `contains`           | `schedule`              |
| `description` | string     | `=`, `!=`, `contains`           | `description`           |
| `record`      | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                                  |
| ---------------------------- | -------------------------------------- |
| Collector ID                 | `aws_ssm_maintenance_window_collector` |
| Collector Type               | `aws_ssm_maintenance_window`           |
| Collection Mode              | Metadata                               |
| Required Capabilities        | `aws_cli`, `ssm_read`                  |
| Expected Collection Time     | ~1500ms                                |
| Memory Usage                 | ~2MB                                   |
| Network Intensive            | Yes                                    |
| CPU Intensive                | No                                     |
| Requires Elevated Privileges | No                                     |
| Batch Collection             | No                                     |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ssm:DescribeMaintenanceWindows"],
  "Resource": "*"
}
```

---

## ESP Examples

### Pre-backup maintenance window enabled and running daily (KSI-RPL-TRC)

```esp
OBJECT backup_prep_mw
    window_name `example-org-backup-prep`
    region `us-east-1`
OBJECT_END

STATE backup_prep_compliant
    found boolean = true
    enabled boolean = true
    duration int >= 1
    cutoff int = 0
STATE_END

CTN aws_ssm_maintenance_window
    TEST all all AND
    STATE_REF backup_prep_compliant
    OBJECT_REF backup_prep_mw
CTN_END
```

### Record checks for schedule inspection

```esp
STATE window_schedule_valid
    found boolean = true
    record
        field Enabled boolean = true
        field Schedule string = `cron(0 2 * * ? *)`
        field Duration int = 1
    record_end
STATE_END
```

---

## Error Conditions

| Condition                         | Error Type                   | Outcome       |
| --------------------------------- | ---------------------------- | ------------- |
| Window not found by name          | N/A (not an error)           | `found=false` |
| `window_name` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied                 | `CollectionFailed`           | Error         |
| Incompatible CTN type             | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                   | Relationship                                                      |
| -------------------------- | ----------------------------------------------------------------- |
| `aws_backup_vault`         | Maintenance window runs pre-backup dumps before the backup window |
| `aws_cloudwatch_log_group` | SSM Run Command output is delivered to a CloudWatch log group     |
