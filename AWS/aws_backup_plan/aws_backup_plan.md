# aws_backup_plan

## Overview

Validates AWS Backup plan configuration via two AWS CLI calls. `list-backup-plans` locates the plan by name, then `get-backup-plan` retrieves the full rule set. Rule-level compliance scalars are derived in-process from the Rules array — no Python, no shell pipelines.

**Platform:** AWS (requires `aws` CLI binary with Backup read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

---

## Object Fields

| Field       | Type   | Required | Description                                         | Example                       |
| ----------- | ------ | -------- | --------------------------------------------------- | ----------------------------- |
| `plan_name` | string | **Yes**  | Backup plan name (matched against `BackupPlanName`) | `example-org-backup-plan` |
| `region`    | string | No       | AWS region override (passed as `--region`)          | `us-east-1`                   |

---

## Commands Executed

### Command 1: list-backup-plans

Lists all backup plans in the account, matched in-process by `BackupPlanName`.

**Collector call:** `client.execute("backup", "list-backup-plans", &[])`

**Resulting command:**

```
aws backup list-backup-plans --output json
```

**Sample response:**

```json
{
  "BackupPlansList": [
    {
      "BackupPlanArn": "arn:aws:backup:us-east-1:123456789012:backup-plan:cacd09f7-...",
      "BackupPlanId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "BackupPlanName": "example-org-backup-plan",
      "CreationDate": "2026-03-24T17:11:15.248000+00:00",
      "LastExecutionDate": "2026-03-26T03:00:47.134000+00:00"
    }
  ]
}
```

The collector finds the first entry where `BackupPlanName == plan_name` and extracts `BackupPlanId` for Command 2. If no match is found, `found = false`.

---

### Command 2: get-backup-plan

**Collector call:** `client.execute("backup", "get-backup-plan", &["--backup-plan-id", plan_id])`

**Resulting command:**

```
aws backup get-backup-plan --backup-plan-id a1b2c3d4-e5f6-7890-abcd-ef1234567890 --output json
```

**Sample response:**

```json
{
  "BackupPlan": {
    "BackupPlanName": "example-org-backup-plan",
    "Rules": [
      {
        "RuleName": "daily-backup",
        "ScheduleExpression": "cron(0 3 * * ? *)",
        "Lifecycle": { "DeleteAfterDays": 30 },
        "CopyActions": [
          { "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:..." }
        ]
      },
      {
        "RuleName": "weekly-backup",
        "ScheduleExpression": "cron(0 4 ? * SUN *)",
        "Lifecycle": {
          "MoveToColdStorageAfterDays": 90,
          "DeleteAfterDays": 365
        },
        "CopyActions": [
          { "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:..." }
        ]
      },
      {
        "RuleName": "monthly-backup",
        "ScheduleExpression": "cron(0 5 1 * ? *)",
        "Lifecycle": {
          "MoveToColdStorageAfterDays": 30,
          "DeleteAfterDays": 2555
        },
        "CopyActions": [
          { "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:..." }
        ]
      }
    ]
  },
  "BackupPlanId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "BackupPlanArn": "arn:aws:backup:us-east-1:123456789012:backup-plan:cacd09f7-..."
}
```

**Derived scalars from Rules array:**

| Scalar Field            | Derivation Logic                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `rule_count`            | Total number of entries in `Rules`                                                 |
| `has_daily_rule`        | Any rule with `ScheduleExpression` matching a daily pattern (no day-of-week token) |
| `has_weekly_rule`       | Any rule with `ScheduleExpression` containing `SUN`, `MON`, `TUE`, etc.            |
| `has_monthly_rule`      | Any rule with `ScheduleExpression` containing day-of-month `1 * ?`                 |
| `has_cross_region_copy` | Any rule where `CopyActions` array is non-empty                                    |
| `max_delete_after_days` | Maximum `Lifecycle.DeleteAfterDays` across all rules                               |

---

## Collected Data Fields

### Scalar Fields

| Field                   | Type    | Always Present | Source                                           |
| ----------------------- | ------- | -------------- | ------------------------------------------------ |
| `found`                 | boolean | Yes            | Derived — `true` if plan found by name           |
| `plan_name`             | string  | When found     | Object field `plan_name`                         |
| `plan_arn`              | string  | When found     | `BackupPlanArn`                                  |
| `rule_count`            | integer | When found     | Derived — count of `Rules` array entries         |
| `has_daily_rule`        | boolean | When found     | Derived — any rule with daily schedule           |
| `has_weekly_rule`       | boolean | When found     | Derived — any rule with weekly schedule          |
| `has_monthly_rule`      | boolean | When found     | Derived — any rule with monthly schedule         |
| `has_cross_region_copy` | boolean | When found     | Derived — any rule with non-empty `CopyActions`  |
| `max_delete_after_days` | integer | When found     | Derived — max `DeleteAfterDays` across all rules |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `get-backup-plan` response. Empty `{}` when not found |

---

## RecordData Structure

| Path                                                         | Type    | Example Value                    |
| ------------------------------------------------------------ | ------- | -------------------------------- |
| `BackupPlan.BackupPlanName`                                  | string  | `"example-org-backup-plan"`  |
| `BackupPlan.Rules.0.RuleName`                                | string  | `"daily-backup"`                 |
| `BackupPlan.Rules.0.ScheduleExpression`                      | string  | `"cron(0 3 * * ? *)"`            |
| `BackupPlan.Rules.0.Lifecycle.DeleteAfterDays`               | integer | `30`                             |
| `BackupPlan.Rules.0.CopyActions.0.DestinationBackupVaultArn` | string  | `"arn:aws:backup:us-west-2:..."` |
| `BackupPlan.Rules.1.RuleName`                                | string  | `"weekly-backup"`                |
| `BackupPlan.Rules.1.Lifecycle.MoveToColdStorageAfterDays`    | integer | `90`                             |
| `BackupPlan.Rules.1.Lifecycle.DeleteAfterDays`               | integer | `365`                            |
| `BackupPlan.Rules.2.RuleName`                                | string  | `"monthly-backup"`               |
| `BackupPlan.Rules.2.Lifecycle.DeleteAfterDays`               | integer | `2555`                           |

---

## State Fields

| State Field             | Type       | Allowed Operations              | Maps To Collected Field |
| ----------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`                 | boolean    | `=`, `!=`                       | `found`                 |
| `plan_name`             | string     | `=`, `!=`, `contains`, `starts` | `plan_name`             |
| `plan_arn`              | string     | `=`, `!=`, `contains`, `starts` | `plan_arn`              |
| `rule_count`            | int        | `=`, `!=`, `>=`, `>`            | `rule_count`            |
| `has_daily_rule`        | boolean    | `=`, `!=`                       | `has_daily_rule`        |
| `has_weekly_rule`       | boolean    | `=`, `!=`                       | `has_weekly_rule`       |
| `has_monthly_rule`      | boolean    | `=`, `!=`                       | `has_monthly_rule`      |
| `has_cross_region_copy` | boolean    | `=`, `!=`                       | `has_cross_region_copy` |
| `max_delete_after_days` | int        | `=`, `!=`, `>=`, `>`            | `max_delete_after_days` |
| `record`                | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_backup_plan_collector` |
| Collector Type               | `aws_backup_plan`           |
| Collection Mode              | Content                     |
| Required Capabilities        | `aws_cli`, `backup_read`    |
| Expected Collection Time     | ~2000ms (two API calls)     |
| Memory Usage                 | ~2MB                        |
| Network Intensive            | Yes                         |
| CPU Intensive                | No                          |
| Requires Elevated Privileges | No                          |
| Batch Collection             | No                          |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["backup:ListBackupPlans", "backup:GetBackupPlan"],
  "Resource": "*"
}
```

---

## ESP Examples

### Backup plan with three rule tiers and cross-region copy (KSI-RPL-ARP)

```esp
OBJECT backup_plan
    plan_name `example-org-backup-plan`
    region `us-east-1`
OBJECT_END

STATE plan_compliant
    found boolean = true
    rule_count int >= 3
    has_daily_rule boolean = true
    has_weekly_rule boolean = true
    has_monthly_rule boolean = true
    has_cross_region_copy boolean = true
    max_delete_after_days int >= 2555
STATE_END

CTN aws_backup_plan
    TEST all all AND
    STATE_REF plan_compliant
    OBJECT_REF backup_plan
CTN_END
```

### Record checks for specific rule retention values

```esp
STATE plan_retention_details
    found boolean = true
    record
        field BackupPlan.Rules.2.RuleName string = `monthly-backup`
        field BackupPlan.Rules.2.Lifecycle.DeleteAfterDays int = 2555
        field BackupPlan.Rules.0.CopyActions.0.DestinationBackupVaultArn string contains `us-west-2`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                       | Error Type                   | Outcome       |
| ------------------------------- | ---------------------------- | ------------- |
| Plan not found by name          | N/A (not an error)           | `found=false` |
| `plan_name` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied               | `CollectionFailed`           | Error         |
| Incompatible CTN type           | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type           | Relationship                                           |
| ------------------ | ------------------------------------------------------ |
| `aws_backup_vault` | Backup plans deliver recovery points to a backup vault |
| `aws_iam_role`     | Backup service role executes the backup plan           |
