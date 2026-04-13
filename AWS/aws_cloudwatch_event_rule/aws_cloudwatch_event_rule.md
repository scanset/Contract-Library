# aws_cloudwatch_event_rule

## Overview

Validates AWS EventBridge (CloudWatch Events) rule configuration via the AWS CLI. Makes two sequential API calls: `describe-rule` for rule state and event pattern, and `list-targets-by-rule` for delivery targets. The `EventPattern` field is a JSON-encoded string that is parsed and stored as RecordData for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with EventBridge read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

---

## Object Fields

| Field       | Type   | Required | Description                                | Example                              |
| ----------- | ------ | -------- | ------------------------------------------ | ------------------------------------ |
| `rule_name` | string | **Yes**  | EventBridge rule name (exact match)        | `example-org-guardduty-findings` |
| `region`    | string | No       | AWS region override (passed as `--region`) | `us-east-1`                          |

---

## Commands Executed

### Command 1: describe-rule

**Collector call:** `client.execute("events", "describe-rule", &["--name", rule_name])`

**Resulting command:**

```
aws events describe-rule --name example-org-guardduty-findings --output json
```

**Sample response:**

```json
{
  "Name": "example-org-guardduty-findings",
  "Arn": "arn:aws:events:us-east-1:123456789012:rule/example-org-guardduty-findings",
  "EventPattern": "{\"detail\":{\"severity\":[{\"numeric\":[\">=\",4]}]},\"detail-type\":[\"GuardDuty Finding\"],\"source\":[\"aws.guardduty\"]}",
  "State": "ENABLED",
  "Description": "Capture GuardDuty findings severity >= 4",
  "EventBusName": "default",
  "CreatedBy": "123456789012"
}
```

**Response parsing:**

- `Name` → `rule_name` scalar
- `Arn` → `rule_arn` scalar
- `State` → `state` scalar
- `Description` → `description` scalar
- `EventBusName` → `event_bus_name` scalar
- `EventPattern` (JSON string) → parsed and stored as `EventPattern` key in RecordData
- `found = false` if rule does not exist (`ResourceNotFoundException`)

---

### Command 2: list-targets-by-rule

**Collector call:** `client.execute("events", "list-targets-by-rule", &["--rule", rule_name])`

**Resulting command:**

```
aws events list-targets-by-rule --rule example-org-guardduty-findings --output json
```

**Sample response:**

```json
{
  "Targets": [
    {
      "Id": "GuardDutyFindingsToLogs",
      "Arn": "arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings"
    }
  ]
}
```

**Response parsing:**

- `target_count` → count of `Targets` array entries (integer)
- `target_arn` → `Targets[0].Arn` scalar (first target ARN)
- `target_id` → `Targets[0].Id` scalar (first target ID)
- Full `Targets` array stored under `Targets` key in RecordData

---

### Error Detection

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `ResourceNotFoundException`                  | `AwsError::ResourceNotFound` |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| Anything else                                | `AwsError::CommandFailed`    |

`ResourceNotFoundException` on Command 1 sets `found = false` and skips Command 2.

---

## Collected Data Fields

### Scalar Fields

| Field            | Type    | Always Present     | Source                                  |
| ---------------- | ------- | ------------------ | --------------------------------------- |
| `found`          | boolean | Yes                | Derived — `true` if rule exists         |
| `rule_name`      | string  | When found         | describe-rule → `Name`                  |
| `rule_arn`       | string  | When found         | describe-rule → `Arn`                   |
| `state`          | string  | When found         | describe-rule → `State`                 |
| `description`    | string  | When found         | describe-rule → `Description`           |
| `event_bus_name` | string  | When found         | describe-rule → `EventBusName`          |
| `target_count`   | integer | When found         | Derived — count of `Targets` array      |
| `target_arn`     | string  | When target exists | list-targets-by-rule → `Targets[0].Arn` |
| `target_id`      | string  | When target exists | list-targets-by-rule → `Targets[0].Id`  |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                   |
| ---------- | ---------- | -------------- | ----------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged rule config + parsed EventPattern + targets. Empty `{}` when not found |

---

## RecordData Structure

```rust
let merged = serde_json::json!({
    "Rule": rule_response_without_event_pattern_string,
    "EventPattern": parsed_event_pattern,   // parsed from JSON string
    "Targets": targets_array,
});
```

### Rule paths

| Path                | Type   | Example Value                                |
| ------------------- | ------ | -------------------------------------------- |
| `Rule.Name`         | string | `"example-org-guardduty-findings"`       |
| `Rule.State`        | string | `"ENABLED"`                                  |
| `Rule.EventBusName` | string | `"default"`                                  |
| `Rule.Description`  | string | `"Capture GuardDuty findings severity >= 4"` |

### EventPattern paths (parsed from JSON string)

| Path                         | Type   | Example Value         |
| ---------------------------- | ------ | --------------------- |
| `EventPattern.source.0`      | string | `"aws.guardduty"`     |
| `EventPattern.detail-type.0` | string | `"GuardDuty Finding"` |

### Targets paths

| Path            | Type   | Example Value                                                                        |
| --------------- | ------ | ------------------------------------------------------------------------------------ |
| `Targets.0.Id`  | string | `"GuardDutyFindingsToLogs"`                                                          |
| `Targets.0.Arn` | string | `"arn:aws:logs:us-east-1:123456789012:log-group:/example-org/security/findings"` |

---

## State Fields

| State Field      | Type       | Allowed Operations              | Maps To Collected Field |
| ---------------- | ---------- | ------------------------------- | ----------------------- |
| `found`          | boolean    | `=`, `!=`                       | `found`                 |
| `rule_name`      | string     | `=`, `!=`, `contains`, `starts` | `rule_name`             |
| `rule_arn`       | string     | `=`, `!=`, `contains`, `starts` | `rule_arn`              |
| `state`          | string     | `=`, `!=`                       | `state`                 |
| `description`    | string     | `=`, `!=`, `contains`           | `description`           |
| `event_bus_name` | string     | `=`, `!=`                       | `event_bus_name`        |
| `target_count`   | int        | `=`, `!=`, `>=`, `>`            | `target_count`          |
| `target_arn`     | string     | `=`, `!=`, `contains`, `starts` | `target_arn`            |
| `target_id`      | string     | `=`, `!=`, `contains`           | `target_id`             |
| `record`         | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                                 |
| ---------------------------- | ------------------------------------- |
| Collector ID                 | `aws_cloudwatch_event_rule_collector` |
| Collector Type               | `aws_cloudwatch_event_rule`           |
| Collection Mode              | Content                               |
| Required Capabilities        | `aws_cli`, `events_read`              |
| Expected Collection Time     | ~2000ms (two API calls)               |
| Memory Usage                 | ~2MB                                  |
| Network Intensive            | Yes                                   |
| CPU Intensive                | No                                    |
| Requires Elevated Privileges | No                                    |
| Batch Collection             | No                                    |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["events:DescribeRule", "events:ListTargetsByRule"],
  "Resource": "*"
}
```

---

## ESP Examples

### GuardDuty findings rule enabled and targeting security log group

```esp
OBJECT guardduty_rule
    rule_name `example-org-guardduty-findings`
    region `us-east-1`
OBJECT_END

STATE rule_compliant
    found boolean = true
    state string = `ENABLED`
    target_count int >= 1
    target_arn string contains `example-org-security-findings`
STATE_END

CTN aws_cloudwatch_event_rule
    TEST all all AND
    STATE_REF rule_compliant
    OBJECT_REF guardduty_rule
CTN_END
```

### Record checks for event pattern inspection

```esp
OBJECT guardduty_rule
    rule_name `example-org-guardduty-findings`
    region `us-east-1`
OBJECT_END

STATE rule_pattern_valid
    found boolean = true
    state string = `ENABLED`
    record
        field EventPattern.source.0 string = `aws.guardduty`
        field EventPattern.detail-type.0 string = `GuardDuty Finding`
        field Targets.0.Arn string contains `example-org-security-findings`
    record_end
STATE_END

CTN aws_cloudwatch_event_rule
    TEST all all AND
    STATE_REF rule_pattern_valid
    OBJECT_REF guardduty_rule
CTN_END
```

---

## Error Conditions

| Condition                                    | Error Type                   | Outcome       | Notes                                                         |
| -------------------------------------------- | ---------------------------- | ------------- | ------------------------------------------------------------- |
| Rule not found (`ResourceNotFoundException`) | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent            |
| `rule_name` missing from object              | `InvalidObjectConfiguration` | Error         | Required field                                                |
| `aws` CLI binary not found                   | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                          |
| IAM access denied                            | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`         |
| EventPattern JSON parse failure              | `CollectionFailed`           | Error         | Inner JSON string fails to parse                              |
| Incompatible CTN type                        | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_cloudwatch_event_rule"` |

---

## Related CTN Types

| CTN Type                   | Relationship                                                |
| -------------------------- | ----------------------------------------------------------- |
| `aws_cloudwatch_log_group` | EventBridge rules deliver findings to CloudWatch log groups |
| `aws_guardduty_detector`   | GuardDuty is the event source for the findings rule         |
| `aws_securityhub_account`  | Security Hub is the event source for the findings rule      |
