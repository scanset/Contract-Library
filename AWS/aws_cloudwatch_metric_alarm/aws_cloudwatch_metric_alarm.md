# aws_cloudwatch_metric_alarm

## Overview

Validates AWS CloudWatch metric alarm configuration via a single AWS CLI call using `describe-alarms --alarm-names`. Returns alarm state, metric configuration, threshold, and action settings as scalar fields.

**Platform:** AWS (requires `aws` CLI binary with CloudWatch read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** `Threshold` is a float in the API (`1.0`, `5.0`). The collector truncates it to an integer for the `threshold` scalar. All three alarms in this system use whole number thresholds.

---

## Object Fields

| Field        | Type   | Required | Description                                | Example                            |
| ------------ | ------ | -------- | ------------------------------------------ | ---------------------------------- |
| `alarm_name` | string | **Yes**  | Alarm name (exact match)                   | `example-org-root-login-alarm` |
| `region`     | string | No       | AWS region override (passed as `--region`) | `us-east-1`                        |

---

## Commands Executed

### Command 1: describe-alarms

```
aws cloudwatch describe-alarms --alarm-names example-org-root-login-alarm --output json
```

**Sample response (abbreviated):**

```json
{
  "MetricAlarms": [
    {
      "AlarmName": "example-org-root-login-alarm",
      "AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:example-org-root-login-alarm",
      "AlarmDescription": "Root account login detected - KSI-IAM-SUS",
      "ActionsEnabled": true,
      "StateValue": "OK",
      "MetricName": "RootLoginCount",
      "Namespace": "ExampleOrg/Security",
      "Statistic": "Sum",
      "Period": 300,
      "EvaluationPeriods": 1,
      "Threshold": 1.0,
      "ComparisonOperator": "GreaterThanOrEqualToThreshold",
      "TreatMissingData": "notBreaching"
    }
  ]
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                 | Type    | Always Present | Source                          |
| --------------------- | ------- | -------------- | ------------------------------- |
| `found`               | boolean | Yes            | Derived — `true` if alarm found |
| `alarm_name`          | string  | When found     | `AlarmName`                     |
| `state_value`         | string  | When found     | `StateValue`                    |
| `metric_name`         | string  | When found     | `MetricName`                    |
| `namespace`           | string  | When found     | `Namespace`                     |
| `statistic`           | string  | When found     | `Statistic`                     |
| `period`              | integer | When found     | `Period` (seconds)              |
| `evaluation_periods`  | integer | When found     | `EvaluationPeriods`             |
| `threshold`           | integer | When found     | `Threshold` (truncated float)   |
| `comparison_operator` | string  | When found     | `ComparisonOperator`            |
| `treat_missing_data`  | string  | When found     | `TreatMissingData`              |
| `actions_enabled`     | boolean | When found     | `ActionsEnabled`                |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full alarm object. Empty `{}` when not found |

---

## RecordData Structure

```
AlarmName                 → "example-org-root-login-alarm"
StateValue                → "OK"
MetricName                → "RootLoginCount"
Namespace                 → "ExampleOrg/Security"
Statistic                 → "Sum"
Period                    → 300
EvaluationPeriods         → 1
Threshold                 → 1.0
ComparisonOperator        → "GreaterThanOrEqualToThreshold"
TreatMissingData          → "notBreaching"
ActionsEnabled            → true
AlarmDescription          → "Root account login detected - KSI-IAM-SUS"
```

**`StateValue` values:** `OK` (metric below threshold), `ALARM` (threshold crossed), `INSUFFICIENT_DATA` (not enough data to evaluate)

**`TreatMissingData` values:** `notBreaching` (missing = OK), `breaching` (missing = ALARM), `ignore` (keep current state), `missing` (set INSUFFICIENT_DATA)

---

## State Fields

| State Field           | Type       | Allowed Operations              | Maps To Collected Field |
| --------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`               | boolean    | `=`, `!=`                       | `found`                 |
| `alarm_name`          | string     | `=`, `!=`                       | `alarm_name`            |
| `state_value`         | string     | `=`, `!=`                       | `state_value`           |
| `metric_name`         | string     | `=`, `!=`                       | `metric_name`           |
| `namespace`           | string     | `=`, `!=`                       | `namespace`             |
| `statistic`           | string     | `=`, `!=`                       | `statistic`             |
| `period`              | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `period`                |
| `evaluation_periods`  | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `evaluation_periods`    |
| `threshold`           | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `threshold`             |
| `comparison_operator` | string     | `=`, `!=`, `contains`, `starts` | `comparison_operator`   |
| `treat_missing_data`  | string     | `=`, `!=`                       | `treat_missing_data`    |
| `actions_enabled`     | boolean    | `=`, `!=`                       | `actions_enabled`       |
| `record`              | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                 | Value                                   |
| ------------------------ | --------------------------------------- |
| Collector ID             | `aws_cloudwatch_metric_alarm_collector` |
| Collector Type           | `aws_cloudwatch_metric_alarm`           |
| Collection Mode          | Content                                 |
| Required Capabilities    | `aws_cli`, `cloudwatch_read`            |
| Expected Collection Time | ~1500ms                                 |
| Memory Usage             | ~2MB                                    |
| Batch Collection         | No                                      |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["cloudwatch:DescribeAlarms"],
  "Resource": "*"
}
```

---

## ESP Examples

### Root login alarm configured and not firing (KSI-MLA-OSM, KSI-CMT-LMC)

```esp
OBJECT root_login_alarm
    alarm_name `example-org-root-login-alarm`
    region `us-east-1`
OBJECT_END

STATE alarm_configured
    found boolean = true
    metric_name string = `RootLoginCount`
    namespace string = `ExampleOrg/Security`
    statistic string = `Sum`
    period int = 300
    threshold int = 1
    comparison_operator string = `GreaterThanOrEqualToThreshold`
    treat_missing_data string = `notBreaching`
STATE_END

CTN aws_cloudwatch_metric_alarm
    TEST all all AND
    STATE_REF alarm_configured
    OBJECT_REF root_login_alarm
CTN_END
```

---

## Error Conditions

| Condition                        | Error Type                   | Outcome       |
| -------------------------------- | ---------------------------- | ------------- |
| Alarm not found                  | N/A (not an error)           | `found=false` |
| `alarm_name` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied                | `CollectionFailed`           | Error         |
| Incompatible CTN type            | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                       | Relationship                                              |
| ------------------------------ | --------------------------------------------------------- |
| `aws_cloudwatch_metric_filter` | Filters produce the metrics that alarms monitor           |
| `aws_cloudwatch_log_group`     | Log groups feed filters that feed alarms                  |
| `aws_cloudtrail`               | CloudTrail events are the source data for filter patterns |
