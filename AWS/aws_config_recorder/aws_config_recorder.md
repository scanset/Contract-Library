# aws_config_recorder

## Overview

Validates AWS Config configuration recorder state via two AWS CLI calls: `describe-configuration-recorders` for recording scope and mode, and `describe-configuration-recorder-status` for active recording state and last delivery status. Both responses are merged into a single RecordData object.

**Platform:** AWS (requires `aws` CLI binary with Config read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

---

## Object Fields

| Field           | Type   | Required | Description                                | Example                           |
| --------------- | ------ | -------- | ------------------------------------------ | --------------------------------- |
| `recorder_name` | string | **Yes**  | Config recorder name (exact match)         | `example-org-config-recorder` |
| `region`        | string | No       | AWS region override (passed as `--region`) | `us-east-1`                       |

---

## Commands Executed

### Command 1: describe-configuration-recorders

```
aws configservice describe-configuration-recorders --configuration-recorder-names example-org-config-recorder --output json
```

**Sample response (abbreviated):**

```json
{
  "ConfigurationRecorders": [
    {
      "name": "example-org-config-recorder",
      "roleARN": "arn:aws:iam::123456789012:role/example-org-config-role",
      "recordingGroup": {
        "allSupported": true,
        "includeGlobalResourceTypes": true
      },
      "recordingMode": {
        "recordingFrequency": "CONTINUOUS"
      }
    }
  ]
}
```

### Command 2: describe-configuration-recorder-status

```
aws configservice describe-configuration-recorder-status --configuration-recorder-names example-org-config-recorder --output json
```

**Sample response:**

```json
{
  "ConfigurationRecordersStatus": [
    {
      "name": "example-org-config-recorder",
      "lastStartTime": "2026-03-24T16:24:59.146000+00:00",
      "recording": true,
      "lastStatus": "SUCCESS",
      "lastStatusChangeTime": "2026-03-26T15:16:10.098000+00:00"
    }
  ]
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                           | Type    | Always Present | Source                                      |
| ------------------------------- | ------- | -------------- | ------------------------------------------- |
| `found`                         | boolean | Yes            | Derived — `true` if recorder found          |
| `recorder_name`                 | string  | When found     | `name`                                      |
| `all_supported`                 | boolean | When found     | `recordingGroup.allSupported`               |
| `include_global_resource_types` | boolean | When found     | `recordingGroup.includeGlobalResourceTypes` |
| `recording_frequency`           | string  | When found     | `recordingMode.recordingFrequency`          |
| `recording`                     | boolean | When found     | `Status.recording`                          |
| `last_status`                   | string  | When found     | `Status.lastStatus`                         |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged recorder config + status. Empty `{}` when not found |

---

## RecordData Structure

```
Recorder.name                                    → "example-org-config-recorder"
Recorder.roleARN                                 → "arn:aws:iam::123456789012:role/..."
Recorder.recordingGroup.allSupported             → true
Recorder.recordingGroup.includeGlobalResourceTypes → true
Recorder.recordingMode.recordingFrequency        → "CONTINUOUS"
Status.recording                                 → true
Status.lastStatus                                → "SUCCESS"
Status.lastStartTime                             → "2026-03-24T16:24:59.146000+00:00"
```

---

## State Fields

| State Field                     | Type       | Allowed Operations | Maps To Collected Field         |
| ------------------------------- | ---------- | ------------------ | ------------------------------- |
| `found`                         | boolean    | `=`, `!=`          | `found`                         |
| `recorder_name`                 | string     | `=`, `!=`          | `recorder_name`                 |
| `all_supported`                 | boolean    | `=`, `!=`          | `all_supported`                 |
| `include_global_resource_types` | boolean    | `=`, `!=`          | `include_global_resource_types` |
| `recording_frequency`           | string     | `=`, `!=`          | `recording_frequency`           |
| `recording`                     | boolean    | `=`, `!=`          | `recording`                     |
| `last_status`                   | string     | `=`, `!=`          | `last_status`                   |
| `record`                        | RecordData | (record checks)    | `resource`                      |

---

## Collection Strategy

| Property                 | Value                           |
| ------------------------ | ------------------------------- |
| Collector ID             | `aws_config_recorder_collector` |
| Collector Type           | `aws_config_recorder`           |
| Collection Mode          | Content                         |
| Required Capabilities    | `aws_cli`, `config_read`        |
| Expected Collection Time | ~2000ms (two API calls)         |
| Memory Usage             | ~2MB                            |
| Batch Collection         | No                              |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "config:DescribeConfigurationRecorders",
    "config:DescribeConfigurationRecorderStatus"
  ],
  "Resource": "*"
}
```

---

## ESP Examples

### Config recorder active and recording all resources (KSI-MLA-LET, KSI-CMT-VTD)

```esp
OBJECT config_recorder
    recorder_name `example-org-config-recorder`
    region `us-east-1`
OBJECT_END

STATE recorder_compliant
    found boolean = true
    recording boolean = true
    all_supported boolean = true
    include_global_resource_types boolean = true
    recording_frequency string = `CONTINUOUS`
    last_status string = `SUCCESS`
STATE_END

CTN aws_config_recorder
    TEST all all AND
    STATE_REF recorder_compliant
    OBJECT_REF config_recorder
CTN_END
```

---

## Error Conditions

| Condition                              | Error Type                   | Outcome       |
| -------------------------------------- | ---------------------------- | ------------- |
| Recorder not found                     | N/A (not an error)           | `found=false` |
| `recorder_name` missing from object    | `InvalidObjectConfiguration` | Error         |
| IAM access denied                      | `CollectionFailed`           | Error         |
| Status call fails after recorder found | `CollectionFailed`           | Error         |
| Incompatible CTN type                  | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type          | Relationship                                             |
| ----------------- | -------------------------------------------------------- |
| `aws_config_rule` | Config rules depend on the recorder being active         |
| `aws_iam_role`    | Config recorder assumes an IAM role to deliver snapshots |
| `aws_s3_bucket`   | Config snapshots are delivered to an S3 bucket           |
