# aws_macie2_account

## Overview

Validates AWS Macie2 account configuration and classification job status via the AWS CLI. Makes two or three sequential API calls: `get-macie-session` for account-level status, `list-classification-jobs` to find jobs targeting a specified bucket, and `describe-classification-job` for full job detail when a matching job is found.

**Platform:** AWS (requires `aws` CLI binary with Macie2 read permissions)
**Collection Method:** Two or three sequential AWS CLI commands per object via `AwsClient`

**Note:** Macie2 has one session per account per region. No session identifier is required — only optional `region` and `bucket_name` object fields.

**Note:** `jobStatus` values for scheduled jobs include `IDLE` (between runs), `RUNNING` (actively scanning), `PAUSED`, and `CANCELLED`. A scheduled job in `IDLE` status between runs is operationally normal. Policy authors should validate `job_type` and `last_run_error_code` rather than `job_status` for compliance checks.

**Note:** Tags on classification jobs are returned as a flat `{ "Key": "Value" }` map (same as GuardDuty). Tag scalar fields (`tag_key:<Key>`) are always collected when a job is found.

---

## Object Fields

| Field         | Type   | Required | Description                                          | Example                             |
| ------------- | ------ | -------- | ---------------------------------------------------- | ----------------------------------- |
| `region`      | string | No       | AWS region override (passed as `--region`)           | `us-east-1`                         |
| `bucket_name` | string | No       | S3 bucket name to find associated classification job | `example-org-security-findings` |

- If `bucket_name` is provided, the collector finds the first job whose `s3JobDefinition.bucketDefinitions[*].buckets` contains the specified bucket name.
- If `bucket_name` is omitted, the collector uses the first job returned by `list-classification-jobs`.
- If no matching job exists, `has_classification_job` is set to `false` and `describe-classification-job` is skipped.

---

## Commands Executed

### Command 1: get-macie-session

Retrieves Macie2 account-level configuration.

**Collector call:** `client.execute("macie2", "get-macie-session", &[])`

**Resulting command:**

```
aws macie2 get-macie-session --output json
aws macie2 get-macie-session --region us-east-1 --output json    # with region
```

**Sample response:**

```json
{
  "createdAt": "2026-03-24T16:02:47.733000+00:00",
  "findingPublishingFrequency": "FIFTEEN_MINUTES",
  "serviceRole": "arn:aws:iam::123456789012:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
  "status": "ENABLED",
  "updatedAt": "2026-03-24T16:02:47.733000+00:00"
}
```

**Response parsing:**

- `status` → `session_status` scalar
- `findingPublishingFrequency` → `finding_publishing_frequency` scalar
- Full response stored under `Session` key in RecordData

If Macie2 is not enabled (`ResourceNotFoundException` or `AccessDeniedException`), collector sets `found = false` and skips remaining commands.

---

### Command 2: list-classification-jobs

Retrieves all classification jobs in the account/region.

**Collector call:** `client.execute("macie2", "list-classification-jobs", &[])`

**Resulting command:**

```
aws macie2 list-classification-jobs --output json
```

**Sample response:**

```json
{
  "items": [
    {
      "bucketDefinitions": [
        {
          "accountId": "123456789012",
          "buckets": ["example-org-security-findings"]
        }
      ],
      "createdAt": "2026-03-24T16:09:21.272070+00:00",
      "jobId": "b2c3d4e5f6789012abcdef3456789012",
      "jobStatus": "IDLE",
      "jobType": "SCHEDULED",
      "name": "example-org-security-bucket-scan"
    }
  ]
}
```

**Response parsing:**

- If `bucket_name` is provided: find first item where any `bucketDefinitions[*].buckets` contains the bucket name
- If `bucket_name` is omitted: use `items.first()`
- Extract `jobId` for use in Command 3
- `has_classification_job` derived as `true` if a matching job is found

---

### Command 3: describe-classification-job _(only when a matching job exists)_

Retrieves full classification job configuration.

**Collector call:** `client.execute("macie2", "describe-classification-job", &["--job-id", job_id])`

**Resulting command:**

```
aws macie2 describe-classification-job --job-id b2c3d4e5f6789012abcdef3456789012 --output json
```

**Sample response:**

```json
{
  "jobId": "b2c3d4e5f6789012abcdef3456789012",
  "jobStatus": "IDLE",
  "jobType": "SCHEDULED",
  "name": "example-org-security-bucket-scan",
  "managedDataIdentifierSelector": "RECOMMENDED",
  "samplingPercentage": 100,
  "scheduleFrequency": {
    "weeklySchedule": { "dayOfWeek": "MONDAY" }
  },
  "lastRunErrorStatus": { "code": "NONE" },
  "s3JobDefinition": {
    "bucketDefinitions": [
      {
        "accountId": "123456789012",
        "buckets": ["example-org-security-findings"]
      }
    ]
  },
  "tags": {
    "Environment": "demo",
    "ManagedBy": "terraform"
  }
}
```

**Response parsing:**

- `jobStatus` → `job_status` scalar
- `jobType` → `job_type` scalar
- `name` → `job_name` scalar
- `managedDataIdentifierSelector` → `managed_data_identifier_selector` scalar
- `samplingPercentage` → `sampling_percentage` scalar (integer)
- `lastRunErrorStatus.code` → `last_run_error_code` scalar
- `scheduleFrequency.weeklySchedule.dayOfWeek` → `schedule_day_of_week` scalar (when weekly schedule)
- Tags flat map → `tag_key:<Key>` scalars
- Full response stored under `ClassificationJob` key in RecordData

---

### Error Detection

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `ResourceNotFoundException`                  | `AwsError::ResourceNotFound` |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| Anything else                                | `AwsError::CommandFailed`    |

`ResourceNotFoundException` on Command 1 means Macie2 is not enabled — collector sets `found = false`.

---

## Collected Data Fields

### Scalar Fields

| Field                              | Type    | Always Present     | Source                                                                     |
| ---------------------------------- | ------- | ------------------ | -------------------------------------------------------------------------- |
| `found`                            | boolean | Yes                | Derived — `true` if Macie2 session exists                                  |
| `session_status`                   | string  | When found         | get-macie-session → `status`                                               |
| `finding_publishing_frequency`     | string  | When found         | get-macie-session → `findingPublishingFrequency`                           |
| `has_classification_job`           | boolean | When found         | Derived — `true` if a matching classification job exists                   |
| `job_status`                       | string  | When job exists    | describe-classification-job → `jobStatus`                                  |
| `job_type`                         | string  | When job exists    | describe-classification-job → `jobType`                                    |
| `job_name`                         | string  | When job exists    | describe-classification-job → `name`                                       |
| `managed_data_identifier_selector` | string  | When job exists    | describe-classification-job → `managedDataIdentifierSelector`              |
| `sampling_percentage`              | integer | When job exists    | describe-classification-job → `samplingPercentage`                         |
| `last_run_error_code`              | string  | When job exists    | describe-classification-job → `lastRunErrorStatus.code`                    |
| `schedule_day_of_week`             | string  | When weekly sched. | describe-classification-job → `scheduleFrequency.weeklySchedule.dayOfWeek` |
| `tag_key:<Key>`                    | string  | When job exists    | describe-classification-job → `tags` flat map, one field per tag           |

### RecordData Field

| Field      | Type       | Always Present | Description                                                           |
| ---------- | ---------- | -------------- | --------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged session + classification job config. Empty `{}` when not found |

---

## RecordData Structure

```rust
let merged = serde_json::json!({
    "Session": session_response,              // get-macie-session
    "ClassificationJob": job_response,        // describe-classification-job (or {})
});
```

### Session paths (from get-macie-session)

| Path                                 | Type   | Example Value        |
| ------------------------------------ | ------ | -------------------- |
| `Session.status`                     | string | `"ENABLED"`          |
| `Session.findingPublishingFrequency` | string | `"FIFTEEN_MINUTES"`  |
| `Session.serviceRole`                | string | `"arn:aws:iam::..."` |

### ClassificationJob paths (from describe-classification-job)

| Path                                                              | Type    | Example Value                            |
| ----------------------------------------------------------------- | ------- | ---------------------------------------- |
| `ClassificationJob.jobStatus`                                     | string  | `"IDLE"`                                 |
| `ClassificationJob.jobType`                                       | string  | `"SCHEDULED"`                            |
| `ClassificationJob.name`                                          | string  | `"example-org-security-bucket-scan"` |
| `ClassificationJob.managedDataIdentifierSelector`                 | string  | `"RECOMMENDED"`                          |
| `ClassificationJob.samplingPercentage`                            | integer | `100`                                    |
| `ClassificationJob.lastRunErrorStatus.code`                       | string  | `"NONE"`                                 |
| `ClassificationJob.scheduleFrequency.weeklySchedule.dayOfWeek`    | string  | `"MONDAY"`                               |
| `ClassificationJob.s3JobDefinition.bucketDefinitions.0.buckets.0` | string  | `"example-org-security-findings"`    |

---

## State Fields

### Scalar State Fields

| State Field                        | Type    | Allowed Operations              | Maps To Collected Field            |
| ---------------------------------- | ------- | ------------------------------- | ---------------------------------- |
| `found`                            | boolean | `=`, `!=`                       | `found`                            |
| `session_status`                   | string  | `=`, `!=`                       | `session_status`                   |
| `finding_publishing_frequency`     | string  | `=`, `!=`                       | `finding_publishing_frequency`     |
| `has_classification_job`           | boolean | `=`, `!=`                       | `has_classification_job`           |
| `job_status`                       | string  | `=`, `!=`                       | `job_status`                       |
| `job_type`                         | string  | `=`, `!=`                       | `job_type`                         |
| `job_name`                         | string  | `=`, `!=`, `contains`, `starts` | `job_name`                         |
| `managed_data_identifier_selector` | string  | `=`, `!=`                       | `managed_data_identifier_selector` |
| `sampling_percentage`              | int     | `=`, `!=`, `>=`, `>`            | `sampling_percentage`              |
| `last_run_error_code`              | string  | `=`, `!=`                       | `last_run_error_code`              |
| `schedule_day_of_week`             | string  | `=`, `!=`                       | `schedule_day_of_week`             |
| `tag_key:<Key>`                    | string  | `=`, `!=`, `contains`           | `tag_key:<Key>` (dynamic)          |

### Record Checks

| State Field | Maps To Collected Field | Description                                            |
| ----------- | ----------------------- | ------------------------------------------------------ |
| `record`    | `resource`              | Deep inspection of merged session + classification job |

---

## Collection Strategy

| Property                     | Value                            |
| ---------------------------- | -------------------------------- |
| Collector ID                 | `aws_macie2_account_collector`   |
| Collector Type               | `aws_macie2_account`             |
| Collection Mode              | Content                          |
| Required Capabilities        | `aws_cli`, `macie2_read`         |
| Expected Collection Time     | ~4000ms (two or three API calls) |
| Memory Usage                 | ~5MB                             |
| Network Intensive            | Yes                              |
| CPU Intensive                | No                               |
| Requires Elevated Privileges | No                               |
| Batch Collection             | No                               |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "macie2:GetMacieSession",
    "macie2:ListClassificationJobs",
    "macie2:DescribeClassificationJob"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                                     |
| ----------- | ----------------------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                                 |
| description | `"Query Macie2 session status and classification job configuration via AWS CLI"`          |
| target      | `"macie2:account"` or `"macie2:bucket:<bucket_name>"`                                     |
| command     | `"aws macie2 get-macie-session + list-classification-jobs + describe-classification-job"` |
| inputs      | `bucket_name` (when provided), `region` (when provided)                                   |

---

## ESP Examples

### Macie enabled with scheduled scan of security findings bucket

```esp
OBJECT macie_account
    region `us-east-1`
    bucket_name `example-org-security-findings`
OBJECT_END

STATE macie_compliant
    found boolean = true
    session_status string = `ENABLED`
    finding_publishing_frequency string = `FIFTEEN_MINUTES`
    has_classification_job boolean = true
    job_type string = `SCHEDULED`
    last_run_error_code string = `NONE`
    managed_data_identifier_selector string = `RECOMMENDED`
    sampling_percentage int = 100
STATE_END

CTN aws_macie2_account
    TEST all all AND
    STATE_REF macie_compliant
    OBJECT_REF macie_account
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT macie_account
    region `us-east-1`
    bucket_name `example-org-security-findings`
OBJECT_END

STATE macie_details
    found boolean = true
    record
        field Session.status string = `ENABLED`
        field Session.findingPublishingFrequency string = `FIFTEEN_MINUTES`
        field ClassificationJob.jobType string = `SCHEDULED`
        field ClassificationJob.lastRunErrorStatus.code string = `NONE`
        field ClassificationJob.samplingPercentage int = 100
        field ClassificationJob.scheduleFrequency.weeklySchedule.dayOfWeek string = `MONDAY`
    record_end
STATE_END

CTN aws_macie2_account
    TEST all all AND
    STATE_REF macie_details
    OBJECT_REF macie_account
CTN_END
```

---

## Error Conditions

| Condition                                        | Error Type              | Outcome                        | Notes                                                  |
| ------------------------------------------------ | ----------------------- | ------------------------------ | ------------------------------------------------------ |
| Macie2 not enabled (`ResourceNotFoundException`) | N/A (not an error)      | `found=false`                  | `resource` set to empty `{}`, scalar fields absent     |
| `aws` CLI binary not found                       | `CollectionFailed`      | Error                          | `Command::new("aws")` fails to spawn                   |
| Invalid AWS credentials                          | `CollectionFailed`      | Error                          | CLI returns non-zero exit with credential error        |
| IAM access denied                                | `CollectionFailed`      | Error                          | stderr matched `AccessDenied` or `UnauthorizedAccess`  |
| No matching classification job                   | N/A                     | `has_classification_job=false` | Command 3 skipped                                      |
| JSON parse failure                               | `CollectionFailed`      | Error                          | `serde_json::from_str` fails on stdout                 |
| Incompatible CTN type                            | `CtnContractValidation` | Error                          | Collector validates `ctn_type == "aws_macie2_account"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail**
- Record checks will **fail** with message `"Macie2 not enabled, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                 | Relationship                                                           |
| ------------------------ | ---------------------------------------------------------------------- |
| `aws_s3_bucket`          | Macie classification jobs scan S3 buckets for sensitive data           |
| `aws_guardduty_detector` | GuardDuty and Macie complement each other for data security monitoring |
