# aws_cloudtrail

## Overview

Validates AWS CloudTrail trail configurations via the AWS CLI. Collects from both `describe-trails` (configuration) and `get-trail-status` (operational state), merging results into scalar fields and a single RecordData object for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with CloudTrail read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

---

## Object Fields

| Field        | Type   | Required | Description                                | Example         |
| ------------ | ------ | -------- | ------------------------------------------ | --------------- |
| `trail_name` | string | No       | Trail name or full ARN for direct lookup   | `example-trail` |
| `region`     | string | No       | AWS region override (passed as `--region`) | `us-east-1`     |

- If `trail_name` is omitted, the collector uses the **first trail** returned by `describe-trails`.
- If `trail_name` is provided, matching is attempted against both the `Name` and `TrailARN` fields in the response.
- If multiple trails exist and no `trail_name` is specified, a warning is logged and the first result is used.
- If `region` is omitted, the AWS CLI's default region resolution applies (env vars, config file, instance metadata).

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

- `--output json` is **always** appended.
- `--region <region>` is appended **only** when a `region` value is provided in the object fields.
- The process is spawned directly — no shell, no inherited environment variable filtering by the client.

### Command 1: describe-trails

Retrieves all trail configurations in the account/region. No additional arguments are passed beyond the base command.

**Collector call:** `client.execute("cloudtrail", "describe-trails", &[])`

**Resulting command:**

```
aws cloudtrail describe-trails --output json
aws cloudtrail describe-trails --region us-east-1 --output json    # with region
```

**Response parsing:**

1. Extract `response["trailList"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If `trail_name` is specified in the object, find the first element where `Name == trail_name` OR `TrailARN == trail_name`
3. If `trail_name` is not specified, use `trails.first()`
4. If no match is found, set `found = false` and skip Command 2

**Sample response:**

```json
{
  "trailList": [
    {
      "Name": "example-trail",
      "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/example-trail",
      "S3BucketName": "example-org-cloudtrail-123456789012",
      "IsMultiRegionTrail": true,
      "IncludeGlobalServiceEvents": true,
      "LogFileValidationEnabled": true,
      "HomeRegion": "us-east-1",
      "IsOrganizationTrail": false,
      "HasCustomEventSelectors": false,
      "HasInsightSelectors": false
    }
  ]
}
```

### Command 2: get-trail-status

Retrieves operational state for the matched trail. **Only called if Command 1 found a matching trail.**

**Collector call:** `client.execute("cloudtrail", "get-trail-status", &["--name", status_name])`

Where `status_name` is the `Name` field extracted from the matched trail in the `describe-trails` response — not the original `trail_name` input from the object. If the original lookup was by ARN, the resolved `Name` is still used here.

**Resulting command:**

```
aws cloudtrail get-trail-status --name example-trail --output json
aws cloudtrail get-trail-status --name example-trail --region us-east-1 --output json    # with region
```

**Sample response:**

```json
{
  "IsLogging": true,
  "LatestDeliveryTime": "2026-02-23T19:57:00Z",
  "StartLoggingTime": "2026-02-23T12:56:59.288000-07:00",
  "TimeLoggingStarted": "2026-02-23T19:56:59Z",
  "TimeLoggingStopped": "",
  "LatestDeliveryAttemptTime": "2026-02-23T19:57:00Z"
}
```

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

If stdout is empty on a successful exit, an empty JSON object is returned. If stdout is non-empty but not valid JSON, `AwsError::ParseError` is raised.

All `AwsError` variants are mapped to `CollectionError::CollectionFailed` by the collector with a message indicating which API call failed (`describe-trails` or `get-trail-status`).

---

## Collected Data Fields

### Scalar Fields

These are extracted individually from the command responses and added as typed fields.

| Field                           | Type    | Always Present | Source                                         |
| ------------------------------- | ------- | -------------- | ---------------------------------------------- |
| `found`                         | boolean | Yes            | Derived — `true` if a matching trail was found |
| `trail_name`                    | string  | When found     | describe-trails → `Name`                       |
| `trail_arn`                     | string  | When found     | describe-trails → `TrailARN`                   |
| `s3_bucket_name`                | string  | When found     | describe-trails → `S3BucketName`               |
| `is_multi_region`               | boolean | When found     | describe-trails → `IsMultiRegionTrail`         |
| `include_global_service_events` | boolean | When found     | describe-trails → `IncludeGlobalServiceEvents` |
| `log_file_validation_enabled`   | boolean | When found     | describe-trails → `LogFileValidationEnabled`   |
| `is_organization_trail`         | boolean | When found     | describe-trails → `IsOrganizationTrail`        |
| `home_region`                   | string  | When found     | describe-trails → `HomeRegion`                 |
| `is_logging`                    | boolean | When found     | get-trail-status → `IsLogging`                 |

Each field is only added if the corresponding JSON key exists and has the expected type (string via `as_str()`, boolean via `as_bool()`). Missing keys in the AWS response result in the field being absent from collected data.

### RecordData Field

| Field      | Type       | Always Present | Description                                                                   |
| ---------- | ---------- | -------------- | ----------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged trail config + `Status` sub-object. Empty `{}` when trail is not found |

---

## RecordData Structure

The `resource` field is built by cloning the matched trail JSON object from `describe-trails` and inserting the entire `get-trail-status` response as a `Status` key:

```rust
let mut merged = trail.clone();             // full describe-trails object for this trail
merged["Status"] = status_response;         // entire get-trail-status response
let record_data = RecordData::from_json_value(merged);
```

### Top-level paths (from describe-trails)

| Path                         | Type    | Example Value                                                     |
| ---------------------------- | ------- | ----------------------------------------------------------------- |
| `Name`                       | string  | `"example-trail"`                                                 |
| `TrailARN`                   | string  | `"arn:aws:cloudtrail:us-east-1:123456789012:trail/example-trail"` |
| `S3BucketName`               | string  | `"example-org-cloudtrail-123456789012"`                               |
| `IsMultiRegionTrail`         | boolean | `true`                                                            |
| `IncludeGlobalServiceEvents` | boolean | `true`                                                            |
| `LogFileValidationEnabled`   | boolean | `true`                                                            |
| `HomeRegion`                 | string  | `"us-east-1"`                                                     |
| `IsOrganizationTrail`        | boolean | `false`                                                           |
| `HasCustomEventSelectors`    | boolean | `false`                                                           |
| `HasInsightSelectors`        | boolean | `false`                                                           |

### Status paths (from get-trail-status, nested under `Status`)

| Path                        | Type    | Example Value                        |
| --------------------------- | ------- | ------------------------------------ |
| `Status.IsLogging`          | boolean | `true`                               |
| `Status.StartLoggingTime`   | string  | `"2026-02-23T12:56:59.288000-07:00"` |
| `Status.TimeLoggingStarted` | string  | `"2026-02-23T19:56:59Z"`             |
| `Status.TimeLoggingStopped` | string  | `""`                                 |
| `Status.LatestDeliveryTime` | string  | `"2026-02-23T19:57:00Z"`             |

---

## State Fields

### Scalar State Fields

| State Field                     | Type    | Allowed Operations              | Maps To Collected Field         |
| ------------------------------- | ------- | ------------------------------- | ------------------------------- |
| `found`                         | boolean | `=`, `!=`                       | `found`                         |
| `trail_name`                    | string  | `=`, `!=`, `contains`           | `trail_name`                    |
| `trail_arn`                     | string  | `=`, `!=`, `contains`, `starts` | `trail_arn`                     |
| `s3_bucket_name`                | string  | `=`, `!=`, `contains`, `starts` | `s3_bucket_name`                |
| `is_multi_region`               | boolean | `=`, `!=`                       | `is_multi_region`               |
| `include_global_service_events` | boolean | `=`, `!=`                       | `include_global_service_events` |
| `log_file_validation_enabled`   | boolean | `=`, `!=`                       | `log_file_validation_enabled`   |
| `is_organization_trail`         | boolean | `=`, `!=`                       | `is_organization_trail`         |
| `home_region`                   | string  | `=`, `!=`                       | `home_region`                   |
| `is_logging`                    | boolean | `=`, `!=`                       | `is_logging`                    |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the merged RecordData.

| State Field | Maps To Collected Field | Description                                            |
| ----------- | ----------------------- | ------------------------------------------------------ |
| `record`    | `resource`              | Deep inspection of merged trail config + status object |

Record check field paths use the structure documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                              |
| ---------------------------- | ---------------------------------- |
| Collector ID                 | `aws_cloudtrail_collector`         |
| Collector Type               | `aws_cloudtrail`                   |
| Collection Mode              | Content                            |
| Required Capabilities        | `aws_cli`, `cloudtrail_read`       |
| Expected Collection Time     | ~3000ms (two sequential API calls) |
| Memory Usage                 | ~5MB                               |
| Network Intensive            | Yes                                |
| CPU Intensive                | No                                 |
| Requires Elevated Privileges | No                                 |
| Batch Collection             | No                                 |

### Authentication

The `AwsClient` uses `Command::new("aws")` which relies on the AWS CLI's default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM role (EC2, ECS, Lambda)
4. IRSA (EKS)

The client does not pass credentials explicitly — it relies on whatever the `aws` binary resolves.

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                     |
| ----------- | --------------------------------------------------------- |
| method_type | `ApiCall`                                                 |
| description | `"Query CloudTrail configuration and status via AWS CLI"` |
| target      | `"trail:<trail_name>"` or `"trail:default"`               |
| command     | `"aws cloudtrail describe-trails + get-trail-status"`     |
| inputs      | `trail_name` and `region` (when provided in object)       |

---

## ESP Examples

### Basic: Trail is active and compliant

```esp
OBJECT audit_trail
    trail_name `example-trail`
    region `us-east-1`
OBJECT_END

STATE trail_compliant
    found boolean = true
    is_logging boolean = true
    is_multi_region boolean = true
    log_file_validation_enabled boolean = true
    include_global_service_events boolean = true
STATE_END

CTN aws_cloudtrail
    TEST all all AND
    STATE_REF trail_compliant
    OBJECT_REF audit_trail
CTN_END
```

### S3 destination validation

```esp
OBJECT audit_trail
    trail_name `example-trail`
    region `us-east-1`
OBJECT_END

STATE correct_destination
    found boolean = true
    s3_bucket_name string starts `example-cloudtrail-`
    is_logging boolean = true
STATE_END

CTN aws_cloudtrail
    TEST all all AND
    STATE_REF correct_destination
    OBJECT_REF audit_trail
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT audit_trail
    trail_name `example-trail`
    region `us-east-1`
OBJECT_END

STATE trail_details
    found boolean = true
    record
        field IsMultiRegionTrail boolean = true
        field LogFileValidationEnabled boolean = true
        field Status.IsLogging boolean = true
        field HomeRegion string = `us-east-1`
    record_end
STATE_END

CTN aws_cloudtrail
    TEST all all AND
    STATE_REF trail_details
    OBJECT_REF audit_trail
CTN_END
```

### Default trail (no trail_name specified)

```esp
OBJECT any_trail
    region `us-east-1`
OBJECT_END

STATE logging_active
    found boolean = true
    is_logging boolean = true
STATE_END

CTN aws_cloudtrail
    TEST all all AND
    STATE_REF logging_active
    OBJECT_REF any_trail
CTN_END
```

---

## Error Conditions

| Condition                            | Error Type              | Outcome       | Notes                                                 |
| ------------------------------------ | ----------------------- | ------------- | ----------------------------------------------------- |
| Trail not found in `describe-trails` | N/A (not an error)      | `found=false` | `resource` set to empty `{}`, scalar fields absent    |
| `aws` CLI binary not found           | `CollectionFailed`      | Error         | `Command::new("aws")` fails to spawn                  |
| Invalid AWS credentials              | `CollectionFailed`      | Error         | CLI returns non-zero exit with credential error       |
| IAM access denied                    | `CollectionFailed`      | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess` |
| `get-trail-status` fails             | `CollectionFailed`      | Error         | Second API call fails after trail was found           |
| Empty response from AWS              | N/A                     | `found=false` | Empty `trailList` array or empty stdout               |
| JSON parse failure                   | `CollectionFailed`      | Error         | `serde_json::from_str` fails on stdout                |
| Incompatible CTN type                | `CtnContractValidation` | Error         | Collector validates `ctn_type == "aws_cloudtrail"`    |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Trail not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                   | Relationship                                                  |
| -------------------------- | ------------------------------------------------------------- |
| `aws_flow_log`             | Flow logs cover network audit; CloudTrail covers API audit    |
| `aws_s3_bucket`            | Trail logs delivered to S3; validate bucket encryption/policy |
| `aws_cloudwatch_log_group` | Trail can also deliver to CloudWatch (if configured)          |
