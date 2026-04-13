# aws_guardduty_detector

## Overview

Validates AWS GuardDuty detector configuration via the AWS CLI. Makes two or three sequential API calls: `get-detector` for configuration and data source/feature status, `list-publishing-destinations` to discover publishing destinations, and optionally `describe-publishing-destination` for destination detail when a destination exists. All results are merged into scalar fields and a single RecordData object for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with GuardDuty read permissions)
**Collection Method:** Two or three sequential AWS CLI commands per object via `AwsClient`

**Note:** GuardDuty `Tags` are returned inline in `get-detector` as a flat `{ "Key": "Value" }` map (not a `TagSet` array). Tag scalar fields (`tag_key:<Key>`) are always collected — no behavior flag required.

**Note:** GuardDuty has two overlapping configuration representations: `DataSources` (legacy) and `Features` (current). Both are included in RecordData. Scalar fields are derived from `Features` as it is more complete and includes newer feature names.

---

## Object Fields

| Field         | Type   | Required | Description                                | Example                            |
| ------------- | ------ | -------- | ------------------------------------------ | ---------------------------------- |
| `detector_id` | string | **Yes**  | GuardDuty detector ID (exact match)        | `00000000000000000000000000000000` |
| `region`      | string | No       | AWS region override (passed as `--region`) | `us-east-1`                        |

- `detector_id` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`.

### Command 1: get-detector

Retrieves full detector configuration including status, data sources, features, and tags.

**Collector call:** `client.execute("guardduty", "get-detector", &["--detector-id", detector_id])`

**Resulting command:**

```
aws guardduty get-detector --detector-id 00000000000000000000000000000000 --output json
```

**Sample response:**

```json
{
  "CreatedAt": "2026-03-24T16:02:47.927Z",
  "FindingPublishingFrequency": "FIFTEEN_MINUTES",
  "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
  "Status": "ENABLED",
  "UpdatedAt": "2026-03-24T16:02:47.927Z",
  "DataSources": {
    "CloudTrail": { "Status": "ENABLED" },
    "DNSLogs": { "Status": "ENABLED" },
    "FlowLogs": { "Status": "ENABLED" },
    "S3Logs": { "Status": "ENABLED" },
    "Kubernetes": { "AuditLogs": { "Status": "DISABLED" } },
    "MalwareProtection": {
      "ScanEc2InstanceWithFindings": { "EbsVolumes": { "Status": "ENABLED" } }
    }
  },
  "Tags": {
    "Name": "example-org-guardduty",
    "Environment": "demo",
    "ManagedBy": "terraform"
  },
  "Features": [
    {
      "Name": "CLOUD_TRAIL",
      "Status": "ENABLED",
      "UpdatedAt": "2026-03-26T14:50:11+00:00"
    },
    {
      "Name": "S3_DATA_EVENTS",
      "Status": "ENABLED",
      "UpdatedAt": "2026-03-24T16:02:47+00:00"
    },
    {
      "Name": "EBS_MALWARE_PROTECTION",
      "Status": "ENABLED",
      "UpdatedAt": "2026-03-24T16:02:47+00:00"
    },
    {
      "Name": "EKS_AUDIT_LOGS",
      "Status": "DISABLED",
      "UpdatedAt": "2026-03-24T16:02:47+00:00"
    }
  ]
}
```

**Response parsing:**

- `Status` → `status` scalar
- `FindingPublishingFrequency` → `finding_publishing_frequency` scalar
- `Features` array → one scalar per feature: `feature_<lowercase_name>` = `"ENABLED"` or `"DISABLED"`
- `Tags` flat map → one scalar per tag: `tag_key:<Key>` = value
- Full response stored under `Detector` key in RecordData

If `detector_id` not found (non-zero exit with `BadRequestException` or `ResourceNotFoundException`), collector sets `found = false` and returns early.

---

### Command 2: list-publishing-destinations

Retrieves all publishing destinations for the detector.

**Collector call:** `client.execute("guardduty", "list-publishing-destinations", &["--detector-id", detector_id])`

**Resulting command:**

```
aws guardduty list-publishing-destinations --detector-id 00000000000000000000000000000000 --output json
```

**Sample response:**

```json
{
  "Destinations": [
    {
      "DestinationId": "a1b2c3d4e5f67890abcdef1234567890",
      "DestinationType": "S3",
      "Status": "PUBLISHING"
    }
  ]
}
```

**Response parsing:**

- `Destinations` array → take `first()` element
- `DestinationType` → `publishing_destination_type` scalar
- `Status` → `publishing_destination_status` scalar
- `DestinationId` stored for use in Command 3
- `has_publishing_destination` derived as `true` if any destination exists

If `Destinations` is empty, `has_publishing_destination` is set to `false` and Command 3 is skipped.

---

### Command 3: describe-publishing-destination _(only when a destination exists)_

Retrieves full destination detail including ARN and KMS key.

**Collector call:** `client.execute("guardduty", "describe-publishing-destination", &["--detector-id", detector_id, "--destination-id", destination_id])`

**Resulting command:**

```
aws guardduty describe-publishing-destination --detector-id 00000000000000000000000000000000 --destination-id a1b2c3d4e5f67890abcdef1234567890 --output json
```

**Sample response:**

```json
{
  "DestinationId": "a1b2c3d4e5f67890abcdef1234567890",
  "DestinationType": "S3",
  "Status": "PUBLISHING",
  "DestinationProperties": {
    "DestinationArn": "arn:aws:s3:::example-org-security-findings",
    "KmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  "Tags": {}
}
```

**Response parsing:**

- `DestinationProperties.DestinationArn` → `publishing_destination_arn` scalar
- `DestinationProperties.KmsKeyArn` → `publishing_destination_kms_key_arn` scalar
- Full response stored under `PublishingDestination` key in RecordData

---

### Error Detection

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| `BadRequestException`                        | `AwsError::InvalidParameter` |
| Anything else                                | `AwsError::CommandFailed`    |

If the detector does not exist (`ResourceNotFoundException` on Command 1), the collector sets `found = false` and skips Commands 2 and 3.

---

## Collected Data Fields

### Scalar Fields

| Field                                | Type    | Always Present    | Source                                                                   |
| ------------------------------------ | ------- | ----------------- | ------------------------------------------------------------------------ |
| `found`                              | boolean | Yes               | Derived — `true` if detector exists                                      |
| `detector_id`                        | string  | When found        | Echoed from object field                                                 |
| `status`                             | string  | When found        | get-detector → `Status`                                                  |
| `finding_publishing_frequency`       | string  | When found        | get-detector → `FindingPublishingFrequency`                              |
| `feature_cloud_trail`                | string  | When found        | Features array → `CLOUD_TRAIL` entry `Status`                            |
| `feature_dns_logs`                   | string  | When found        | Features array → `DNS_LOGS` entry `Status`                               |
| `feature_flow_logs`                  | string  | When found        | Features array → `FLOW_LOGS` entry `Status`                              |
| `feature_s3_data_events`             | string  | When found        | Features array → `S3_DATA_EVENTS` entry `Status`                         |
| `feature_ebs_malware_protection`     | string  | When found        | Features array → `EBS_MALWARE_PROTECTION` entry `Status`                 |
| `feature_eks_audit_logs`             | string  | When found        | Features array → `EKS_AUDIT_LOGS` entry `Status`                         |
| `feature_rds_login_events`           | string  | When found        | Features array → `RDS_LOGIN_EVENTS` entry `Status`                       |
| `feature_eks_runtime_monitoring`     | string  | When found        | Features array → `EKS_RUNTIME_MONITORING` entry `Status`                 |
| `feature_lambda_network_logs`        | string  | When found        | Features array → `LAMBDA_NETWORK_LOGS` entry `Status`                    |
| `feature_runtime_monitoring`         | string  | When found        | Features array → `RUNTIME_MONITORING` entry `Status`                     |
| `has_publishing_destination`         | boolean | When found        | Derived — `true` if Destinations list is non-empty                       |
| `publishing_destination_type`        | string  | When dest. exists | list-publishing-destinations → `Destinations[0].DestinationType`         |
| `publishing_destination_status`      | string  | When dest. exists | list-publishing-destinations → `Destinations[0].Status`                  |
| `publishing_destination_arn`         | string  | When dest. exists | describe-publishing-destination → `DestinationProperties.DestinationArn` |
| `publishing_destination_kms_key_arn` | string  | When dest. exists | describe-publishing-destination → `DestinationProperties.KmsKeyArn`      |
| `tag_key:<Key>`                      | string  | When found        | get-detector → `Tags` flat map, one field per tag                        |

Feature scalar fields use lowercase with underscores, e.g. `CLOUD_TRAIL` → `feature_cloud_trail`. Features not present in the API response result in absent fields.

### RecordData Field

| Field      | Type       | Always Present | Description                                                     |
| ---------- | ---------- | -------------- | --------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged detector + destination config. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field is built by merging all API responses under named keys:

```rust
let merged = serde_json::json!({
    "Detector": detector_response,                    // get-detector
    "PublishingDestination": destination_response,    // describe-publishing-destination (or {})
});
```

### Detector paths (from get-detector)

| Path                                                                                   | Type   | Example Value                 |
| -------------------------------------------------------------------------------------- | ------ | ----------------------------- |
| `Detector.Status`                                                                      | string | `"ENABLED"`                   |
| `Detector.FindingPublishingFrequency`                                                  | string | `"FIFTEEN_MINUTES"`           |
| `Detector.DataSources.CloudTrail.Status`                                               | string | `"ENABLED"`                   |
| `Detector.DataSources.DNSLogs.Status`                                                  | string | `"ENABLED"`                   |
| `Detector.DataSources.FlowLogs.Status`                                                 | string | `"ENABLED"`                   |
| `Detector.DataSources.S3Logs.Status`                                                   | string | `"ENABLED"`                   |
| `Detector.DataSources.Kubernetes.AuditLogs.Status`                                     | string | `"DISABLED"`                  |
| `Detector.DataSources.MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes.Status` | string | `"ENABLED"`                   |
| `Detector.Features.0.Name`                                                             | string | `"CLOUD_TRAIL"`               |
| `Detector.Features.0.Status`                                                           | string | `"ENABLED"`                   |
| `Detector.Tags.Name`                                                                   | string | `"example-org-guardduty"` |
| `Detector.Tags.Environment`                                                            | string | `"demo"`                      |

### PublishingDestination paths (from describe-publishing-destination)

| Path                                                         | Type   | Example Value                                      |
| ------------------------------------------------------------ | ------ | -------------------------------------------------- |
| `PublishingDestination.DestinationType`                      | string | `"S3"`                                             |
| `PublishingDestination.Status`                               | string | `"PUBLISHING"`                                     |
| `PublishingDestination.DestinationProperties.DestinationArn` | string | `"arn:aws:s3:::example-org-security-findings"` |
| `PublishingDestination.DestinationProperties.KmsKeyArn`      | string | `"arn:aws:kms:us-east-1:123456789012:key/..."`     |

---

## State Fields

### Scalar State Fields

| State Field                          | Type    | Allowed Operations              | Maps To Collected Field              |
| ------------------------------------ | ------- | ------------------------------- | ------------------------------------ |
| `found`                              | boolean | `=`, `!=`                       | `found`                              |
| `detector_id`                        | string  | `=`, `!=`                       | `detector_id`                        |
| `status`                             | string  | `=`, `!=`                       | `status`                             |
| `finding_publishing_frequency`       | string  | `=`, `!=`                       | `finding_publishing_frequency`       |
| `feature_cloud_trail`                | string  | `=`, `!=`                       | `feature_cloud_trail`                |
| `feature_dns_logs`                   | string  | `=`, `!=`                       | `feature_dns_logs`                   |
| `feature_flow_logs`                  | string  | `=`, `!=`                       | `feature_flow_logs`                  |
| `feature_s3_data_events`             | string  | `=`, `!=`                       | `feature_s3_data_events`             |
| `feature_ebs_malware_protection`     | string  | `=`, `!=`                       | `feature_ebs_malware_protection`     |
| `feature_eks_audit_logs`             | string  | `=`, `!=`                       | `feature_eks_audit_logs`             |
| `feature_rds_login_events`           | string  | `=`, `!=`                       | `feature_rds_login_events`           |
| `feature_eks_runtime_monitoring`     | string  | `=`, `!=`                       | `feature_eks_runtime_monitoring`     |
| `feature_lambda_network_logs`        | string  | `=`, `!=`                       | `feature_lambda_network_logs`        |
| `feature_runtime_monitoring`         | string  | `=`, `!=`                       | `feature_runtime_monitoring`         |
| `has_publishing_destination`         | boolean | `=`, `!=`                       | `has_publishing_destination`         |
| `publishing_destination_type`        | string  | `=`, `!=`                       | `publishing_destination_type`        |
| `publishing_destination_status`      | string  | `=`, `!=`                       | `publishing_destination_status`      |
| `publishing_destination_arn`         | string  | `=`, `!=`, `contains`, `starts` | `publishing_destination_arn`         |
| `publishing_destination_kms_key_arn` | string  | `=`, `!=`, `contains`, `starts` | `publishing_destination_kms_key_arn` |
| `tag_key:<Key>`                      | string  | `=`, `!=`, `contains`           | `tag_key:<Key>` (dynamic)            |

### Record Checks

| State Field | Maps To Collected Field | Description                                             |
| ----------- | ----------------------- | ------------------------------------------------------- |
| `record`    | `resource`              | Deep inspection of merged detector + destination config |

---

## Collection Strategy

| Property                     | Value                              |
| ---------------------------- | ---------------------------------- |
| Collector ID                 | `aws_guardduty_detector_collector` |
| Collector Type               | `aws_guardduty_detector`           |
| Collection Mode              | Content                            |
| Required Capabilities        | `aws_cli`, `guardduty_read`        |
| Expected Collection Time     | ~4000ms (two or three API calls)   |
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

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "guardduty:GetDetector",
    "guardduty:ListPublishingDestinations",
    "guardduty:DescribePublishingDestination"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                                           |
| ----------- | ----------------------------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                                       |
| description | `"Query GuardDuty detector configuration and publishing destination via AWS CLI"`               |
| target      | `"guardduty:<detector_id>"`                                                                     |
| command     | `"aws guardduty get-detector + list-publishing-destinations + describe-publishing-destination"` |
| inputs      | `detector_id` (always), `region` (when provided)                                                |

---

## ESP Examples

### Detector enabled with required features active

```esp
OBJECT main_detector
    detector_id `00000000000000000000000000000000`
    region `us-east-1`
OBJECT_END

STATE detector_compliant
    found boolean = true
    status string = `ENABLED`
    finding_publishing_frequency string = `FIFTEEN_MINUTES`
    feature_cloud_trail string = `ENABLED`
    feature_s3_data_events string = `ENABLED`
    feature_ebs_malware_protection string = `ENABLED`
    feature_flow_logs string = `ENABLED`
STATE_END

CTN aws_guardduty_detector
    TEST all all AND
    STATE_REF detector_compliant
    OBJECT_REF main_detector
CTN_END
```

### Publishing destination validated

```esp
OBJECT main_detector
    detector_id `00000000000000000000000000000000`
    region `us-east-1`
OBJECT_END

STATE destination_compliant
    found boolean = true
    has_publishing_destination boolean = true
    publishing_destination_type string = `S3`
    publishing_destination_status string = `PUBLISHING`
    publishing_destination_arn string starts `arn:aws:s3:::example-org`
    publishing_destination_kms_key_arn string starts `arn:aws:kms:us-east-1:123456789012:`
STATE_END

CTN aws_guardduty_detector
    TEST all all AND
    STATE_REF destination_compliant
    OBJECT_REF main_detector
CTN_END
```

### Tag compliance check

```esp
OBJECT main_detector
    detector_id `00000000000000000000000000000000`
    region `us-east-1`
OBJECT_END

STATE tagged_correctly
    found boolean = true
    tag_key:ManagedBy string = `terraform`
    tag_key:Environment string = `demo`
STATE_END

CTN aws_guardduty_detector
    TEST all all AND
    STATE_REF tagged_correctly
    OBJECT_REF main_detector
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT main_detector
    detector_id `00000000000000000000000000000000`
    region `us-east-1`
OBJECT_END

STATE detector_deep
    found boolean = true
    record
        field Detector.Status string = `ENABLED`
        field Detector.FindingPublishingFrequency string = `FIFTEEN_MINUTES`
        field Detector.DataSources.S3Logs.Status string = `ENABLED`
        field Detector.DataSources.MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes.Status string = `ENABLED`
        field PublishingDestination.Status string = `PUBLISHING`
        field PublishingDestination.DestinationProperties.DestinationArn string = `arn:aws:s3:::example-org-security-findings`
    record_end
STATE_END

CTN aws_guardduty_detector
    TEST all all AND
    STATE_REF detector_deep
    OBJECT_REF main_detector
CTN_END
```

---

## Error Conditions

| Condition                                        | Error Type                   | Outcome                            | Notes                                                      |
| ------------------------------------------------ | ---------------------------- | ---------------------------------- | ---------------------------------------------------------- |
| Detector not found (`ResourceNotFoundException`) | N/A (not an error)           | `found=false`                      | `resource` set to empty `{}`, scalar fields absent         |
| `detector_id` missing from object                | `InvalidObjectConfiguration` | Error                              | Required field — collector returns immediately             |
| `aws` CLI binary not found                       | `CollectionFailed`           | Error                              | `Command::new("aws")` fails to spawn                       |
| Invalid AWS credentials                          | `CollectionFailed`           | Error                              | CLI returns non-zero exit with credential error            |
| IAM access denied                                | `CollectionFailed`           | Error                              | stderr matched `AccessDenied` or `UnauthorizedAccess`      |
| No publishing destinations                       | N/A                          | `has_publishing_destination=false` | Command 3 skipped                                          |
| `describe-publishing-destination` fails          | `CollectionFailed`           | Error                              | Third call fails after destination was found in list       |
| JSON parse failure                               | `CollectionFailed`           | Error                              | `serde_json::from_str` fails on stdout                     |
| Incompatible CTN type                            | `CtnContractValidation`      | Error                              | Collector validates `ctn_type == "aws_guardduty_detector"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"GuardDuty detector not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type         | Relationship                                                               |
| ---------------- | -------------------------------------------------------------------------- |
| `aws_s3_bucket`  | GuardDuty publishes findings to S3; validate the destination bucket config |
| `aws_cloudtrail` | CloudTrail is a GuardDuty data source; validate the trail is active        |
