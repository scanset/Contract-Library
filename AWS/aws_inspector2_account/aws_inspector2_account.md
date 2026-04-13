# aws_inspector2_account

## Overview

Validates AWS Inspector2 account configuration and coverage via the AWS CLI. Makes two sequential API calls: `get-configuration` for scan mode and rescan duration settings, and `list-coverage` to derive active scan coverage across EC2, ECR, and network resource types.

**Platform:** AWS (requires `aws` CLI binary with Inspector2 read permissions)
**Collection Method:** Two sequential AWS CLI commands per object via `AwsClient`

**Note:** Inspector2 has one configuration per account per region. No identifier is required beyond optional `region`.

**Note:** Coverage scalars are derived by scanning the `coveredResources` array from `list-coverage`. A resource type is considered "active" when at least one entry with that `resourceType` has `scanStatus.statusCode == "ACTIVE"`.

---

## Object Fields

| Field    | Type   | Required | Description                                | Example     |
| -------- | ------ | -------- | ------------------------------------------ | ----------- |
| `region` | string | No       | AWS region override (passed as `--region`) | `us-east-1` |

---

## Commands Executed

### Command 1: get-configuration

Retrieves Inspector2 scan configuration for ECR and EC2.

**Collector call:** `client.execute("inspector2", "get-configuration", &[])`

**Resulting command:**

```
aws inspector2 get-configuration --output json
aws inspector2 get-configuration --region us-east-1 --output json    # with region
```

**Sample response:**

```json
{
  "ecrConfiguration": {
    "rescanDurationState": {
      "rescanDuration": "DAYS_14",
      "status": "SUCCESS",
      "updatedAt": "2026-03-24T16:03:01.110000+00:00",
      "pullDateRescanDuration": "DAYS_14",
      "pullDateRescanMode": "LAST_IN_USE_AT"
    }
  },
  "ec2Configuration": {
    "scanModeState": {
      "scanMode": "EC2_HYBRID",
      "scanModeStatus": "SUCCESS"
    }
  }
}
```

**Response parsing:**

- `ecrConfiguration.rescanDurationState.rescanDuration` → `ecr_rescan_duration` scalar
- `ecrConfiguration.rescanDurationState.pullDateRescanDuration` → `ecr_pull_date_rescan_duration` scalar
- `ecrConfiguration.rescanDurationState.pullDateRescanMode` → `ecr_pull_date_rescan_mode` scalar
- `ec2Configuration.scanModeState.scanMode` → `ec2_scan_mode` scalar
- `ec2Configuration.scanModeState.scanModeStatus` → `ec2_scan_mode_status` scalar
- Full response stored under `Configuration` key in RecordData

If Inspector2 is not enabled (`AccessDeniedException` or `ValidationException`), collector sets `found = false`.

---

### Command 2: list-coverage

Retrieves all resources currently covered by Inspector2 scanning.

**Collector call:** `client.execute("inspector2", "list-coverage", &[])`

**Resulting command:**

```
aws inspector2 list-coverage --output json
```

**Sample response:**

```json
{
  "coveredResources": [
    {
      "resourceType": "AWS_ACCOUNT",
      "resourceId": "123456789012",
      "accountId": "123456789012",
      "scanType": "NETWORK",
      "scanStatus": { "statusCode": "ACTIVE", "reason": "SUCCESSFUL" }
    },
    {
      "resourceType": "AWS_EC2_INSTANCE",
      "resourceId": "i-0123456789abcdef0",
      "accountId": "123456789012",
      "scanType": "PACKAGE",
      "scanStatus": { "statusCode": "ACTIVE", "reason": "SUCCESSFUL" },
      "resourceMetadata": {
        "ec2": {
          "tags": { "Name": "example-org-vm" },
          "amiId": "ami-0123456789abcdef0",
          "platform": "LINUX"
        }
      },
      "lastScannedAt": "2026-03-26T16:08:06+00:00",
      "scanMode": "EC2_SSM_AGENT_BASED"
    }
  ]
}
```

**Response parsing — derived coverage scalars:**

| Scalar Field             | Derivation Logic                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| `ec2_scan_active`        | Any entry with `resourceType=AWS_EC2_INSTANCE` AND `scanStatus.statusCode=ACTIVE`                   |
| `ecr_scan_active`        | Any entry with `resourceType=AWS_ECR_REPOSITORY` AND `scanStatus.statusCode=ACTIVE`                 |
| `network_scan_active`    | Any entry with `resourceType=AWS_ACCOUNT` AND `scanType=NETWORK` AND `scanStatus.statusCode=ACTIVE` |
| `covered_resource_count` | Total count of entries in `coveredResources`                                                        |

Full response stored under `Coverage` key in RecordData.

---

### Error Detection

| Stderr contains                        | Error variant                |
| -------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess` | `AwsError::AccessDenied`     |
| `ValidationException`                  | `AwsError::InvalidParameter` |
| `ResourceNotFoundException`            | `AwsError::ResourceNotFound` |
| Anything else                          | `AwsError::CommandFailed`    |

`AccessDeniedException` on Command 1 when Inspector2 is not enabled is treated as `found = false`.

---

## Collected Data Fields

### Scalar Fields

| Field                           | Type    | Always Present | Source                                                                            |
| ------------------------------- | ------- | -------------- | --------------------------------------------------------------------------------- |
| `found`                         | boolean | Yes            | Derived — `true` if Inspector2 is enabled                                         |
| `ecr_rescan_duration`           | string  | When found     | get-configuration → `ecrConfiguration.rescanDurationState.rescanDuration`         |
| `ecr_pull_date_rescan_duration` | string  | When found     | get-configuration → `ecrConfiguration.rescanDurationState.pullDateRescanDuration` |
| `ecr_pull_date_rescan_mode`     | string  | When found     | get-configuration → `ecrConfiguration.rescanDurationState.pullDateRescanMode`     |
| `ec2_scan_mode`                 | string  | When found     | get-configuration → `ec2Configuration.scanModeState.scanMode`                     |
| `ec2_scan_mode_status`          | string  | When found     | get-configuration → `ec2Configuration.scanModeState.scanModeStatus`               |
| `ec2_scan_active`               | boolean | When found     | Derived — any EC2 instance with ACTIVE scan status                                |
| `ecr_scan_active`               | boolean | When found     | Derived — any ECR repository with ACTIVE scan status                              |
| `network_scan_active`           | boolean | When found     | Derived — AWS_ACCOUNT NETWORK scan is ACTIVE                                      |
| `covered_resource_count`        | integer | When found     | Total count of entries in coveredResources                                        |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged configuration + coverage. Empty `{}` when not found |

---

## RecordData Structure

```rust
let merged = serde_json::json!({
    "Configuration": configuration_response,   // get-configuration
    "Coverage": coverage_response,             // list-coverage
});
```

### Configuration paths (from get-configuration)

| Path                                                                    | Type   | Example Value      |
| ----------------------------------------------------------------------- | ------ | ------------------ |
| `Configuration.ecrConfiguration.rescanDurationState.rescanDuration`     | string | `"DAYS_14"`        |
| `Configuration.ecrConfiguration.rescanDurationState.pullDateRescanMode` | string | `"LAST_IN_USE_AT"` |
| `Configuration.ec2Configuration.scanModeState.scanMode`                 | string | `"EC2_HYBRID"`     |
| `Configuration.ec2Configuration.scanModeState.scanModeStatus`           | string | `"SUCCESS"`        |

### Coverage paths (from list-coverage)

| Path                                                        | Type   | Example Value           |
| ----------------------------------------------------------- | ------ | ----------------------- |
| `Coverage.coveredResources.0.resourceType`                  | string | `"AWS_ACCOUNT"`         |
| `Coverage.coveredResources.0.scanType`                      | string | `"NETWORK"`             |
| `Coverage.coveredResources.0.scanStatus.statusCode`         | string | `"ACTIVE"`              |
| `Coverage.coveredResources.1.resourceType`                  | string | `"AWS_EC2_INSTANCE"`    |
| `Coverage.coveredResources.1.scanStatus.statusCode`         | string | `"ACTIVE"`              |
| `Coverage.coveredResources.1.resourceMetadata.ec2.platform` | string | `"LINUX"`               |
| `Coverage.coveredResources.1.scanMode`                      | string | `"EC2_SSM_AGENT_BASED"` |

---

## State Fields

### Scalar State Fields

| State Field                     | Type    | Allowed Operations   | Maps To Collected Field         |
| ------------------------------- | ------- | -------------------- | ------------------------------- |
| `found`                         | boolean | `=`, `!=`            | `found`                         |
| `ecr_rescan_duration`           | string  | `=`, `!=`            | `ecr_rescan_duration`           |
| `ecr_pull_date_rescan_duration` | string  | `=`, `!=`            | `ecr_pull_date_rescan_duration` |
| `ecr_pull_date_rescan_mode`     | string  | `=`, `!=`            | `ecr_pull_date_rescan_mode`     |
| `ec2_scan_mode`                 | string  | `=`, `!=`            | `ec2_scan_mode`                 |
| `ec2_scan_mode_status`          | string  | `=`, `!=`            | `ec2_scan_mode_status`          |
| `ec2_scan_active`               | boolean | `=`, `!=`            | `ec2_scan_active`               |
| `ecr_scan_active`               | boolean | `=`, `!=`            | `ecr_scan_active`               |
| `network_scan_active`           | boolean | `=`, `!=`            | `network_scan_active`           |
| `covered_resource_count`        | int     | `=`, `!=`, `>=`, `>` | `covered_resource_count`        |

### Record Checks

| State Field | Maps To Collected Field | Description                                        |
| ----------- | ----------------------- | -------------------------------------------------- |
| `record`    | `resource`              | Deep inspection of merged configuration + coverage |

---

## Collection Strategy

| Property                     | Value                              |
| ---------------------------- | ---------------------------------- |
| Collector ID                 | `aws_inspector2_account_collector` |
| Collector Type               | `aws_inspector2_account`           |
| Collection Mode              | Content                            |
| Required Capabilities        | `aws_cli`, `inspector2_read`       |
| Expected Collection Time     | ~3000ms (two API calls)            |
| Memory Usage                 | ~5MB                               |
| Network Intensive            | Yes                                |
| CPU Intensive                | No                                 |
| Requires Elevated Privileges | No                                 |
| Batch Collection             | No                                 |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["inspector2:GetConfiguration", "inspector2:ListCoverage"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                   |
| ----------- | ----------------------------------------------------------------------- |
| method_type | `ApiCall`                                                               |
| description | `"Query Inspector2 scan configuration and coverage status via AWS CLI"` |
| target      | `"inspector2:account"`                                                  |
| command     | `"aws inspector2 get-configuration + list-coverage"`                    |
| inputs      | `region` (when provided)                                                |

---

## ESP Examples

### Inspector2 enabled with EC2 and ECR scanning active (KSI-SCR-MON, KSI-PIY-RVD)

```esp
META
    esp_id `ksi-scr-inspector2-scanning-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `aws`
    criticality `high`
    control_mapping `KSI:KSI-SCR-MON,KSI:KSI-PIY-RVD`
    control_objective `KSI-SCR-MON,KSI-PIY-RVD`
    title `Inspector2 EC2 and ECR scanning active`
META_END

DEF
    OBJECT inspector2
        region `us-east-1`
    OBJECT_END

    STATE inspector2_compliant
        found boolean = true
        ec2_scan_active boolean = true
        ecr_scan_active boolean = true
        network_scan_active boolean = true
        ec2_scan_mode_status string = `SUCCESS`
    STATE_END

    CRI AND
        CTN aws_inspector2_account
            TEST all all AND
            STATE_REF inspector2_compliant
            OBJECT_REF inspector2
        CTN_END
    CRI_END
DEF_END
```

### ECR rescan duration validation

```esp
OBJECT inspector2
    region `us-east-1`
OBJECT_END

STATE ecr_scan_configured
    found boolean = true
    ecr_scan_active boolean = true
    ecr_rescan_duration string = `DAYS_14`
    ecr_pull_date_rescan_mode string = `LAST_IN_USE_AT`
STATE_END

CTN aws_inspector2_account
    TEST all all AND
    STATE_REF ecr_scan_configured
    OBJECT_REF inspector2
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT inspector2
    region `us-east-1`
OBJECT_END

STATE inspector2_details
    found boolean = true
    record
        field Configuration.ecrConfiguration.rescanDurationState.rescanDuration string = `DAYS_14`
        field Configuration.ec2Configuration.scanModeState.scanMode string = `EC2_HYBRID`
        field Configuration.ec2Configuration.scanModeState.scanModeStatus string = `SUCCESS`
    record_end
STATE_END

CTN aws_inspector2_account
    TEST all all AND
    STATE_REF inspector2_details
    OBJECT_REF inspector2
CTN_END
```

---

## Error Conditions

| Condition                                        | Error Type              | Outcome                 | Notes                                                      |
| ------------------------------------------------ | ----------------------- | ----------------------- | ---------------------------------------------------------- |
| Inspector2 not enabled (`AccessDeniedException`) | N/A (not an error)      | `found=false`           | `resource` set to empty `{}`, scalar fields absent         |
| `aws` CLI binary not found                       | `CollectionFailed`      | Error                   | `Command::new("aws")` fails to spawn                       |
| Invalid AWS credentials                          | `CollectionFailed`      | Error                   | CLI returns non-zero exit with credential error            |
| IAM access denied                                | `CollectionFailed`      | Error                   | stderr matched `AccessDenied` or `UnauthorizedAccess`      |
| No EC2 instances covered                         | N/A                     | `ec2_scan_active=false` | No AWS_EC2_INSTANCE entries with ACTIVE status             |
| No ECR repositories covered                      | N/A                     | `ecr_scan_active=false` | No AWS_ECR_REPOSITORY entries with ACTIVE status           |
| JSON parse failure                               | `CollectionFailed`      | Error                   | `serde_json::from_str` fails on stdout                     |
| Incompatible CTN type                            | `CtnContractValidation` | Error                   | Collector validates `ctn_type == "aws_inspector2_account"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail**
- Record checks will **fail** with message `"Inspector2 not enabled, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                 | Relationship                                                                |
| ------------------------ | --------------------------------------------------------------------------- |
| `aws_ecr_repository`     | Inspector2 scans ECR repositories; validate repo config alongside coverage  |
| `aws_guardduty_detector` | GuardDuty EBS malware complements Inspector2 package vulnerability scanning |
| `aws_macie2_account`     | Macie2 covers sensitive data; Inspector2 covers vulnerabilities             |
