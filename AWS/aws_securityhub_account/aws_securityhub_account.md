# aws_securityhub_account

## Overview

Validates AWS Security Hub account configuration via the AWS CLI. Makes three sequential API calls: `describe-hub` for base configuration, `get-enabled-standards` for standards subscriptions, and `list-finding-aggregators` + `get-finding-aggregator` for cross-region aggregation configuration. All results are merged into scalar fields and a single RecordData object for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with Security Hub read permissions)
**Collection Method:** Three or four sequential AWS CLI commands per object via `AwsClient`

**Note:** Security Hub has one hub per account per region. The `detector_id` concept does not apply — the hub is identified by the account and region alone. The object requires no identifier field beyond optional `region`.

**Note:** Standards subscriptions are derived into per-standard boolean scalars by pattern-matching the `StandardsArn` string. This avoids exposing raw array indices in record checks for the most common compliance use cases.

---

## Object Fields

| Field    | Type   | Required | Description                                | Example     |
| -------- | ------ | -------- | ------------------------------------------ | ----------- |
| `region` | string | No       | AWS region override (passed as `--region`) | `us-east-1` |

- No identifier field is required — Security Hub has exactly one hub per account per region.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

### Command 1: describe-hub

Retrieves base Security Hub account configuration.

**Collector call:** `client.execute("securityhub", "describe-hub", &[])`

**Resulting command:**

```
aws securityhub describe-hub --output json
aws securityhub describe-hub --region us-east-1 --output json    # with region
```

**Sample response:**

```json
{
  "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
  "SubscribedAt": "2026-03-24T16:02:47.820Z",
  "AutoEnableControls": true,
  "ControlFindingGenerator": "SECURITY_CONTROL"
}
```

**Response parsing:**

- `HubArn` → `hub_arn` scalar
- `AutoEnableControls` → `auto_enable_controls` scalar (boolean)
- `ControlFindingGenerator` → `control_finding_generator` scalar
- Full response stored under `Hub` key in RecordData

If Security Hub is not enabled in the account/region, the API returns a non-zero exit with `InvalidAccessException`. The collector treats this as `found = false`.

---

### Command 2: get-enabled-standards

Retrieves all enabled standards subscriptions.

**Collector call:** `client.execute("securityhub", "get-enabled-standards", &[])`

**Resulting command:**

```
aws securityhub get-enabled-standards --output json
```

**Sample response:**

```json
{
  "StandardsSubscriptions": [
    {
      "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
      "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
      "StandardsInput": {},
      "StandardsStatus": "READY",
      "StandardsControlsUpdatable": "READY_FOR_UPDATES"
    },
    {
      "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0",
      "StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
      "StandardsInput": {},
      "StandardsStatus": "READY",
      "StandardsControlsUpdatable": "READY_FOR_UPDATES"
    },
    {
      "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/nist-800-53/v/5.0.0",
      "StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
      "StandardsInput": {},
      "StandardsStatus": "READY",
      "StandardsControlsUpdatable": "READY_FOR_UPDATES"
    }
  ]
}
```

**Response parsing:**

Per-standard boolean scalars are derived by checking if any subscription's `StandardsArn` contains a known identifier string:

| Scalar Field                   | StandardsArn contains                      |
| ------------------------------ | ------------------------------------------ |
| `standard_fsbp_enabled`        | `aws-foundational-security-best-practices` |
| `standard_nist_800_53_enabled` | `nist-800-53`                              |
| `standard_cis_enabled`         | `cis-aws-foundations-benchmark`            |

A standard is considered enabled only when its `StandardsStatus` is `"READY"`.

`standards_count` scalar = total number of subscriptions with `StandardsStatus == "READY"`.

Full response stored under `Standards` key in RecordData.

---

### Command 3: list-finding-aggregators

Retrieves the finding aggregator ARN if one is configured.

**Collector call:** `client.execute("securityhub", "list-finding-aggregators", &[])`

**Resulting command:**

```
aws securityhub list-finding-aggregators --output json
```

**Sample response:**

```json
{
  "FindingAggregators": [
    {
      "FindingAggregatorArn": "arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/c3d4e5f6-7890-1234-abcd-ef5678901234"
    }
  ]
}
```

**Response parsing:**

- `has_finding_aggregator` derived as `true` if list is non-empty
- `FindingAggregatorArn` stored for use in Command 4

If list is empty, `has_finding_aggregator = false` and Command 4 is skipped.

---

### Command 4: get-finding-aggregator _(only when aggregator exists)_

Retrieves full aggregator configuration.

**Collector call:** `client.execute("securityhub", "get-finding-aggregator", &["--finding-aggregator-arn", arn])`

**Resulting command:**

```
aws securityhub get-finding-aggregator --finding-aggregator-arn arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/c3d4e5f6-7890-1234-abcd-ef5678901234 --output json
```

**Sample response:**

```json
{
  "FindingAggregatorArn": "arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/c3d4e5f6-7890-1234-abcd-ef5678901234",
  "FindingAggregationRegion": "us-east-1",
  "RegionLinkingMode": "ALL_REGIONS"
}
```

**Response parsing:**

- `finding_aggregation_region` → `FindingAggregationRegion` scalar
- `finding_aggregator_region_linking_mode` → `RegionLinkingMode` scalar
- Full response stored under `FindingAggregator` key in RecordData

---

### Error Detection

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `InvalidAccessException`                     | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

`InvalidAccessException` on Command 1 means Security Hub is not enabled — collector sets `found = false` and skips remaining commands.

---

## Collected Data Fields

### Scalar Fields

| Field                                    | Type    | Always Present   | Source                                                             |
| ---------------------------------------- | ------- | ---------------- | ------------------------------------------------------------------ |
| `found`                                  | boolean | Yes              | Derived — `true` if Security Hub is enabled                        |
| `hub_arn`                                | string  | When found       | describe-hub → `HubArn`                                            |
| `auto_enable_controls`                   | boolean | When found       | describe-hub → `AutoEnableControls`                                |
| `control_finding_generator`              | string  | When found       | describe-hub → `ControlFindingGenerator`                           |
| `standards_count`                        | integer | When found       | Derived — count of subscriptions with `StandardsStatus == "READY"` |
| `standard_fsbp_enabled`                  | boolean | When found       | Derived — FSBP subscription exists and is READY                    |
| `standard_nist_800_53_enabled`           | boolean | When found       | Derived — NIST 800-53 subscription exists and is READY             |
| `standard_cis_enabled`                   | boolean | When found       | Derived — CIS Foundations subscription exists and is READY         |
| `has_finding_aggregator`                 | boolean | When found       | Derived — `true` if finding aggregator is configured               |
| `finding_aggregation_region`             | string  | When agg. exists | get-finding-aggregator → `FindingAggregationRegion`                |
| `finding_aggregator_region_linking_mode` | string  | When agg. exists | get-finding-aggregator → `RegionLinkingMode`                       |

### RecordData Field

| Field      | Type       | Always Present | Description                                                           |
| ---------- | ---------- | -------------- | --------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged hub + standards + aggregator config. Empty `{}` when not found |

---

## RecordData Structure

```rust
let merged = serde_json::json!({
    "Hub": hub_response,                        // describe-hub
    "Standards": standards_response,            // get-enabled-standards
    "FindingAggregator": aggregator_response,   // get-finding-aggregator (or {})
});
```

### Hub paths (from describe-hub)

| Path                          | Type    | Example Value                                              |
| ----------------------------- | ------- | ---------------------------------------------------------- |
| `Hub.HubArn`                  | string  | `"arn:aws:securityhub:us-east-1:123456789012:hub/default"` |
| `Hub.AutoEnableControls`      | boolean | `true`                                                     |
| `Hub.ControlFindingGenerator` | string  | `"SECURITY_CONTROL"`                                       |
| `Hub.SubscribedAt`            | string  | `"2026-03-24T16:02:47.820Z"`                               |

### Standards paths (from get-enabled-standards)

| Path                                                 | Type   | Example Value                                                                                 |
| ---------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------- |
| `Standards.StandardsSubscriptions.0.StandardsArn`    | string | `"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"`                       |
| `Standards.StandardsSubscriptions.0.StandardsStatus` | string | `"READY"`                                                                                     |
| `Standards.StandardsSubscriptions.1.StandardsArn`    | string | `"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"` |
| `Standards.StandardsSubscriptions.2.StandardsArn`    | string | `"arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"`                              |

### FindingAggregator paths (from get-finding-aggregator)

| Path                                         | Type   | Example Value   |
| -------------------------------------------- | ------ | --------------- |
| `FindingAggregator.FindingAggregationRegion` | string | `"us-east-1"`   |
| `FindingAggregator.RegionLinkingMode`        | string | `"ALL_REGIONS"` |

---

## State Fields

### Scalar State Fields

| State Field                              | Type    | Allowed Operations              | Maps To Collected Field                  |
| ---------------------------------------- | ------- | ------------------------------- | ---------------------------------------- |
| `found`                                  | boolean | `=`, `!=`                       | `found`                                  |
| `hub_arn`                                | string  | `=`, `!=`, `contains`, `starts` | `hub_arn`                                |
| `auto_enable_controls`                   | boolean | `=`, `!=`                       | `auto_enable_controls`                   |
| `control_finding_generator`              | string  | `=`, `!=`                       | `control_finding_generator`              |
| `standards_count`                        | int     | `=`, `!=`, `>=`, `>`            | `standards_count`                        |
| `standard_fsbp_enabled`                  | boolean | `=`, `!=`                       | `standard_fsbp_enabled`                  |
| `standard_nist_800_53_enabled`           | boolean | `=`, `!=`                       | `standard_nist_800_53_enabled`           |
| `standard_cis_enabled`                   | boolean | `=`, `!=`                       | `standard_cis_enabled`                   |
| `has_finding_aggregator`                 | boolean | `=`, `!=`                       | `has_finding_aggregator`                 |
| `finding_aggregation_region`             | string  | `=`, `!=`                       | `finding_aggregation_region`             |
| `finding_aggregator_region_linking_mode` | string  | `=`, `!=`                       | `finding_aggregator_region_linking_mode` |

### Record Checks

| State Field | Maps To Collected Field | Description                                            |
| ----------- | ----------------------- | ------------------------------------------------------ |
| `record`    | `resource`              | Deep inspection of merged hub + standards + aggregator |

---

## Collection Strategy

| Property                     | Value                               |
| ---------------------------- | ----------------------------------- |
| Collector ID                 | `aws_securityhub_account_collector` |
| Collector Type               | `aws_securityhub_account`           |
| Collection Mode              | Content                             |
| Required Capabilities        | `aws_cli`, `securityhub_read`       |
| Expected Collection Time     | ~5000ms (three or four API calls)   |
| Memory Usage                 | ~5MB                                |
| Network Intensive            | Yes                                 |
| CPU Intensive                | No                                  |
| Requires Elevated Privileges | No                                  |
| Batch Collection             | No                                  |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "securityhub:DescribeHub",
    "securityhub:GetEnabledStandards",
    "securityhub:ListFindingAggregators",
    "securityhub:GetFindingAggregator"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------ |
| method_type | `ApiCall`                                                                                                    |
| description | `"Query Security Hub account configuration, standards, and aggregator via AWS CLI"`                          |
| target      | `"securityhub:account"`                                                                                      |
| command     | `"aws securityhub describe-hub + get-enabled-standards + list-finding-aggregators + get-finding-aggregator"` |
| inputs      | `region` (when provided)                                                                                     |

---

## ESP Examples

### Security Hub enabled with required standards (KSI-SVC-EIS, KSI-MLA-OSM)

```esp
META
    esp_id `example-org-securityhub-compliant`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `aws`
    criticality `high`
    control_mapping `NIST-800-53:CA-7,NIST-800-53:SI-4,KSI:KSI-SVC-EIS,KSI:KSI-MLA-OSM`
    title `Security Hub enabled with FSBP and NIST 800-53 standards`
META_END

DEF
    OBJECT security_hub
        region `us-east-1`
    OBJECT_END

    STATE hub_compliant
        found boolean = true
        auto_enable_controls boolean = true
        standard_fsbp_enabled boolean = true
        standard_nist_800_53_enabled boolean = true
        standards_count int >= 2
    STATE_END

    CRI AND
        CTN aws_securityhub_account
            TEST all all AND
            STATE_REF hub_compliant
            OBJECT_REF security_hub
        CTN_END
    CRI_END
DEF_END
```

### Cross-region aggregation validated

```esp
OBJECT security_hub
    region `us-east-1`
OBJECT_END

STATE aggregation_compliant
    found boolean = true
    has_finding_aggregator boolean = true
    finding_aggregator_region_linking_mode string = `ALL_REGIONS`
    finding_aggregation_region string = `us-east-1`
STATE_END

CTN aws_securityhub_account
    TEST all all AND
    STATE_REF aggregation_compliant
    OBJECT_REF security_hub
CTN_END
```

### All three standards active

```esp
OBJECT security_hub
    region `us-east-1`
OBJECT_END

STATE all_standards_active
    found boolean = true
    standard_fsbp_enabled boolean = true
    standard_nist_800_53_enabled boolean = true
    standard_cis_enabled boolean = true
    standards_count int >= 3
STATE_END

CTN aws_securityhub_account
    TEST all all AND
    STATE_REF all_standards_active
    OBJECT_REF security_hub
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT security_hub
    region `us-east-1`
OBJECT_END

STATE hub_details
    found boolean = true
    record
        field Hub.AutoEnableControls boolean = true
        field Hub.ControlFindingGenerator string = `SECURITY_CONTROL`
        field FindingAggregator.RegionLinkingMode string = `ALL_REGIONS`
        field Standards.StandardsSubscriptions.0.StandardsStatus string = `READY`
    record_end
STATE_END

CTN aws_securityhub_account
    TEST all all AND
    STATE_REF hub_details
    OBJECT_REF security_hub
CTN_END
```

---

## Error Conditions

| Condition                                           | Error Type              | Outcome                        | Notes                                                       |
| --------------------------------------------------- | ----------------------- | ------------------------------ | ----------------------------------------------------------- |
| Security Hub not enabled (`InvalidAccessException`) | N/A (not an error)      | `found=false`                  | `resource` set to empty `{}`, scalar fields absent          |
| `aws` CLI binary not found                          | `CollectionFailed`      | Error                          | `Command::new("aws")` fails to spawn                        |
| Invalid AWS credentials                             | `CollectionFailed`      | Error                          | CLI returns non-zero exit with credential error             |
| IAM access denied                                   | `CollectionFailed`      | Error                          | stderr matched `AccessDenied` or `UnauthorizedAccess`       |
| No finding aggregator configured                    | N/A                     | `has_finding_aggregator=false` | Command 4 skipped                                           |
| JSON parse failure                                  | `CollectionFailed`      | Error                          | `serde_json::from_str` fails on stdout                      |
| Incompatible CTN type                               | `CtnContractValidation` | Error                          | Collector validates `ctn_type == "aws_securityhub_account"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Security Hub not enabled, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                   | Relationship                                                          |
| -------------------------- | --------------------------------------------------------------------- |
| `aws_guardduty_detector`   | GuardDuty findings flow into Security Hub when integration is enabled |
| `aws_s3_bucket`            | Security Hub findings can be exported to S3 via EventBridge           |
| `aws_cloudwatch_log_group` | Security Hub findings routed to CloudWatch via EventBridge rules      |
