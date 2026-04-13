# aws_s3_bucket

## Overview

Validates AWS S3 bucket configuration via the AWS CLI. Makes six sequential API calls to collect encryption, versioning, public access block, lifecycle, bucket policy, and location settings. An optional seventh call (`get-bucket-tagging`) is made when the `include_tagging` behavior is set. All results are merged into scalar fields and a single RecordData object for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with S3 read permissions)
**Collection Method:** Six sequential AWS CLI commands per object via `AwsClient` (seven when `include_tagging` is set)

---

## Object Fields

| Field         | Type   | Required | Description                                | Example                             |
| ------------- | ------ | -------- | ------------------------------------------ | ----------------------------------- |
| `bucket_name` | string | **Yes**  | S3 bucket name (exact match)               | `example-org-security-findings` |
| `region`      | string | No       | AWS region override (passed as `--region`) | `us-east-1`                         |

- `bucket_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies (env vars, config file, instance metadata).
- `LocationConstraint` is `null` in API responses for `us-east-1` buckets. The collector normalizes this to the string `"us-east-1"`.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command 1: get-bucket-encryption

**Collector call:** `client.execute("s3api", "get-bucket-encryption", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-encryption --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "ServerSideEncryptionConfiguration": {
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "aws:kms",
          "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        },
        "BucketKeyEnabled": true
      }
    ]
  }
}
```

**Response parsing:** Extract `Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm`, `Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID`, and `Rules[0].BucketKeyEnabled`. If the bucket has no encryption configured, the API returns a `ServerSideEncryptionConfigurationNotFoundError` — the collector treats this as missing fields (not a collection error).

---

### Command 2: get-bucket-versioning

**Collector call:** `client.execute("s3api", "get-bucket-versioning", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-versioning --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "Status": "Enabled"
}
```

**Response parsing:** Extract `Status` as a string. If versioning has never been enabled, the response is an empty object `{}` and the field is absent from collected data.

---

### Command 3: get-public-access-block

**Collector call:** `client.execute("s3api", "get-public-access-block", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-public-access-block --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

**Response parsing:** Extract all four booleans from `PublicAccessBlockConfiguration`. If the public access block is not configured, the API returns `NoSuchPublicAccessBlockConfiguration` — the collector treats this as missing fields.

---

### Command 4: get-bucket-lifecycle-configuration

**Collector call:** `client.execute("s3api", "get-bucket-lifecycle-configuration", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-lifecycle-configuration --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "TransitionDefaultMinimumObjectSize": "all_storage_classes_128K",
  "Rules": [
    {
      "Expiration": {
        "Days": 2555
      },
      "ID": "findings-retention",
      "Filter": {
        "Prefix": ""
      },
      "Status": "Enabled",
      "Transitions": [
        {
          "Days": 365,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 90,
          "StorageClass": "STANDARD_IA"
        }
      ]
    }
  ]
}
```

**Response parsing:** Extract `Rules` as a JSON array. The scalar field `lifecycle_enabled` is derived as `true` if any rule with `Status == "Enabled"` exists. If no lifecycle configuration exists, the API returns `NoSuchLifecycleConfiguration` — the collector sets `lifecycle_enabled` to `false`.

---

### Command 5: get-bucket-policy

**Collector call:** `client.execute("s3api", "get-bucket-policy", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-policy --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[...]}"
}
```

**Response parsing:** The `Policy` field is a JSON-encoded string. The collector parses it with `serde_json::from_str` into a `serde_json::Value` and stores the parsed object as the `policy` key in the RecordData. The scalar `has_bucket_policy` is set to `true` if the policy exists. If no bucket policy is configured, the API returns `NoSuchBucketPolicy` — the collector sets `has_bucket_policy` to `false`.

---

### Command 6: get-bucket-location

**Collector call:** `client.execute("s3api", "get-bucket-location", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-location --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "LocationConstraint": null
}
```

**Response parsing:** Extract `LocationConstraint`. When `null` (us-east-1 buckets), normalize to the string `"us-east-1"`. Otherwise use the string value directly.

---

### Command 7: get-bucket-tagging _(only when `include_tagging` behavior is set)_

**Collector call:** `client.execute("s3api", "get-bucket-tagging", &["--bucket", bucket_name])`

**Resulting command:**

```
aws s3api get-bucket-tagging --bucket example-org-security-findings --output json
```

**Sample response:**

```json
{
  "TagSet": [
    { "Key": "Name", "Value": "example-org-security-findings" },
    { "Key": "Environment", "Value": "demo" },
    { "Key": "ManagedBy", "Value": "terraform" },
    { "Key": "Owner", "Value": "admin" }
  ]
}
```

**Response parsing:** The full response is stored under the `Tags` key in RecordData. Each tag is also flattened into a scalar field named `tag_key:<Key>` with the tag value as a string. If the bucket has no tags, the API returns `NoSuchTagSet` — the collector treats this as an empty tag set (not an error).

---

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

The following API errors are treated as **missing configuration** (not collection errors) and result in absent scalar fields rather than `Outcome::Error`:

| API Error                                        | Affected Command                   | Behavior                              |
| ------------------------------------------------ | ---------------------------------- | ------------------------------------- |
| `ServerSideEncryptionConfigurationNotFoundError` | get-bucket-encryption              | Fields absent                         |
| `NoSuchPublicAccessBlockConfiguration`           | get-public-access-block            | Fields absent                         |
| `NoSuchLifecycleConfiguration`                   | get-bucket-lifecycle-configuration | `lifecycle_enabled = false`           |
| `NoSuchBucketPolicy`                             | get-bucket-policy                  | `has_bucket_policy = false`           |
| `NoSuchTagSet`                                   | get-bucket-tagging                 | No tag fields collected, not an error |

If the bucket itself does not exist (e.g., `NoSuchBucket` from Command 1), the collector sets `found = false` and skips all remaining commands.

All other `AwsError` variants are mapped to `CollectionError::CollectionFailed`.

---

## Collected Data Fields

### Scalar Fields

| Field                     | Type    | Always Present                 | Source                                                                               |
| ------------------------- | ------- | ------------------------------ | ------------------------------------------------------------------------------------ |
| `found`                   | boolean | Yes                            | Derived — `true` if bucket exists                                                    |
| `bucket_name`             | string  | When found                     | Object field (echoed back for traceability)                                          |
| `region`                  | string  | When found                     | get-bucket-location → `LocationConstraint` (normalized, `null` → `us-east-1`)        |
| `versioning_status`       | string  | When found                     | get-bucket-versioning → `Status`                                                     |
| `sse_algorithm`           | string  | When found                     | get-bucket-encryption → `Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm`   |
| `kms_master_key_id`       | string  | When found                     | get-bucket-encryption → `Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID` |
| `bucket_key_enabled`      | boolean | When found                     | get-bucket-encryption → `Rules[0].BucketKeyEnabled`                                  |
| `block_public_acls`       | boolean | When found                     | get-public-access-block → `PublicAccessBlockConfiguration.BlockPublicAcls`           |
| `ignore_public_acls`      | boolean | When found                     | get-public-access-block → `PublicAccessBlockConfiguration.IgnorePublicAcls`          |
| `block_public_policy`     | boolean | When found                     | get-public-access-block → `PublicAccessBlockConfiguration.BlockPublicPolicy`         |
| `restrict_public_buckets` | boolean | When found                     | get-public-access-block → `PublicAccessBlockConfiguration.RestrictPublicBuckets`     |
| `lifecycle_enabled`       | boolean | When found                     | Derived — `true` if any enabled lifecycle rule exists                                |
| `has_bucket_policy`       | boolean | When found                     | Derived — `true` if a bucket policy exists                                           |
| `ssl_enforced`            | boolean | When found                     | Derived — `true` if policy contains a `Deny` + `aws:SecureTransport=false` statement |
| `tag_key:<Key>`           | string  | When found + `include_tagging` | One field per tag. E.g. `tag_key:Environment` → `"demo"`                             |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                                                               |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged configuration from all API calls. Empty `{}` when not found. `Tags` key only present when `include_tagging` is set |

---

## RecordData Structure

The `resource` field is built by merging all six API responses under named keys:

```rust
let mut merged = serde_json::json!({});
merged["Encryption"] = encryption_response;           // get-bucket-encryption
merged["Versioning"] = versioning_response;           // get-bucket-versioning
merged["PublicAccessBlock"] = public_access_response; // get-public-access-block
merged["Lifecycle"] = lifecycle_response;             // get-bucket-lifecycle-configuration
merged["Policy"] = parsed_policy_object;              // get-bucket-policy (parsed from string)
merged["Location"] = location_response;               // get-bucket-location
let record_data = RecordData::from_json_value(merged);
```

### Top-level paths

| Path                                                                                                     | Type    | Example Value                                  |
| -------------------------------------------------------------------------------------------------------- | ------- | ---------------------------------------------- |
| `Encryption.ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault.SSEAlgorithm`   | string  | `"aws:kms"`                                    |
| `Encryption.ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault.KMSMasterKeyID` | string  | `"arn:aws:kms:us-east-1:123456789012:key/..."` |
| `Encryption.ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled`                                  | boolean | `true`                                         |
| `Versioning.Status`                                                                                      | string  | `"Enabled"`                                    |
| `PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls`                                       | boolean | `true`                                         |
| `PublicAccessBlock.PublicAccessBlockConfiguration.IgnorePublicAcls`                                      | boolean | `true`                                         |
| `PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicPolicy`                                     | boolean | `true`                                         |
| `PublicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets`                                 | boolean | `true`                                         |
| `Lifecycle.Rules.0.Status`                                                                               | string  | `"Enabled"`                                    |
| `Lifecycle.Rules.0.ID`                                                                                   | string  | `"findings-retention"`                         |
| `Lifecycle.Rules.0.Expiration.Days`                                                                      | integer | `2555`                                         |
| `Lifecycle.Rules.0.Transitions.0.Days`                                                                   | integer | `90`                                           |
| `Lifecycle.Rules.0.Transitions.0.StorageClass`                                                           | string  | `"STANDARD_IA"`                                |
| `Lifecycle.Rules.0.Transitions.1.Days`                                                                   | integer | `365`                                          |
| `Lifecycle.Rules.0.Transitions.1.StorageClass`                                                           | string  | `"GLACIER"`                                    |
| `Policy.Version`                                                                                         | string  | `"2012-10-17"`                                 |
| `Policy.Statement.0.Sid`                                                                                 | string  | `"DenyNonSSL"`                                 |
| `Policy.Statement.0.Effect`                                                                              | string  | `"Deny"`                                       |
| `Location.LocationConstraint`                                                                            | string  | `null` (us-east-1) or region string            |

### Tags paths _(only when `include_tagging` behavior is set)_

| Path                  | Type   | Example Value                         |
| --------------------- | ------ | ------------------------------------- |
| `Tags.TagSet.0.Key`   | string | `"Name"`                              |
| `Tags.TagSet.0.Value` | string | `"example-org-security-findings"` |
| `Tags.TagSet.1.Key`   | string | `"Environment"`                       |
| `Tags.TagSet.1.Value` | string | `"demo"`                              |

---

## State Fields

### Scalar State Fields

| State Field               | Type    | Allowed Operations              | Maps To Collected Field   |
| ------------------------- | ------- | ------------------------------- | ------------------------- |
| `found`                   | boolean | `=`, `!=`                       | `found`                   |
| `bucket_name`             | string  | `=`, `!=`, `contains`, `starts` | `bucket_name`             |
| `region`                  | string  | `=`, `!=`                       | `region`                  |
| `versioning_status`       | string  | `=`, `!=`                       | `versioning_status`       |
| `sse_algorithm`           | string  | `=`, `!=`                       | `sse_algorithm`           |
| `kms_master_key_id`       | string  | `=`, `!=`, `contains`, `starts` | `kms_master_key_id`       |
| `bucket_key_enabled`      | boolean | `=`, `!=`                       | `bucket_key_enabled`      |
| `block_public_acls`       | boolean | `=`, `!=`                       | `block_public_acls`       |
| `ignore_public_acls`      | boolean | `=`, `!=`                       | `ignore_public_acls`      |
| `block_public_policy`     | boolean | `=`, `!=`                       | `block_public_policy`     |
| `restrict_public_buckets` | boolean | `=`, `!=`                       | `restrict_public_buckets` |
| `lifecycle_enabled`       | boolean | `=`, `!=`                       | `lifecycle_enabled`       |
| `has_bucket_policy`       | boolean | `=`, `!=`                       | `has_bucket_policy`       |
| `ssl_enforced`            | boolean | `=`, `!=`                       | `ssl_enforced`            |
| `tag_key:<Key>`           | string  | `=`, `!=`, `contains`           | `tag_key:<Key>` (dynamic) |

### Behaviors

| Behavior          | Type | Description                                                                                                                                              |
| ----------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `include_tagging` | Flag | Collect bucket tags via `get-bucket-tagging`. Adds one API call. Off by default. Exposes `tag_key:<Key>` scalar fields and `Tags.TagSet.*` record paths. |

**Example usage in ESP:**

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    behavior include_tagging
OBJECT_END
```

### Record Checks

The state field name `record` maps to the collected data field `resource`.

| State Field | Maps To Collected Field | Description                                      |
| ----------- | ----------------------- | ------------------------------------------------ |
| `record`    | `resource`              | Deep inspection of merged six-call configuration |

---

## Collection Strategy

| Property                     | Value                                                   |
| ---------------------------- | ------------------------------------------------------- |
| Collector ID                 | `aws_s3_bucket_collector`                               |
| Collector Type               | `aws_s3_bucket`                                         |
| Collection Mode              | Content                                                 |
| Required Capabilities        | `aws_cli`, `s3_read`                                    |
| Expected Collection Time     | ~6000ms (six API calls); ~7000ms with `include_tagging` |
| Memory Usage                 | ~5MB                                                    |
| Network Intensive            | Yes                                                     |
| CPU Intensive                | No                                                      |
| Requires Elevated Privileges | No                                                      |
| Batch Collection             | No                                                      |

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
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketVersioning",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetLifecycleConfiguration",
    "s3:GetBucketPolicy",
    "s3:GetBucketLocation"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                                                                                                                |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                                                                                                            |
| description | `"Query S3 bucket configuration via AWS CLI (6 API calls)"`                                                                                                          |
| target      | `"s3:<bucket_name>"`                                                                                                                                                 |
| command     | `"aws s3api get-bucket-encryption + get-bucket-versioning + get-public-access-block + get-bucket-lifecycle-configuration + get-bucket-policy + get-bucket-location"` |
| inputs      | `bucket_name` (always), `region` (when provided)                                                                                                                     |

---

## ESP Examples

### Security findings bucket fully hardened (KSI-MLA-OSM)

```esp
META
    esp_id `example-org-security-bucket-hardened`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `aws`
    criticality `high`
    control_mapping `NIST-800-53:AU-9,NIST-800-53:AU-4,NIST-800-53:SC-8,KSI:KSI-MLA-OSM`
    title `Security findings bucket tamper-resistant and encrypted`
META_END

DEF
    OBJECT security_bucket
        bucket_name `example-org-security-findings`
        region `us-east-1`
    OBJECT_END

    STATE bucket_hardened
        found boolean = true
        versioning_status string = `Enabled`
        sse_algorithm string = `aws:kms`
        bucket_key_enabled boolean = true
        block_public_acls boolean = true
        ignore_public_acls boolean = true
        block_public_policy boolean = true
        restrict_public_buckets boolean = true
        lifecycle_enabled boolean = true
        has_bucket_policy boolean = true
        ssl_enforced boolean = true
    STATE_END

    CRI AND
        CTN aws_s3_bucket
            TEST all all AND
            STATE_REF bucket_hardened
            OBJECT_REF security_bucket
        CTN_END
    CRI_END
DEF_END
```

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    region `us-east-1`
OBJECT_END

STATE bucket_hardened
    found boolean = true
    versioning_status string = `Enabled`
    sse_algorithm string = `aws:kms`
    bucket_key_enabled boolean = true
    block_public_acls boolean = true
    ignore_public_acls boolean = true
    block_public_policy boolean = true
    restrict_public_buckets boolean = true
    lifecycle_enabled boolean = true
    has_bucket_policy boolean = true
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF bucket_hardened
    OBJECT_REF security_bucket
CTN_END
```

### KMS key validation

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    region `us-east-1`
OBJECT_END

STATE correct_kms_key
    found boolean = true
    sse_algorithm string = `aws:kms`
    kms_master_key_id string starts `arn:aws:kms:us-east-1:123456789012:`
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF correct_kms_key
    OBJECT_REF security_bucket
CTN_END
```

### Public access fully blocked

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
OBJECT_END

STATE no_public_access
    found boolean = true
    block_public_acls boolean = true
    ignore_public_acls boolean = true
    block_public_policy boolean = true
    restrict_public_buckets boolean = true
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF no_public_access
    OBJECT_REF security_bucket
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    region `us-east-1`
OBJECT_END

STATE bucket_details
    found boolean = true
    record
        field Versioning.Status string = `Enabled`
        field Encryption.ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled boolean = true
        field Encryption.ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault.SSEAlgorithm string = `aws:kms`
        field PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls boolean = true
        field PublicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets boolean = true
        field Lifecycle.Rules.0.Status string = `Enabled`
        field Lifecycle.Rules.0.Expiration.Days int = 2555
    record_end
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF bucket_details
    OBJECT_REF security_bucket
CTN_END
```

### KSI tag compliance validation

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    region `us-east-1`
    behavior include_tagging
OBJECT_END

STATE ksi_tags_present
    found boolean = true
    tag_key:ManagedBy string = `terraform`
    tag_key:Environment string = `demo`
    tag_key:ksi-ksi-mla-osm string contains `SIEM`
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF ksi_tags_present
    OBJECT_REF security_bucket
CTN_END
```

### Record checks for tag deep inspection

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
    region `us-east-1`
    behavior include_tagging
OBJECT_END

STATE tag_details
    found boolean = true
    record
        field Tags.TagSet.0.Key string = `ksi-ksi-mla-osm`
    record_end
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF tag_details
    OBJECT_REF security_bucket
CTN_END
```

```esp
OBJECT security_bucket
    bucket_name `example-org-security-findings`
OBJECT_END

STATE retention_compliant
    found boolean = true
    lifecycle_enabled boolean = true
    record
        field Lifecycle.Rules.0.Expiration.Days int = 2555
        field Lifecycle.Rules.0.Status string = `Enabled`
    record_end
STATE_END

CTN aws_s3_bucket
    TEST all all AND
    STATE_REF retention_compliant
    OBJECT_REF security_bucket
CTN_END
```

---

## Error Conditions

| Condition                              | Error Type                   | Outcome                                         | Notes                                                                    |
| -------------------------------------- | ---------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------ |
| Bucket does not exist (`NoSuchBucket`) | N/A (not an error)           | `found=false`                                   | `resource` set to empty `{}`, scalar fields absent                       |
| `bucket_name` missing from object      | `InvalidObjectConfiguration` | Error                                           | Required field — collector returns immediately                           |
| `aws` CLI binary not found             | `CollectionFailed`           | Error                                           | `Command::new("aws")` fails to spawn                                     |
| Invalid AWS credentials                | `CollectionFailed`           | Error                                           | CLI returns non-zero exit with credential error                          |
| IAM access denied                      | `CollectionFailed`           | Error                                           | stderr matched `AccessDenied` or `UnauthorizedAccess`                    |
| Encryption not configured              | N/A                          | Fields absent                                   | `sse_algorithm`, `kms_master_key_id`, `bucket_key_enabled` not collected |
| Public access block not configured     | N/A                          | Fields absent                                   | All four `block_*` / `restrict_*` fields not collected                   |
| No lifecycle configuration             | N/A                          | `lifecycle_enabled=false`                       | Lifecycle absent treated as disabled                                     |
| No bucket policy                       | N/A                          | `has_bucket_policy=false`, `ssl_enforced=false` | Both derived fields set to false                                         |
| No bucket tags (`NoSuchTagSet`)        | N/A                          | No tag fields collected                         | Only relevant when `include_tagging` is set                              |
| JSON parse failure                     | `CollectionFailed`           | Error                                           | `serde_json::from_str` fails on stdout                                   |
| Incompatible CTN type                  | `CtnContractValidation`      | Error                                           | Collector validates `ctn_type == "aws_s3_bucket"`                        |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"S3 bucket not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                   | Relationship                                                        |
| -------------------------- | ------------------------------------------------------------------- |
| `aws_cloudtrail`           | CloudTrail delivers logs to S3; validate the destination bucket     |
| `aws_guardduty_detector`   | GuardDuty publishes findings to S3; validate the destination bucket |
| `aws_cloudwatch_log_group` | Alternative finding destination alongside S3                        |
