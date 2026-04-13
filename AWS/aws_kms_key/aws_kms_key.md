# aws_kms_key

## Overview

Validates AWS KMS key configuration via the AWS CLI. Makes three sequential API calls: `describe-key` for key metadata, `get-key-rotation-status` for rotation configuration, and `get-key-policy` for the key policy. The key policy is a JSON-encoded string that is parsed and stored as structured RecordData.

**Platform:** AWS (requires `aws` CLI binary with KMS read permissions)
**Collection Method:** Three sequential AWS CLI commands per object via `AwsClient`

**IMPORTANT:** `key_id` must be the key ID (UUID) or full ARN. KMS aliases (`alias/*`) are not supported by `get-key-rotation-status` or `get-key-policy` and will return `InvalidArnException`. Use the key ID from `describe-key` output.

---

## Object Fields

| Field    | Type   | Required | Description                                | Example                                |
| -------- | ------ | -------- | ------------------------------------------ | -------------------------------------- |
| `key_id` | string | **Yes**  | KMS key ID (UUID) or ARN — NOT an alias    | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` |
| `region` | string | No       | AWS region override (passed as `--region`) | `us-east-1`                            |

---

## Commands Executed

### Command 1: describe-key

**Resulting command:**

```
aws kms describe-key --key-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --output json
```

**Sample response (abbreviated):**

```json
{
  "KeyMetadata": {
    "KeyId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "Arn": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "Enabled": true,
    "Description": "ExampleOrg secrets encryption key",
    "KeyUsage": "ENCRYPT_DECRYPT",
    "KeyState": "Enabled",
    "Origin": "AWS_KMS",
    "KeyManager": "CUSTOMER",
    "KeySpec": "SYMMETRIC_DEFAULT",
    "MultiRegion": false
  }
}
```

---

### Command 2: get-key-rotation-status

**Resulting command:**

```
aws kms get-key-rotation-status --key-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --output json
```

**Sample response:**

```json
{
  "KeyRotationEnabled": true,
  "KeyId": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "RotationPeriodInDays": 90,
  "NextRotationDate": "2026-06-21T22:08:43.336000+00:00"
}
```

---

### Command 3: get-key-policy

**Resulting command:**

```
aws kms get-key-policy --key-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee --policy-name default --output json
```

**Sample response (abbreviated):**

```json
{
  "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"RootAccountFullAccess\",...},{\"Sid\":\"SecretsManagerAccess\",...},...]}",
  "PolicyName": "default"
}
```

The `Policy` field is a JSON-encoded string. The collector parses it and stores the structured policy under the `KeyPolicy` key in RecordData.

---

## Collected Data Fields

### Scalar Fields

| Field                     | Type    | Always Present   | Source                                |
| ------------------------- | ------- | ---------------- | ------------------------------------- |
| `found`                   | boolean | Yes              | Derived — `true` if key found         |
| `key_id`                  | string  | When found       | `KeyMetadata.KeyId`                   |
| `key_arn`                 | string  | When found       | `KeyMetadata.Arn`                     |
| `enabled`                 | boolean | When found       | `KeyMetadata.Enabled`                 |
| `key_state`               | string  | When found       | `KeyMetadata.KeyState`                |
| `key_usage`               | string  | When found       | `KeyMetadata.KeyUsage`                |
| `key_spec`                | string  | When found       | `KeyMetadata.KeySpec`                 |
| `key_manager`             | string  | When found       | `KeyMetadata.KeyManager`              |
| `origin`                  | string  | When found       | `KeyMetadata.Origin`                  |
| `multi_region`            | boolean | When found       | `KeyMetadata.MultiRegion`             |
| `description`             | string  | When found       | `KeyMetadata.Description`             |
| `rotation_enabled`        | boolean | When found       | `RotationStatus.KeyRotationEnabled`   |
| `rotation_period_in_days` | integer | When rotation on | `RotationStatus.RotationPeriodInDays` |

### RecordData Field

| Field      | Type       | Always Present | Description                                               |
| ---------- | ---------- | -------------- | --------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged key metadata + rotation status + parsed key policy |

---

## RecordData Structure

```
KeyMetadata.KeyId                         → "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KeyMetadata.Enabled                       → true
KeyMetadata.KeyState                      → "Enabled"
KeyMetadata.KeyUsage                      → "ENCRYPT_DECRYPT"
KeyMetadata.KeyManager                    → "CUSTOMER"
KeyMetadata.KeySpec                       → "SYMMETRIC_DEFAULT"
KeyMetadata.Origin                        → "AWS_KMS"
KeyMetadata.MultiRegion                   → false
RotationStatus.KeyRotationEnabled         → true
RotationStatus.RotationPeriodInDays       → 90
KeyPolicy.Version                         → "2012-10-17"
KeyPolicy.Statement.0.Sid                 → "RootAccountFullAccess"
KeyPolicy.Statement.0.Effect              → "Allow"
KeyPolicy.Statement.0.Principal.AWS       → "arn:aws:iam::123456789012:root"
KeyPolicy.Statement.1.Sid                 → "SecretsManagerAccess"
KeyPolicy.Statement.1.Principal.Service   → "secretsmanager.amazonaws.com"
KeyPolicy.Statement.2.Sid                 → "EC2RoleAccess"
KeyPolicy.Statement.2.Principal.AWS       → "arn:aws:iam::123456789012:role/example-org-ec2-role"
KeyPolicy.Statement.3.Sid                 → "CloudWatchLogsKMS"
KeyPolicy.Statement.4.Sid                 → "CloudTrailKMS"
KeyPolicy.Statement.5.Sid                 → "GuardDutyKMS"
```

---

## State Fields

| State Field               | Type       | Allowed Operations              | Maps To Collected Field   |
| ------------------------- | ---------- | ------------------------------- | ------------------------- |
| `found`                   | boolean    | `=`, `!=`                       | `found`                   |
| `key_id`                  | string     | `=`, `!=`                       | `key_id`                  |
| `key_arn`                 | string     | `=`, `!=`, `contains`, `starts` | `key_arn`                 |
| `enabled`                 | boolean    | `=`, `!=`                       | `enabled`                 |
| `key_state`               | string     | `=`, `!=`                       | `key_state`               |
| `key_usage`               | string     | `=`, `!=`                       | `key_usage`               |
| `key_spec`                | string     | `=`, `!=`                       | `key_spec`                |
| `key_manager`             | string     | `=`, `!=`                       | `key_manager`             |
| `origin`                  | string     | `=`, `!=`                       | `origin`                  |
| `multi_region`            | boolean    | `=`, `!=`                       | `multi_region`            |
| `description`             | string     | `=`, `!=`, `contains`           | `description`             |
| `rotation_enabled`        | boolean    | `=`, `!=`                       | `rotation_enabled`        |
| `rotation_period_in_days` | int        | `=`, `!=`, `<=`, `<`, `>=`, `>` | `rotation_period_in_days` |
| `record`                  | RecordData | (record checks)                 | `resource`                |

---

## Collection Strategy

| Property                     | Value                     |
| ---------------------------- | ------------------------- |
| Collector ID                 | `aws_kms_key_collector`   |
| Collector Type               | `aws_kms_key`             |
| Collection Mode              | Content                   |
| Required Capabilities        | `aws_cli`, `kms_read`     |
| Expected Collection Time     | ~3000ms (three API calls) |
| Memory Usage                 | ~2MB                      |
| Network Intensive            | Yes                       |
| CPU Intensive                | No                        |
| Requires Elevated Privileges | No                        |
| Batch Collection             | No                        |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy"],
  "Resource": "*"
}
```

---

## ESP Examples

### KMS key enabled with rotation (KSI-AFR-UCM, KSI-SCR-MIT)

```esp
OBJECT secrets_kms_key
    key_id `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`
    region `us-east-1`
OBJECT_END

STATE kms_key_compliant
    found boolean = true
    enabled boolean = true
    key_state string = `Enabled`
    key_manager string = `CUSTOMER`
    key_usage string = `ENCRYPT_DECRYPT`
    rotation_enabled boolean = true
    rotation_period_in_days int <= 90
    multi_region boolean = false
STATE_END

CTN aws_kms_key
    TEST all all AND
    STATE_REF kms_key_compliant
    OBJECT_REF secrets_kms_key
CTN_END
```

### Key policy record checks — validate service principals

```esp
STATE kms_policy_valid
    found boolean = true
    record
        field KeyPolicy.Statement.0.Sid string = `RootAccountFullAccess`
        field KeyPolicy.Statement.1.Sid string = `SecretsManagerAccess`
        field KeyPolicy.Statement.1.Principal.Service string = `secretsmanager.amazonaws.com`
        field KeyPolicy.Statement.2.Sid string = `EC2RoleAccess`
        field RotationStatus.KeyRotationEnabled boolean = true
        field RotationStatus.RotationPeriodInDays int = 90
    record_end
STATE_END
```

---

## Error Conditions

| Condition                    | Error Type                   | Outcome       |
| ---------------------------- | ---------------------------- | ------------- |
| Key not found                | N/A (not an error)           | `found=false` |
| Alias used as `key_id`       | `CollectionFailed`           | Error         |
| `key_id` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied            | `CollectionFailed`           | Error         |
| Incompatible CTN type        | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                    | Relationship                                             |
| --------------------------- | -------------------------------------------------------- |
| `aws_secretsmanager_secret` | Secrets are encrypted with this KMS key                  |
| `aws_s3_bucket`             | S3 buckets use this key for SSE-KMS encryption           |
| `aws_backup_vault`          | Backup vaults use this key for recovery point encryption |
| `aws_ebs_volume`            | EBS volumes use this key for encryption at rest          |
