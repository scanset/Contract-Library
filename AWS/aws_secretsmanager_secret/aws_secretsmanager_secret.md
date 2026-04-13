# aws_secretsmanager_secret

## Overview

Validates AWS Secrets Manager secret configuration via the AWS CLI. Makes a single API call using `describe-secret` to retrieve secret metadata including KMS encryption, rotation status, version state, and tags. The secret value is never retrieved — only metadata.

**Platform:** AWS (requires `aws` CLI binary with Secrets Manager read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** `RecoveryWindowInDays` is a creation parameter only and is not returned by `describe-secret`. It cannot be validated via the AWS API.

**Note:** `rotation_enabled` defaults to `false` when the `RotationEnabled` field is absent from the response. This is correct — Secrets Manager omits the field entirely when rotation is not configured rather than returning `false`.

---

## Object Fields

| Field       | Type   | Required | Description                                | Example                          |
| ----------- | ------ | -------- | ------------------------------------------ | -------------------------------- |
| `secret_id` | string | **Yes**  | Secret name or ARN                         | `example-org/db/credentials` |
| `region`    | string | No       | AWS region override (passed as `--region`) | `us-east-1`                      |

---

## Commands Executed

### Command 1: describe-secret

**Collector call:** `client.execute("secretsmanager", "describe-secret", &["--secret-id", secret_id])`

**Resulting command:**

```
aws secretsmanager describe-secret --secret-id example-org/db/credentials --output json
```

**Sample response:**

```json
{
  "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:example-org/db/credentials-Sp6FkL",
  "Name": "example-org/db/credentials",
  "Description": "ExampleOrg PostgreSQL credentials",
  "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "LastChangedDate": "2026-03-23T22:16:21.656000+00:00",
  "LastAccessedDate": "2026-03-25T00:00:00+00:00",
  "Tags": [
    { "Key": "SecretType", "Value": "database" },
    { "Key": "ManagedBy", "Value": "terraform" }
  ],
  "VersionIdsToStages": {
    "terraform-20260323221621262500000001": ["AWSCURRENT"],
    "terraform-20260323220857340500000007": ["AWSPREVIOUS"]
  }
}
```

**Response parsing:**

| Collected Field       | Source                                                          | Notes                                |
| --------------------- | --------------------------------------------------------------- | ------------------------------------ |
| `secret_name`         | `Name`                                                          |                                      |
| `secret_arn`          | `ARN`                                                           |                                      |
| `kms_key_id`          | `KmsKeyId`                                                      | Absent if using AWS managed key      |
| `description`         | `Description`                                                   |                                      |
| `rotation_enabled`    | `RotationEnabled` (absent = false)                              | Derived — defaults false when absent |
| `has_current_version` | Derived: any `VersionIdsToStages` value contains `"AWSCURRENT"` | Confirms secret has active version   |
| `tag_key:<Key>`       | `Tags[*]` flat map                                              | One scalar per tag                   |

---

### Error Detection

| Stderr contains             | Outcome            |
| --------------------------- | ------------------ |
| `ResourceNotFoundException` | `found=false`      |
| `SecretNotFound`            | `found=false`      |
| `AccessDenied`              | `CollectionFailed` |
| Anything else               | `CollectionFailed` |

---

## Collected Data Fields

### Scalar Fields

| Field                 | Type    | Always Present | Source                             |
| --------------------- | ------- | -------------- | ---------------------------------- |
| `found`               | boolean | Yes            | Derived — `true` if secret exists  |
| `secret_name`         | string  | When found     | `Name`                             |
| `secret_arn`          | string  | When found     | `ARN`                              |
| `kms_key_id`          | string  | When encrypted | `KmsKeyId`                         |
| `description`         | string  | When found     | `Description`                      |
| `rotation_enabled`    | boolean | When found     | `RotationEnabled` (absent = false) |
| `has_current_version` | boolean | When found     | Derived from `VersionIdsToStages`  |
| `tag_key:<Key>`       | string  | When found     | One field per tag                  |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `describe-secret` response. Empty `{}` when not found |

---

## RecordData Structure

| Path                                | Type   | Example Value                                                                                  |
| ----------------------------------- | ------ | ---------------------------------------------------------------------------------------------- |
| `Name`                              | string | `"example-org/db/credentials"`                                                             |
| `ARN`                               | string | `"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-org/db/credentials-Sp6FkL"` |
| `KmsKeyId`                          | string | `"arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-..."`                                        |
| `Description`                       | string | `"ExampleOrg PostgreSQL credentials"`                                                          |
| `VersionIdsToStages.<version-id>.0` | string | `"AWSCURRENT"`                                                                                 |
| `Tags.0.Key`                        | string | `"SecretType"`                                                                                 |
| `Tags.0.Value`                      | string | `"database"`                                                                                   |

---

## State Fields

| State Field           | Type       | Allowed Operations              | Maps To Collected Field   |
| --------------------- | ---------- | ------------------------------- | ------------------------- |
| `found`               | boolean    | `=`, `!=`                       | `found`                   |
| `secret_name`         | string     | `=`, `!=`, `contains`, `starts` | `secret_name`             |
| `secret_arn`          | string     | `=`, `!=`, `contains`, `starts` | `secret_arn`              |
| `kms_key_id`          | string     | `=`, `!=`, `contains`, `starts` | `kms_key_id`              |
| `description`         | string     | `=`, `!=`, `contains`           | `description`             |
| `rotation_enabled`    | boolean    | `=`, `!=`                       | `rotation_enabled`        |
| `has_current_version` | boolean    | `=`, `!=`                       | `has_current_version`     |
| `tag_key:<Key>`       | string     | `=`, `!=`, `contains`           | `tag_key:<Key>` (dynamic) |
| `record`              | RecordData | (record checks)                 | `resource`                |

---

## Collection Strategy

| Property                     | Value                                 |
| ---------------------------- | ------------------------------------- |
| Collector ID                 | `aws_secretsmanager_secret_collector` |
| Collector Type               | `aws_secretsmanager_secret`           |
| Collection Mode              | Metadata                              |
| Required Capabilities        | `aws_cli`, `secretsmanager_read`      |
| Expected Collection Time     | ~1500ms                               |
| Memory Usage                 | ~2MB                                  |
| Network Intensive            | Yes                                   |
| CPU Intensive                | No                                    |
| Requires Elevated Privileges | No                                    |
| Batch Collection             | No                                    |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["secretsmanager:DescribeSecret"],
  "Resource": "*"
}
```

---

## ESP Examples

### Secret encrypted with CMK and has active version (KSI-SVC-ASM, KSI-AFR-UCM)

```esp
OBJECT db_secret
    secret_id `example-org/db/credentials`
    region `us-east-1`
OBJECT_END

STATE secret_compliant
    found boolean = true
    kms_key_id string starts `arn:aws:kms:`
    has_current_version boolean = true
STATE_END

CTN aws_secretsmanager_secret
    TEST all all AND
    STATE_REF secret_compliant
    OBJECT_REF db_secret
CTN_END
```

### Validate secret tag for type classification

```esp
STATE secret_tagged
    found boolean = true
    tag_key:SecretType string = `database`
    tag_key:ManagedBy string = `terraform`
STATE_END
```

---

## Error Conditions

| Condition                       | Error Type                   | Outcome       |
| ------------------------------- | ---------------------------- | ------------- |
| Secret not found                | N/A (not an error)           | `found=false` |
| `secret_id` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied               | `CollectionFailed`           | Error         |
| Incompatible CTN type           | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type           | Relationship                                                         |
| ------------------ | -------------------------------------------------------------------- |
| `aws_kms_key`      | KMS key used to encrypt the secret                                   |
| `aws_vpc_endpoint` | Secrets Manager VPC endpoint keeps secret access private             |
| `aws_iam_role`     | EC2 role granted `secretsmanager:GetSecretValue` to retrieve secrets |
