# aws_ecr_repository

## Overview

Validates AWS ECR repository configurations via the AWS CLI. Checks image tag immutability, scan-on-push settings, and encryption configuration. Returns scalar fields for common security checks and the full API response as RecordData for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with ECR read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The ECR API returns **camelCase** field names (e.g., `repositoryName`, `imageTagMutability`), unlike most AWS services which use PascalCase. Record check field paths must use camelCase accordingly.

---

## Object Fields

| Field             | Type   | Required | Description                                | Example                    |
| ----------------- | ------ | -------- | ------------------------------------------ | -------------------------- |
| `repository_name` | string | **Yes**  | ECR repository name (exact match)          | `scanset/transparency-log` |
| `region`          | string | No       | AWS region override (passed as `--region`) | `us-east-1`                |

- `repository_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies (env vars, config file, instance metadata).

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-repositories

Retrieves repository configuration by name.

**Collector call:** `client.execute("ecr", "describe-repositories", &["--repository-names", repo_name])`

**Resulting command:**

```
aws ecr describe-repositories --repository-names scanset/transparency-log --output json
aws ecr describe-repositories --repository-names scanset/transparency-log --region us-east-1 --output json    # with region
```

**Response parsing:**

1. Extract `response["repositories"]` as a JSON array
2. Take the first element (`a.first()`)
3. If the API returns a `RepositoryNotFoundException` error (detected in the error string), set `found = false` rather than returning an error
4. Any other API error is returned as `CollectionError::CollectionFailed`

**Sample response:**

```json
{
  "repositories": [
    {
      "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/scanset/transparency-log",
      "registryId": "123456789012",
      "repositoryName": "scanset/transparency-log",
      "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/scanset/transparency-log",
      "createdAt": "2026-01-15T10:30:00-07:00",
      "imageTagMutability": "IMMUTABLE",
      "imageScanningConfiguration": {
        "scanOnPush": true
      },
      "encryptionConfiguration": {
        "encryptionType": "AES256"
      }
    }
  ]
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

Additionally, the collector checks the error string for `RepositoryNotFoundException`. If matched, it treats this as a not-found condition (`found = false`) rather than a collection error.

---

## Collected Data Fields

### Scalar Fields

| Field                  | Type    | Always Present | Source                                            |
| ---------------------- | ------- | -------------- | ------------------------------------------------- |
| `found`                | boolean | Yes            | Derived — `true` if repository was found          |
| `repository_name`      | string  | When found     | `repositoryName` (string)                         |
| `repository_arn`       | string  | When found     | `repositoryArn` (string)                          |
| `image_tag_mutability` | string  | When found     | `imageTagMutability` (string)                     |
| `scan_on_push`         | boolean | When found     | `imageScanningConfiguration.scanOnPush` (boolean) |
| `encryption_type`      | string  | When found     | `encryptionConfiguration.encryptionType` (string) |

Each field is only added if the corresponding JSON key exists and has the expected type. Missing keys in the AWS response result in the field being absent from collected data.

### RecordData Field

| Field      | Type       | Always Present | Description                                                                    |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------ |
| `resource` | RecordData | Yes            | Full repository object from `describe-repositories`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete repository object as returned by the ECR API. Field paths use **camelCase** as returned by the API.

```rust
let record_data = RecordData::from_json_value(repo.clone());
```

| Path                                     | Type    | Example Value                                                              |
| ---------------------------------------- | ------- | -------------------------------------------------------------------------- |
| `repositoryName`                         | string  | `"scanset/transparency-log"`                                               |
| `repositoryArn`                          | string  | `"arn:aws:ecr:us-east-1:123456789012:repository/scanset/transparency-log"` |
| `repositoryUri`                          | string  | `"123456789012.dkr.ecr.us-east-1.amazonaws.com/scanset/transparency-log"`  |
| `registryId`                             | string  | `"123456789012"`                                                           |
| `imageTagMutability`                     | string  | `"IMMUTABLE"`                                                              |
| `imageScanningConfiguration.scanOnPush`  | boolean | `true`                                                                     |
| `encryptionConfiguration.encryptionType` | string  | `"AES256"`                                                                 |
| `createdAt`                              | string  | `"2026-01-15T10:30:00-07:00"`                                              |

---

## State Fields

### Scalar State Fields

| State Field            | Type    | Allowed Operations              | Maps To Collected Field |
| ---------------------- | ------- | ------------------------------- | ----------------------- |
| `found`                | boolean | `=`, `!=`                       | `found`                 |
| `repository_name`      | string  | `=`, `!=`, `contains`, `starts` | `repository_name`       |
| `repository_arn`       | string  | `=`, `!=`, `contains`, `starts` | `repository_arn`        |
| `image_tag_mutability` | string  | `=`, `!=`                       | `image_tag_mutability`  |
| `scan_on_push`         | boolean | `=`, `!=`                       | `scan_on_push`          |
| `encryption_type`      | string  | `=`, `!=`                       | `encryption_type`       |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **camelCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `aws_ecr_repository_collector` |
| Collector Type               | `aws_ecr_repository`           |
| Collection Mode              | Content                        |
| Required Capabilities        | `aws_cli`, `ecr_read`          |
| Expected Collection Time     | ~2000ms                        |
| Memory Usage                 | ~5MB                           |
| Network Intensive            | Yes                            |
| CPU Intensive                | No                             |
| Requires Elevated Privileges | No                             |
| Batch Collection             | No                             |

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
  "Action": ["ecr:DescribeRepositories"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                |
| ----------- | ---------------------------------------------------- |
| method_type | `ApiCall`                                            |
| description | `"Query ECR repository configuration via AWS CLI"`   |
| target      | `"ecr:<repository_name>"`                            |
| command     | `"aws ecr describe-repositories"`                    |
| inputs      | `repository_name` (always), `region` (when provided) |

---

## ESP Examples

### Repository hardened with immutable tags and scanning

```esp
OBJECT tlog_repo
    repository_name `scanset/transparency-log`
    region `us-east-1`
OBJECT_END

STATE repo_hardened
    found boolean = true
    image_tag_mutability string = `IMMUTABLE`
    scan_on_push boolean = true
    encryption_type string = `AES256`
STATE_END

CTN aws_ecr_repository
    TEST all all AND
    STATE_REF repo_hardened
    OBJECT_REF tlog_repo
CTN_END
```

### Validate encryption is KMS-managed

```esp
OBJECT app_repo
    repository_name `myapp/backend`
    region `us-west-2`
OBJECT_END

STATE kms_encrypted
    found boolean = true
    encryption_type string = `KMS`
STATE_END

CTN aws_ecr_repository
    TEST all all AND
    STATE_REF kms_encrypted
    OBJECT_REF app_repo
CTN_END
```

### Record checks for deep inspection

```esp
OBJECT tlog_repo
    repository_name `scanset/transparency-log`
    region `us-east-1`
OBJECT_END

STATE repo_details
    found boolean = true
    record
        field imageTagMutability string = `IMMUTABLE`
        field imageScanningConfiguration.scanOnPush boolean = true
        field encryptionConfiguration.encryptionType string = `AES256`
    record_end
STATE_END

CTN aws_ecr_repository
    TEST all all AND
    STATE_REF repo_details
    OBJECT_REF tlog_repo
CTN_END
```

---

## Error Conditions

| Condition                                            | Error Type                   | Outcome       | Notes                                                  |
| ---------------------------------------------------- | ---------------------------- | ------------- | ------------------------------------------------------ |
| Repository not found (`RepositoryNotFoundException`) | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent     |
| `repository_name` missing from object                | `InvalidObjectConfiguration` | Error         | Required field — collector returns immediately         |
| `aws` CLI binary not found                           | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                   |
| Invalid AWS credentials                              | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error        |
| IAM access denied                                    | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`  |
| JSON parse failure                                   | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                 |
| Incompatible CTN type                                | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_ecr_repository"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"ECR repo not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type          | Relationship                       |
| ----------------- | ---------------------------------- |
| `aws_eks_cluster` | EKS pulls images from ECR          |
| `k8s_resource`    | Pod specs reference ECR image URIs |
