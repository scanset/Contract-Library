# aws_rds_instance

## Overview

Validates AWS RDS database instance configurations via the AWS CLI. Returns scalar summary fields for common security checks and the full API response as RecordData for detailed inspection of security groups, subnet groups, encryption, endpoints, certificates, and storage configuration.

**Platform:** AWS (requires `aws` CLI binary with RDS read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The RDS API returns **PascalCase** field names (e.g., `DBInstanceIdentifier`, `StorageEncrypted`). Record check field paths must use PascalCase accordingly. Tags are under `TagList` (not `Tags` like EC2 resources).

---

## Object Fields

| Field                    | Type   | Required | Description                                | Example                    |
| ------------------------ | ------ | -------- | ------------------------------------------ | -------------------------- |
| `db_instance_identifier` | string | **Yes**  | RDS DB instance identifier (exact match)   | `example-transparency-log` |
| `region`                 | string | No       | AWS region override (passed as `--region`) | `us-east-1`                |

- `db_instance_identifier` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-db-instances

Retrieves DB instance configuration by identifier.

**Collector call:** `client.execute("rds", "describe-db-instances", &["--db-instance-identifier", db_id])`

**Resulting command:**

```
aws rds describe-db-instances --db-instance-identifier example-transparency-log --output json
aws rds describe-db-instances --db-instance-identifier example-transparency-log --region us-east-1 --output json    # with region
```

**Response parsing:**

1. Extract `response["DBInstances"]` as a JSON array
2. Take the first element (`a.first()`)
3. If the API returns a `DBInstanceNotFound` error (detected in the error string), set `found = false` rather than returning an error
4. Any other API error is returned as `CollectionError::CollectionFailed`

**Scalar field extraction:**

The collector uses loop-based extraction for string and boolean fields, iterating over predefined `(collected_field_name, json_key)` pairs:

String fields:

| Collected Field          | JSON Key               | Extraction  |
| ------------------------ | ---------------------- | ----------- |
| `db_instance_identifier` | `DBInstanceIdentifier` | `.as_str()` |
| `db_instance_status`     | `DBInstanceStatus`     | `.as_str()` |
| `engine`                 | `Engine`               | `.as_str()` |
| `engine_version`         | `EngineVersion`        | `.as_str()` |
| `kms_key_id`             | `KmsKeyId`             | `.as_str()` |

Boolean fields:

| Collected Field              | JSON Key                           | Extraction   |
| ---------------------------- | ---------------------------------- | ------------ |
| `storage_encrypted`          | `StorageEncrypted`                 | `.as_bool()` |
| `publicly_accessible`        | `PubliclyAccessible`               | `.as_bool()` |
| `multi_az`                   | `MultiAZ`                          | `.as_bool()` |
| `deletion_protection`        | `DeletionProtection`               | `.as_bool()` |
| `auto_minor_version_upgrade` | `AutoMinorVersionUpgrade`          | `.as_bool()` |
| `iam_auth_enabled`           | `IAMDatabaseAuthenticationEnabled` | `.as_bool()` |

Individually extracted fields:

| Collected Field           | JSON Path                         | Extraction                                     |
| ------------------------- | --------------------------------- | ---------------------------------------------- |
| `backup_retention_period` | `BackupRetentionPeriod`           | `.as_i64()`                                    |
| `vpc_id`                  | `DBSubnetGroup.VpcId`             | `.as_str()`                                    |
| `db_subnet_group_name`    | `DBSubnetGroup.DBSubnetGroupName` | `.as_str()`                                    |
| `tag_name`                | `TagList` array                   | Iterate, find `Key == "Name"`, extract `Value` |

**Sample response (abbreviated):**

```json
{
  "DBInstances": [
    {
      "DBInstanceIdentifier": "example-transparency-log",
      "DBInstanceClass": "db.t4g.micro",
      "DBInstanceStatus": "available",
      "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:example-transparency-log",
      "Engine": "postgres",
      "EngineVersion": "16.4",
      "StorageEncrypted": true,
      "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/b2c3d4e5-f678-9012-abcd-ef3456789012",
      "PubliclyAccessible": false,
      "MultiAZ": false,
      "DeletionProtection": false,
      "AutoMinorVersionUpgrade": true,
      "IAMDatabaseAuthenticationEnabled": false,
      "BackupRetentionPeriod": 7,
      "AllocatedStorage": 20,
      "StorageType": "gp3",
      "Iops": 3000,
      "MaxAllocatedStorage": 100,
      "Endpoint": {
        "Address": "example-transparency-log.cmp6mwcmerdo.us-east-1.rds.amazonaws.com",
        "Port": 5432,
        "HostedZoneId": "Z2R2ITUGPM61AM"
      },
      "VpcSecurityGroups": [
        { "VpcSecurityGroupId": "sg-0bbbbbbbbbbbbbbbb0", "Status": "active" }
      ],
      "DBSubnetGroup": {
        "DBSubnetGroupName": "example-db-subnets",
        "VpcId": "vpc-0fedcba9876543210",
        "Subnets": [
          {
            "SubnetIdentifier": "subnet-0eeeeeeeeeeeeeeee",
            "SubnetAvailabilityZone": { "Name": "us-east-1a" }
          },
          {
            "SubnetIdentifier": "subnet-0cccccccccccccccc",
            "SubnetAvailabilityZone": { "Name": "us-east-1b" }
          }
        ]
      },
      "CACertificateIdentifier": "rds-ca-rsa2048-g1",
      "CertificateDetails": {
        "CAIdentifier": "rds-ca-rsa2048-g1",
        "ValidTill": "2027-02-21T06:25:44+00:00"
      },
      "TagList": [{ "Key": "Project", "Value": "scanset" }]
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

Additionally, the collector checks the error string for `DBInstanceNotFound`. If matched, it treats this as a not-found condition (`found = false`) rather than a collection error.

---

## Collected Data Fields

### Scalar Fields

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`                      | boolean | Yes            | Derived — `true` if instance was found                    |
| `db_instance_identifier`     | string  | When found     | `DBInstanceIdentifier` (string)                           |
| `db_instance_status`         | string  | When found     | `DBInstanceStatus` (string)                               |
| `engine`                     | string  | When found     | `Engine` (string)                                         |
| `engine_version`             | string  | When found     | `EngineVersion` (string)                                  |
| `storage_encrypted`          | boolean | When found     | `StorageEncrypted` (boolean)                              |
| `publicly_accessible`        | boolean | When found     | `PubliclyAccessible` (boolean)                            |
| `multi_az`                   | boolean | When found     | `MultiAZ` (boolean)                                       |
| `deletion_protection`        | boolean | When found     | `DeletionProtection` (boolean)                            |
| `auto_minor_version_upgrade` | boolean | When found     | `AutoMinorVersionUpgrade` (boolean)                       |
| `iam_auth_enabled`           | boolean | When found     | `IAMDatabaseAuthenticationEnabled` (boolean)              |
| `backup_retention_period`    | int     | When found     | `BackupRetentionPeriod` (i64)                             |
| `vpc_id`                     | string  | When found     | `DBSubnetGroup.VpcId` (string) — nested field             |
| `db_subnet_group_name`       | string  | When found     | `DBSubnetGroup.DBSubnetGroupName` (string) — nested field |
| `kms_key_id`                 | string  | When found     | `KmsKeyId` (string) — only present if encrypted           |
| `tag_name`                   | string  | When found     | `TagList` array — value of the tag where `Key == "Name"`  |

Each field is only added if the corresponding JSON key exists and has the expected type.

### RecordData Field

| Field      | Type       | Always Present | Description                                                                     |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full DB instance object from `describe-db-instances`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete DB instance object as returned by the RDS API:

```rust
let record_data = RecordData::from_json_value(db.clone());
```

### Identity and status

| Path                   | Type   | Example Value                                                      |
| ---------------------- | ------ | ------------------------------------------------------------------ |
| `DBInstanceIdentifier` | string | `"example-transparency-log"`                                       |
| `DBInstanceStatus`     | string | `"available"`                                                      |
| `DBInstanceClass`      | string | `"db.t4g.micro"`                                                   |
| `DBInstanceArn`        | string | `"arn:aws:rds:us-east-1:123456789012:db:example-transparency-log"` |
| `Engine`               | string | `"postgres"`                                                       |
| `EngineVersion`        | string | `"16.4"`                                                           |

### Security and encryption

| Path                               | Type    | Example Value                                           |
| ---------------------------------- | ------- | ------------------------------------------------------- |
| `StorageEncrypted`                 | boolean | `true`                                                  |
| `KmsKeyId`                         | string  | `"arn:aws:kms:us-east-1:123456789012:key/8783e3f3-..."` |
| `PubliclyAccessible`               | boolean | `false`                                                 |
| `IAMDatabaseAuthenticationEnabled` | boolean | `false`                                                 |
| `DeletionProtection`               | boolean | `false`                                                 |
| `CACertificateIdentifier`          | string  | `"rds-ca-rsa2048-g1"`                                   |
| `CertificateDetails.CAIdentifier`  | string  | `"rds-ca-rsa2048-g1"`                                   |
| `CertificateDetails.ValidTill`     | string  | `"2027-02-21T06:25:44+00:00"`                           |

### Networking

| Path                                       | Type    | Example Value                                                         |
| ------------------------------------------ | ------- | --------------------------------------------------------------------- |
| `Endpoint.Address`                         | string  | `"example-transparency-log.cmp6mwcmerdo.us-east-1.rds.amazonaws.com"` |
| `Endpoint.Port`                            | integer | `5432`                                                                |
| `VpcSecurityGroups.0.VpcSecurityGroupId`   | string  | `"sg-0bbbbbbbbbbbbbbbb0"`                                              |
| `VpcSecurityGroups.0.Status`               | string  | `"active"`                                                            |
| `VpcSecurityGroups.*.VpcSecurityGroupId`   | string  | (all SG IDs via wildcard)                                             |
| `DBSubnetGroup.VpcId`                      | string  | `"vpc-0fedcba9876543210"`                                             |
| `DBSubnetGroup.DBSubnetGroupName`          | string  | `"example-db-subnets"`                                                |
| `DBSubnetGroup.Subnets.0.SubnetIdentifier` | string  | `"subnet-0eeeeeeeeeeeeeeee"`                                          |
| `DBSubnetGroup.Subnets.*.SubnetIdentifier` | string  | (all subnet IDs via wildcard)                                         |

### Backup and storage

| Path                    | Type    | Example Value |
| ----------------------- | ------- | ------------- |
| `BackupRetentionPeriod` | integer | `7`           |
| `AllocatedStorage`      | integer | `20`          |
| `StorageType`           | string  | `"gp3"`       |
| `Iops`                  | integer | `3000`        |
| `MaxAllocatedStorage`   | integer | `100`         |
| `MultiAZ`               | boolean | `false`       |

### Tags

| Path              | Type   | Example Value    |
| ----------------- | ------ | ---------------- |
| `TagList.0.Key`   | string | `"Project"`      |
| `TagList.0.Value` | string | `"scanset"`      |
| `TagList.*.Key`   | string | (all tag keys)   |
| `TagList.*.Value` | string | (all tag values) |

**Note:** RDS uses `TagList` for tags, not `Tags` like EC2 resources. Record check paths must use `TagList.0.Key`, not `Tags.0.Key`.

---

## State Fields

### Scalar State Fields

| State Field                  | Type    | Allowed Operations              | Maps To Collected Field      |
| ---------------------------- | ------- | ------------------------------- | ---------------------------- |
| `found`                      | boolean | `=`, `!=`                       | `found`                      |
| `db_instance_identifier`     | string  | `=`, `!=`, `contains`           | `db_instance_identifier`     |
| `db_instance_status`         | string  | `=`, `!=`                       | `db_instance_status`         |
| `engine`                     | string  | `=`, `!=`                       | `engine`                     |
| `engine_version`             | string  | `=`, `!=`, `starts`             | `engine_version`             |
| `storage_encrypted`          | boolean | `=`, `!=`                       | `storage_encrypted`          |
| `publicly_accessible`        | boolean | `=`, `!=`                       | `publicly_accessible`        |
| `multi_az`                   | boolean | `=`, `!=`                       | `multi_az`                   |
| `deletion_protection`        | boolean | `=`, `!=`                       | `deletion_protection`        |
| `auto_minor_version_upgrade` | boolean | `=`, `!=`                       | `auto_minor_version_upgrade` |
| `backup_retention_period`    | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `backup_retention_period`    |
| `vpc_id`                     | string  | `=`, `!=`                       | `vpc_id`                     |
| `db_subnet_group_name`       | string  | `=`, `!=`                       | `db_subnet_group_name`       |
| `iam_auth_enabled`           | boolean | `=`, `!=`                       | `iam_auth_enabled`           |
| `kms_key_id`                 | string  | `=`, `!=`, `contains`, `starts` | `kms_key_id`                 |
| `tag_name`                   | string  | `=`, `!=`, `contains`           | `tag_name`                   |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                        |
| ---------------------------- | ---------------------------- |
| Collector ID                 | `aws_rds_instance_collector` |
| Collector Type               | `aws_rds_instance`           |
| Collection Mode              | Content                      |
| Required Capabilities        | `aws_cli`, `rds_read`        |
| Expected Collection Time     | ~2000ms                      |
| Memory Usage                 | ~10MB                        |
| Network Intensive            | Yes                          |
| CPU Intensive                | No                           |
| Requires Elevated Privileges | No                           |
| Batch Collection             | No                           |

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
  "Action": ["rds:DescribeDBInstances"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                       |
| ----------- | ----------------------------------------------------------- |
| method_type | `ApiCall`                                                   |
| description | `"Query RDS instance configuration via AWS CLI"`            |
| target      | `"rds:<db_instance_identifier>"`                            |
| command     | `"aws rds describe-db-instances"`                           |
| inputs      | `db_instance_identifier` (always), `region` (when provided) |

---

## ESP Examples

### Validate RDS is encrypted, not public, with backups

```esp
OBJECT transparency_db
    db_instance_identifier `example-transparency-log`
    region `us-east-1`
OBJECT_END

STATE rds_hardened
    found boolean = true
    db_instance_status string = `available`
    storage_encrypted boolean = true
    publicly_accessible boolean = false
    backup_retention_period int >= 7
    auto_minor_version_upgrade boolean = true
STATE_END

CTN aws_rds_instance
    TEST all all AND
    STATE_REF rds_hardened
    OBJECT_REF transparency_db
CTN_END
```

### Validate RDS is in correct VPC with correct security group

```esp
OBJECT transparency_db
    db_instance_identifier `example-transparency-log`
    region `us-east-1`
OBJECT_END

STATE rds_network_valid
    found boolean = true
    vpc_id string = `vpc-0fedcba9876543210`
    db_subnet_group_name string = `example-db-subnets`
    record
        field VpcSecurityGroups.0.VpcSecurityGroupId string = `sg-0bbbbbbbbbbbbbbbb0`
        field VpcSecurityGroups.0.Status string = `active`
        field Endpoint.Port int = 5432
    record_end
STATE_END

CTN aws_rds_instance
    TEST all all AND
    STATE_REF rds_network_valid
    OBJECT_REF transparency_db
CTN_END
```

### Validate encryption key and certificate

```esp
OBJECT transparency_db
    db_instance_identifier `example-transparency-log`
    region `us-east-1`
OBJECT_END

STATE rds_encryption
    found boolean = true
    storage_encrypted boolean = true
    record
        field KmsKeyId string starts `arn:aws:kms:`
        field CACertificateIdentifier string = `rds-ca-rsa2048-g1`
    record_end
STATE_END

CTN aws_rds_instance
    TEST all all AND
    STATE_REF rds_encryption
    OBJECT_REF transparency_db
CTN_END
```

### Validate subnets are in private subnet group

```esp
OBJECT transparency_db
    db_instance_identifier `example-transparency-log`
    region `us-east-1`
OBJECT_END

STATE rds_private_subnets
    found boolean = true
    record
        field DBSubnetGroup.Subnets.*.SubnetIdentifier string = `subnet-0eeeeeeeeeeeeeeee` at_least_one
        field DBSubnetGroup.Subnets.*.SubnetIdentifier string = `subnet-0cccccccccccccccc` at_least_one
    record_end
STATE_END

CTN aws_rds_instance
    TEST all all AND
    STATE_REF rds_private_subnets
    OBJECT_REF transparency_db
CTN_END
```

---

## Error Conditions

| Condition                                    | Error Type                   | Outcome       | Notes                                                 |
| -------------------------------------------- | ---------------------------- | ------------- | ----------------------------------------------------- |
| Instance not found (`DBInstanceNotFound`)    | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent    |
| `db_instance_identifier` missing from object | `InvalidObjectConfiguration` | Error         | Required field — collector returns immediately        |
| `aws` CLI binary not found                   | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                  |
| Invalid AWS credentials                      | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error       |
| IAM access denied                            | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess` |
| JSON parse failure                           | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                |
| Incompatible CTN type                        | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_rds_instance"`  |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"RDS instance not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type             | Relationship                                           |
| -------------------- | ------------------------------------------------------ |
| `aws_security_group` | VpcSecurityGroups reference SGs that control DB access |
| `aws_subnet`         | DB subnet group references private subnets             |
| `aws_vpc`            | DB resides in boundary VPC                             |
| `aws_iam_role`       | IAM auth roles (if IAMDatabaseAuthenticationEnabled)   |
