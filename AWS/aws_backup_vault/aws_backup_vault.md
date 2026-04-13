# aws_backup_vault

## Overview

Validates AWS Backup vault configuration via the AWS CLI. Makes a single API call using `describe-backup-vault` to retrieve encryption, lock status, retention bounds, and recovery point count. Vault lock (WORM) configuration is returned inline — no separate lock API call is needed.

**Platform:** AWS (requires `aws` CLI binary with Backup read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

---

## Object Fields

| Field        | Type   | Required | Description                                | Example                        |
| ------------ | ------ | -------- | ------------------------------------------ | ------------------------------ |
| `vault_name` | string | **Yes**  | Backup vault name (exact match)            | `example-org-backup-vault` |
| `region`     | string | No       | AWS region override (passed as `--region`) | `us-east-1`                    |

- `vault_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.

---

## Commands Executed

### Command 1: describe-backup-vault

**Collector call:** `client.execute("backup", "describe-backup-vault", &["--backup-vault-name", vault_name])`

**Resulting command:**

```
aws backup describe-backup-vault --backup-vault-name example-org-backup-vault --output json
```

**Sample response:**

```json
{
  "BackupVaultName": "example-org-backup-vault",
  "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:example-org-backup-vault",
  "VaultType": "BACKUP_VAULT",
  "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "CreationDate": "2026-03-24T17:11:14.822000+00:00",
  "NumberOfRecoveryPoints": 4,
  "Locked": true,
  "MinRetentionDays": 7,
  "MaxRetentionDays": 2555,
  "LockDate": "2026-03-27T17:11:15.160000+00:00"
}
```

**Response parsing:**

- `BackupVaultName` → `vault_name` scalar
- `BackupVaultArn` → `vault_arn` scalar
- `VaultType` → `vault_type` scalar
- `EncryptionKeyArn` → `encryption_key_arn` scalar
- `Locked` → `locked` scalar (boolean)
- `MinRetentionDays` → `min_retention_days` scalar (integer, only when locked)
- `MaxRetentionDays` → `max_retention_days` scalar (integer, only when locked)
- `NumberOfRecoveryPoints` → `number_of_recovery_points` scalar (integer)
- Full response stored as `resource` RecordData

**Note:** `get-backup-vault-lock-configuration` does not exist as an AWS CLI command. Lock configuration (`Locked`, `MinRetentionDays`, `MaxRetentionDays`, `LockDate`) is returned inline by `describe-backup-vault`.

---

### Error Detection

| Stderr contains             | Error variant                |
| --------------------------- | ---------------------------- |
| `ResourceNotFoundException` | `AwsError::ResourceNotFound` |
| `AccessDenied`              | `AwsError::AccessDenied`     |
| Anything else               | `AwsError::CommandFailed`    |

`ResourceNotFoundException` sets `found = false`.

---

## Collected Data Fields

### Scalar Fields

| Field                       | Type    | Always Present | Source                           |
| --------------------------- | ------- | -------------- | -------------------------------- |
| `found`                     | boolean | Yes            | Derived — `true` if vault exists |
| `vault_name`                | string  | When found     | `BackupVaultName`                |
| `vault_arn`                 | string  | When found     | `BackupVaultArn`                 |
| `vault_type`                | string  | When found     | `VaultType`                      |
| `encryption_key_arn`        | string  | When found     | `EncryptionKeyArn`               |
| `locked`                    | boolean | When found     | `Locked`                         |
| `min_retention_days`        | integer | When locked    | `MinRetentionDays`               |
| `max_retention_days`        | integer | When locked    | `MaxRetentionDays`               |
| `number_of_recovery_points` | integer | When found     | `NumberOfRecoveryPoints`         |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full vault object. Empty `{}` when not found |

---

## State Fields

| State Field                 | Type       | Allowed Operations              | Maps To Collected Field     |
| --------------------------- | ---------- | ------------------------------- | --------------------------- |
| `found`                     | boolean    | `=`, `!=`                       | `found`                     |
| `vault_name`                | string     | `=`, `!=`, `contains`, `starts` | `vault_name`                |
| `vault_arn`                 | string     | `=`, `!=`, `contains`, `starts` | `vault_arn`                 |
| `vault_type`                | string     | `=`, `!=`                       | `vault_type`                |
| `encryption_key_arn`        | string     | `=`, `!=`, `contains`, `starts` | `encryption_key_arn`        |
| `locked`                    | boolean    | `=`, `!=`                       | `locked`                    |
| `min_retention_days`        | int        | `=`, `!=`, `>=`, `>`            | `min_retention_days`        |
| `max_retention_days`        | int        | `=`, `!=`, `>=`, `>`            | `max_retention_days`        |
| `number_of_recovery_points` | int        | `=`, `!=`, `>=`, `>`            | `number_of_recovery_points` |
| `record`                    | RecordData | (record checks)                 | `resource`                  |

---

## Collection Strategy

| Property                     | Value                        |
| ---------------------------- | ---------------------------- |
| Collector ID                 | `aws_backup_vault_collector` |
| Collector Type               | `aws_backup_vault`           |
| Collection Mode              | Content                      |
| Required Capabilities        | `aws_cli`, `backup_read`     |
| Expected Collection Time     | ~1500ms                      |
| Memory Usage                 | ~2MB                         |
| Network Intensive            | Yes                          |
| CPU Intensive                | No                           |
| Requires Elevated Privileges | No                           |
| Batch Collection             | No                           |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["backup:DescribeBackupVault"],
  "Resource": "*"
}
```

---

## ESP Examples

### Vault WORM locked with KMS encryption and active recovery points (KSI-RPL-ABO)

```esp
OBJECT primary_vault
    vault_name `example-org-backup-vault`
    region `us-east-1`
OBJECT_END

STATE vault_compliant
    found boolean = true
    locked boolean = true
    min_retention_days int >= 7
    max_retention_days int >= 365
    number_of_recovery_points int >= 1
    encryption_key_arn string starts `arn:aws:kms:`
STATE_END

CTN aws_backup_vault
    TEST all all AND
    STATE_REF vault_compliant
    OBJECT_REF primary_vault
CTN_END
```

### Record checks for deep inspection

```esp
STATE vault_details
    found boolean = true
    record
        field Locked boolean = true
        field MinRetentionDays int = 7
        field MaxRetentionDays int = 2555
        field VaultType string = `BACKUP_VAULT`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                        | Error Type                   | Outcome       |
| -------------------------------- | ---------------------------- | ------------- |
| Vault not found                  | N/A (not an error)           | `found=false` |
| `vault_name` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied                | `CollectionFailed`           | Error         |
| Incompatible CTN type            | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type          | Relationship                                               |
| ----------------- | ---------------------------------------------------------- |
| `aws_backup_plan` | Backup plans target this vault as their backup destination |
| `aws_iam_role`    | Backup service role grants backup.amazonaws.com access     |
