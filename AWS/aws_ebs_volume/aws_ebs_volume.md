# aws_ebs_volume

## Overview

Validates EBS volume configuration via a single `ec2 describe-volumes --volume-ids <volume_id>` call. Returns scalar fields for state, type, encryption, IOPS, throughput, attachment, and tag values, plus the full volume object as RecordData for deep inspection.

**Platform:** AWS (requires `aws` CLI binary with `ec2:DescribeVolumes` permission)
**Collection Method:** Single AWS CLI call via `AwsClient.describe_volumes()`

**Note:** `volume_id` is **required** and must be exact. The CTN does not support tag-based or VPC-scoped lookup — use Resource Explorer or describe-instances upstream to enumerate volume IDs first.

---

## Object Fields

| Field       | Type   | Required | Description                                          | Example                       |
| ----------- | ------ | -------- | ---------------------------------------------------- | ----------------------------- |
| `volume_id` | string | **Yes**  | EBS volume ID — exact match                          | `vol-036890cac9d75b9a5`       |
| `region`    | string | No       | AWS region override (defaults to CLI-configured)     | `us-east-1`                   |

---

## Commands Executed

### Command 1: ec2 describe-volumes

Queries the EC2 API for one EBS volume by ID.

**Collector call:** `client.describe_volumes(volume_id, region)`

**Resulting command:**

```
aws ec2 describe-volumes --volume-ids vol-036890cac9d75b9a5
# with region override
aws ec2 describe-volumes --region us-east-1 --volume-ids vol-...
```

**Sample response:**

```json
{
  "Volumes": [
    {
      "VolumeId": "vol-036890cac9d75b9a5",
      "State": "in-use",
      "VolumeType": "gp3",
      "AvailabilityZone": "us-east-1a",
      "Encrypted": true,
      "KmsKeyId": "arn:aws:kms:us-east-1:486027077516:key/3c418345-78b1-4687-ac90-399246730cae",
      "Size": 50,
      "Iops": 3000,
      "Throughput": 125,
      "MultiAttachEnabled": false,
      "Attachments": [
        {
          "InstanceId": "i-02dc10f9292c0a933",
          "Device": "/dev/xvdf",
          "DeleteOnTermination": false,
          "State": "attached"
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "prooflayer-demo-data-volume" }]
    }
  ]
}
```

**Response parsing:**

- `Volumes[0].State` → `state`, `Volumes[0].VolumeType` → `volume_type`, etc. (1:1 scalars)
- `Volumes[0].Attachments[0].InstanceId` / `.Device` / `.DeleteOnTermination` → `attached_instance_id` / `attached_device` / `delete_on_termination` (first attachment only)
- `Volumes[0].KmsKeyId` → `kms_key_id` (only present when encrypted)
- `Volumes[0].Tags[?Key==X].Value` → dynamic field `tag_key:<TagKey>`
- Full `Volumes[0]` object → `resource` RecordData
- Empty `Volumes[]` → `found=false`, no other fields set

---

## Collected Data Fields

### Scalar Fields

| Field                     | Type    | Always Present | Source                                                 |
| ------------------------- | ------- | -------------- | ------------------------------------------------------ |
| `found`                   | boolean | Yes            | Derived — `true` if volume exists                      |
| `volume_id`               | string  | When found     | `Volumes[0].VolumeId`                                  |
| `state`                   | string  | When found     | `Volumes[0].State`                                     |
| `volume_type`             | string  | When found     | `Volumes[0].VolumeType`                                |
| `availability_zone`       | string  | When found     | `Volumes[0].AvailabilityZone`                          |
| `encrypted`               | boolean | When found     | `Volumes[0].Encrypted`                                 |
| `kms_key_id`              | string  | When encrypted | `Volumes[0].KmsKeyId`                                  |
| `size`                    | int     | When found     | `Volumes[0].Size`                                      |
| `iops`                    | int     | When found     | `Volumes[0].Iops`                                      |
| `throughput`              | int     | When found     | `Volumes[0].Throughput`                                |
| `multi_attach_enabled`    | boolean | When found     | `Volumes[0].MultiAttachEnabled`                        |
| `attached_instance_id`    | string  | When attached  | `Volumes[0].Attachments[0].InstanceId`                 |
| `attached_device`         | string  | When attached  | `Volumes[0].Attachments[0].Device`                     |
| `delete_on_termination`   | boolean | When attached  | `Volumes[0].Attachments[0].DeleteOnTermination`        |

### RecordData Field

| Field      | Type       | Always Present | Description                                       |
| ---------- | ---------- | -------------- | ------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `Volumes[0]` object. Empty `{}` when not found |

---

## State Fields

| State Field             | Type       | Allowed Operations              | Maps To Collected Field |
| ----------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`                 | boolean    | `=`, `!=`                       | `found`                 |
| `volume_id`             | string     | `=`, `!=`                       | `volume_id`             |
| `state`                 | string     | `=`, `!=`                       | `state`                 |
| `volume_type`           | string     | `=`, `!=`                       | `volume_type`           |
| `availability_zone`     | string     | `=`, `!=`                       | `availability_zone`     |
| `encrypted`             | boolean    | `=`, `!=`                       | `encrypted`             |
| `kms_key_id`            | string     | `=`, `!=`, `contains`, `starts` | `kms_key_id`            |
| `size`                  | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `size`                  |
| `iops`                  | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `iops`                  |
| `throughput`            | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `throughput`            |
| `multi_attach_enabled`  | boolean    | `=`, `!=`                       | `multi_attach_enabled`  |
| `attached_instance_id`  | string     | `=`, `!=`                       | `attached_instance_id`  |
| `attached_device`       | string     | `=`, `!=`                       | `attached_device`       |
| `delete_on_termination` | boolean    | `=`, `!=`                       | `delete_on_termination` |
| `tag_key`               | string     | `=`, `!=`, `contains`           | `tag_key:<TagKey>` (dynamic field naming) |
| `record`                | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_ebs_volume_collector`  |
| Collector Type               | `aws_ebs_volume`            |
| Collection Mode              | Content                     |
| Required Capabilities        | `aws_cli`, `ec2_read`       |
| Expected Collection Time     | ~1500ms                     |
| Memory Usage                 | ~2MB                        |
| Network Intensive            | Yes                         |
| CPU Intensive                | No                          |
| Requires Elevated Privileges | No                          |
| Batch Collection             | No                          |

### Required Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeVolumes"],
  "Resource": "*"
}
```

---

## ESP Examples

### Validate a data volume is encrypted with the correct KMS key

```esp
OBJECT prod_data_volume
    volume_id `vol-036890cac9d75b9a5`
OBJECT_END

STATE volume_encrypted_correctly
    found boolean = true
    state string = `in-use`
    encrypted boolean = true
    kms_key_id string contains `486027077516`
STATE_END

CTN aws_ebs_volume
    TEST all all AND
    STATE_REF volume_encrypted_correctly
    OBJECT_REF prod_data_volume
CTN_END
```

### Validate sizing and tier

```esp
OBJECT data_volume
    volume_id `vol-036890cac9d75b9a5`
OBJECT_END

STATE properly_sized
    found boolean = true
    volume_type string = `gp3`
    size int >= `50`
    iops int >= `3000`
STATE_END

CTN aws_ebs_volume
    TEST all all AND
    STATE_REF properly_sized
    OBJECT_REF data_volume
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome                          |
| ---------------------------------------- | ---------------------------- | -------------------------------- |
| Volume not found                         | N/A (not an error)           | `found=false`                    |
| `volume_id` missing in OBJECT            | `InvalidObjectConfiguration` | Error                            |
| AWS API failure (auth, throttle, network)| `CollectionFailed`           | Error                            |
| Incompatible CTN type                    | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type                         | Relationship                                                                  |
| -------------------------------- | ----------------------------------------------------------------------------- |
| `aws_ec2_describe_instances`     | Use upstream to discover attached volumes per instance                        |
| `aws_kms_key`                    | If volume is encrypted, validate the KMS key separately                       |
| `aws_backup_vault`               | Snapshot policy for the volume (different concern, complementary)             |
