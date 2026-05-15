# aws_ec2_describe_images

## Overview

AMI metadata enrichment primitive. Takes a comma-separated list of AMI IDs and returns per-image fields (`name`, `description`, `architecture`, `platform_details`, `image_owner_id`, `creation_date`) for every match. Typically used by a discovery orchestrator to derive `os_family` / `os_version` (Rocky 9, RHEL 9.5, Ubuntu 22.04, …) from the AMI's `Name` and `PlatformDetails` — the description Resource Explorer's bulk Search doesn't carry.

**Platform:** AWS (requires `aws` CLI binary with `ec2:DescribeImages` permission)
**Collection Method:** Single AWS CLI call via `AwsClient.describe_images()`

**Note:** `image_ids` is **required**. `DescribeImages` without filters would return every public AMI on AWS — millions of rows. The collector refuses to run without an explicit ID list.

---

## Object Fields

| Field       | Type   | Required  | Description                                    | Example                          |
| ----------- | ------ | --------- | ---------------------------------------------- | -------------------------------- |
| `image_ids` | string | **Yes**   | Comma-separated AMI IDs                        | `ami-0abc1234,ami-0def5678`      |
| `region`    | string | No        | Override the resolved AWS region               | `us-east-1`                      |

---

## Commands Executed

### Command 1: ec2 describe-images

Queries the EC2 API for one or more AMIs by ID.

**Collector call:** `client.describe_images(image_ids, region)`

**Resulting command:**

```
aws ec2 describe-images --image-ids ami-0abc1234 ami-0def5678
# with optional region override
aws ec2 describe-images --region us-east-1 --image-ids ami-0abc1234
```

**Sample response:**

```json
{
  "Images": [
    {
      "ImageId": "ami-0abc1234",
      "Name": "Rocky-9-EC2-Base-9.7-20251123.2.x86_64",
      "Description": "Rocky Linux 9.7 Base",
      "Architecture": "x86_64",
      "PlatformDetails": "Linux/UNIX",
      "ImageOwnerAlias": "self",
      "OwnerId": "486027077516",
      "CreationDate": "2025-11-23T14:00:00.000Z"
    }
  ]
}
```

**Response parsing:**

- `Images[*].ImageId` → `rows[i].image_id`
- `Images[*].Name` → `rows[i].name`
- `Images[*].Description` → `rows[i].description`
- `Images[*].Architecture` → `rows[i].architecture`
- `Images[*].PlatformDetails` → `rows[i].platform_details`
- `Images[*].OwnerId` → `rows[i].image_owner_id`
- `Images[*].CreationDate` → `rows[i].creation_date`
- `Images.length` → `row_count`
- Empty `Images[]` → `found=false`, `row_count=0`, `rows=[]`

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                                   |
| ----------- | ------- | -------------- | ---------------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if API call succeeded   |
| `row_count` | int     | Yes            | `Images.length`                          |

### RecordData Field

| Field  | Type       | Always Present | Description                                        |
| ------ | ---------- | -------------- | -------------------------------------------------- |
| `rows` | RecordData | Yes            | Array of per-AMI objects. Empty `[]` when no match |

---

## RecordData Structure

| Path                     | Type   | Example Value                              |
| ------------------------ | ------ | ------------------------------------------ |
| `rows.*.image_id`        | string | `"ami-0abc1234"`                           |
| `rows.*.name`            | string | `"Rocky-9-EC2-Base-9.7-20251123.2.x86_64"` |
| `rows.*.description`     | string | `"Rocky Linux 9.7 Base"`                   |
| `rows.*.architecture`    | string | `"x86_64"`                                 |
| `rows.*.platform_details`| string | `"Linux/UNIX"`                             |
| `rows.*.image_owner_id`  | string | `"486027077516"`                           |
| `rows.*.creation_date`   | string | `"2025-11-23T14:00:00.000Z"`               |

---

## State Fields

| State Field | Type       | Allowed Operations         | Maps To Collected Field |
| ----------- | ---------- | -------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                  | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`        |
| `rows`      | RecordData | (record checks)            | `rows`                  |

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `aws_ec2_describe_images_collector`  |
| Collector Type               | `aws_ec2_describe_images`            |
| Collection Mode              | Metadata                             |
| Required Capabilities        | `aws_credentials_env`, `ec2_describe_reader` |
| Expected Collection Time     | ~600ms                               |
| Memory Usage                 | ~8MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |

### Required Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeImages"],
  "Resource": "*"
}
```

---

## ESP Examples

### Validate a deployed AMI matches expected baseline

```esp
OBJECT prod_baseline_ami
    image_ids `ami-0abc1234`
OBJECT_END

STATE ami_is_rocky9
    found boolean = true
    row_count int = `1`
    record
        field rows.0.platform_details string = `Linux/UNIX`
        field rows.0.architecture string = `x86_64`
        field rows.0.name string starts `Rocky-9-`
    record_end
STATE_END

CTN aws_ec2_describe_images
    TEST all all AND
    STATE_REF ami_is_rocky9
    OBJECT_REF prod_baseline_ami
CTN_END
```

### Bulk verify all referenced AMIs come from approved owner

```esp
OBJECT all_in_use_amis
    image_ids `ami-0abc1234,ami-0def5678,ami-0ghi9012`
OBJECT_END

STATE owner_is_self
    found boolean = true
    row_count int = `3`
    record
        field rows.*.image_owner_id string = `486027077516`
    record_end
STATE_END

CTN aws_ec2_describe_images
    TEST all all AND
    STATE_REF owner_is_self
    OBJECT_REF all_in_use_amis
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome                          |
| ---------------------------------------- | ---------------------------- | -------------------------------- |
| `image_ids` missing or empty             | `InvalidObjectConfiguration` | Error                            |
| AMI not found / deregistered             | N/A (not an error)           | `found=true`, `row_count=0`      |
| AWS API failure (auth, throttle, network)| `CollectionFailed`           | Error                            |
| Incompatible CTN type                    | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type                         | Relationship                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| `aws_ec2_describe_instances`     | EC2 enrichment — gives `image_id` per instance which becomes input to this CTN              |
| `aws_resource_explorer_query`    | Bulk inventory upstream — Search returns ARNs/types, this enriches the EC2 ones with AMI info |
| `aws_ebs_volume`                 | Sibling EC2 storage check                                                                   |
