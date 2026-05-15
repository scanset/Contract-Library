# aws_ec2_describe_instances

## Overview

EC2 enrichment primitive. Takes a list of instance IDs (or empty for "all in active region") and returns per-instance metadata that Resource Explorer's bulk Search doesn't carry — `Platform`, `PlatformDetails`, `ImageId`, `Architecture`, `InstanceType`, `VpcId`, `SubnetId`. Typically used by a discovery orchestrator to fold detailed EC2 facts into existing inventory rows keyed by instance_id.

**Platform:** AWS (requires `aws` CLI binary with `ec2:DescribeInstances` permission)
**Collection Method:** Single AWS CLI call via `AwsClient.describe_instances()`

**Note:** Unlike `aws_ec2_describe_images`, `instance_ids` is **optional** here — empty / unset enumerates all instances in the active region. Cross-region enrichment requires multiple invocations because EC2 is regional.

---

## Object Fields

| Field          | Type   | Required | Description                                                              | Example                       |
| -------------- | ------ | -------- | ------------------------------------------------------------------------ | ----------------------------- |
| `instance_ids` | string | No       | Comma-separated EC2 instance IDs. Empty / unset = all in active region   | `i-0abc1234,i-0def5678` or `` |
| `region`       | string | No       | Override the resolved AWS region (EC2 is regional)                       | `us-east-1`, `eu-west-2`      |

---

## Commands Executed

### Command 1: ec2 describe-instances

Queries the EC2 API for one or more running/stopped instances.

**Collector call:** `client.describe_instances(instance_ids, region)`

**Resulting commands:**

```
# All instances in the active region
aws ec2 describe-instances

# By specific instance IDs
aws ec2 describe-instances --instance-ids i-0abc1234 i-0def5678

# With region override
aws ec2 describe-instances --region eu-west-2 --instance-ids i-0abc1234
```

**Sample response:**

```json
{
  "Reservations": [
    {
      "Instances": [
        {
          "InstanceId": "i-0abc1234",
          "ImageId": "ami-0abc1234",
          "InstanceType": "t3.micro",
          "Platform": null,
          "PlatformDetails": "Linux/UNIX",
          "Architecture": "x86_64",
          "State": { "Name": "running" },
          "Placement": { "AvailabilityZone": "us-east-1a" },
          "VpcId": "vpc-0123456789abcdef0",
          "SubnetId": "subnet-0123456789abcdef0"
        }
      ]
    }
  ]
}
```

**Response parsing:**

- `Reservations[*].Instances[*]` flattened across reservations into the `rows` array.
- `instance_id`, `image_id`, `platform`, `platform_details`, `architecture`, `instance_type`, `state`, `availability_zone`, `vpc_id`, `subnet_id` extracted per row.
- Empty result → `found=true`, `row_count=0`, `rows=[]`.

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                                  |
| ----------- | ------- | -------------- | --------------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if API call succeeded  |
| `row_count` | int     | Yes            | flattened instance count                |

### RecordData Field

| Field  | Type       | Always Present | Description                                |
| ------ | ---------- | -------------- | ------------------------------------------ |
| `rows` | RecordData | Yes            | Array of per-instance rows. Empty when none |

---

## RecordData Structure

| Path                          | Type   | Example Value                  |
| ----------------------------- | ------ | ------------------------------ |
| `rows.*.instance_id`          | string | `"i-0abc1234"`                 |
| `rows.*.image_id`             | string | `"ami-0abc1234"`               |
| `rows.*.platform`             | string | `null` for Linux, `"windows"` for Win |
| `rows.*.platform_details`     | string | `"Linux/UNIX"`                 |
| `rows.*.architecture`         | string | `"x86_64"`                     |
| `rows.*.instance_type`        | string | `"t3.micro"`                   |
| `rows.*.state`                | string | `"running"`                    |
| `rows.*.availability_zone`    | string | `"us-east-1a"`                 |
| `rows.*.vpc_id`               | string | `"vpc-0123456789abcdef0"`      |
| `rows.*.subnet_id`            | string | `"subnet-0123456789abcdef0"`   |

---

## State Fields

| State Field | Type       | Allowed Operations              | Maps To Collected Field |
| ----------- | ---------- | ------------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                       | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`             |
| `rows`      | RecordData | (record checks)                 | `rows`                  |

---

## Collection Strategy

| Property                     | Value                                          |
| ---------------------------- | ---------------------------------------------- |
| Collector ID                 | `aws_ec2_describe_instances_collector`         |
| Collector Type               | `aws_ec2_describe_instances`                   |
| Collection Mode              | Metadata                                       |
| Required Capabilities        | `aws_credentials_env`, `ec2_describe_reader`   |
| Expected Collection Time     | ~800ms                                         |
| Memory Usage                 | ~8MB                                           |
| Network Intensive            | Yes                                            |
| CPU Intensive                | No                                             |
| Requires Elevated Privileges | No                                             |
| Batch Collection             | No                                             |

### Required Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeInstances"],
  "Resource": "*"
}
```

---

## ESP Examples

### Verify all running instances are in approved subnets

```esp
OBJECT all_running_in_region
    region `us-east-1`
OBJECT_END

STATE all_in_approved_subnets
    found boolean = true
    row_count int > `0`
    record
        field rows.*.subnet_id string starts `subnet-0123`
        field rows.*.state string = `running`
    record_end
STATE_END

CTN aws_ec2_describe_instances
    TEST all all AND
    STATE_REF all_in_approved_subnets
    OBJECT_REF all_running_in_region
CTN_END
```

### Validate a specific instance set is x86_64

```esp
OBJECT prod_workload_instances
    instance_ids `i-0abc1234,i-0def5678`
OBJECT_END

STATE all_x86_64
    found boolean = true
    row_count int = `2`
    record
        field rows.*.architecture string = `x86_64`
    record_end
STATE_END

CTN aws_ec2_describe_instances
    TEST all all AND
    STATE_REF all_x86_64
    OBJECT_REF prod_workload_instances
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome                          |
| ---------------------------------------- | ---------------------------- | -------------------------------- |
| Instance IDs reference non-existent ones | N/A (not an error)           | Returns only the matched ones    |
| Empty result                             | N/A (not an error)           | `found=true`, `row_count=0`      |
| AWS API failure (auth, throttle, network)| `CollectionFailed`           | Error                            |
| Incompatible CTN type                    | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type                         | Relationship                                                                                  |
| -------------------------------- | --------------------------------------------------------------------------------------------- |
| `aws_ec2_describe_images`        | Use `rows.*.image_id` from this CTN as `image_ids` input to enrich AMI metadata               |
| `aws_resource_explorer_query`    | Bulk inventory upstream — Search returns ARNs/types, this enriches the EC2 ones with full details |
| `aws_ec2_instance`               | Per-instance compliance check — different shape (single instance vs bulk)                     |
| `aws_subnet`                     | Validate subnet for instances (use `rows.*.subnet_id`)                                        |
