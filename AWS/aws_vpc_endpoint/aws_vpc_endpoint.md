# aws_vpc_endpoint

## Overview

Validates AWS VPC endpoint configuration via the AWS CLI. Makes a single API call using `describe-vpc-endpoints` with either a direct endpoint ID lookup or filter-based lookup by service name and/or VPC ID. Supports both Interface and Gateway endpoint types.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** Interface and Gateway endpoints have different field shapes. Interface endpoints have `SubnetIds`, `Groups` (security groups), and `PrivateDnsEnabled=true`. Gateway endpoints (S3) have `RouteTableIds` and `PrivateDnsEnabled=false`.

**Note:** `PolicyDocument` is a JSON-encoded string in the API response. The collector parses it and stores it as a structured object under the `PolicyDocument` key in RecordData, replacing the raw string.

---

## Object Fields

| Field          | Type   | Required | Description                                | Example                       |
| -------------- | ------ | -------- | ------------------------------------------ | ----------------------------- |
| `endpoint_id`  | string | No\*     | VPC endpoint ID for direct lookup          | `vpce-0488e6400e49c4422`      |
| `service_name` | string | No\*     | AWS service name filter                    | `com.amazonaws.us-east-1.ssm` |
| `vpc_id`       | string | No\*     | VPC ID to scope the lookup                 | `vpc-0ea38d2598962fda8`       |
| `region`       | string | No       | AWS region override (passed as `--region`) | `us-east-1`                   |

\* At least one of `endpoint_id`, `service_name`, or `vpc_id` must be specified.

- `endpoint_id` uses `--vpc-endpoint-ids` for direct lookup
- `service_name` uses `--filters Name=service-name,Values=<value>`
- `vpc_id` uses `--filters Name=vpc-id,Values=<value>`
- All three can be combined in the same command
- If multiple endpoints match, the first result is used

---

## Commands Executed

### Command 1: describe-vpc-endpoints

**Resulting commands (examples):**

```
# By endpoint ID
aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-0488e6400e49c4422 --output json

# By service name + VPC
aws ec2 describe-vpc-endpoints --filters Name=service-name,Values=com.amazonaws.us-east-1.ssm --filters Name=vpc-id,Values=vpc-0ea38d2598962fda8 --output json
```

**Sample response (Interface endpoint):**

```json
{
  "VpcEndpoints": [
    {
      "VpcEndpointId": "vpce-0488e6400e49c4422",
      "VpcEndpointType": "Interface",
      "VpcId": "vpc-0ea38d2598962fda8",
      "ServiceName": "com.amazonaws.us-east-1.ssm",
      "State": "available",
      "PolicyDocument": "{\"Statement\":[{\"Action\":\"*\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Resource\":\"*\"}]}",
      "SubnetIds": ["subnet-06faa62535ba6541e", "subnet-0765f76c6a2dda34e"],
      "Groups": [
        {
          "GroupId": "sg-099f80ed84d7834a9",
          "GroupName": "prooflayer-demo-vpce-sg"
        }
      ],
      "PrivateDnsEnabled": true,
      "RouteTableIds": [],
      "NetworkInterfaceIds": ["eni-08126c7b04a378cff", "eni-050f5ec0b815d4c7a"]
    }
  ]
}
```

**Sample response (Gateway endpoint — S3):**

```json
{
  "VpcEndpoints": [
    {
      "VpcEndpointId": "vpce-016d5717ba0310558",
      "VpcEndpointType": "Gateway",
      "VpcId": "vpc-0ea38d2598962fda8",
      "ServiceName": "com.amazonaws.us-east-1.s3",
      "State": "available",
      "PolicyDocument": "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
      "RouteTableIds": ["rtb-05a3f415af05a2575"],
      "SubnetIds": [],
      "Groups": [],
      "PrivateDnsEnabled": false
    }
  ]
}
```

**Response parsing:**

| Collected Field       | Source                        | Notes                                      |
| --------------------- | ----------------------------- | ------------------------------------------ |
| `vpc_endpoint_id`     | `VpcEndpointId`               |                                            |
| `vpc_endpoint_type`   | `VpcEndpointType`             | `Interface` or `Gateway`                   |
| `service_name`        | `ServiceName`                 |                                            |
| `state`               | `State`                       | `available`, `pending`, `deleting`         |
| `vpc_id`              | `VpcId`                       |                                            |
| `private_dns_enabled` | `PrivateDnsEnabled`           | Always false for Gateway endpoints         |
| `subnet_count`        | Derived: `len(SubnetIds)`     | Always 0 for Gateway endpoints             |
| `route_table_count`   | Derived: `len(RouteTableIds)` | Always 0 for Interface endpoints           |
| `security_group_id`   | `Groups[0].GroupId`           | First SG only; empty for Gateway endpoints |

`PolicyDocument` is a JSON-encoded string. The collector parses it and replaces the raw string in RecordData with the structured JSON object.

---

## Collected Data Fields

### Scalar Fields

| Field                 | Type    | Always Present | Source                             |
| --------------------- | ------- | -------------- | ---------------------------------- |
| `found`               | boolean | Yes            | Derived — `true` if endpoint found |
| `vpc_endpoint_id`     | string  | When found     | `VpcEndpointId`                    |
| `vpc_endpoint_type`   | string  | When found     | `VpcEndpointType`                  |
| `service_name`        | string  | When found     | `ServiceName`                      |
| `state`               | string  | When found     | `State`                            |
| `vpc_id`              | string  | When found     | `VpcId`                            |
| `private_dns_enabled` | boolean | When found     | `PrivateDnsEnabled`                |
| `subnet_count`        | integer | When found     | Derived — `len(SubnetIds)`         |
| `route_table_count`   | integer | When found     | Derived — `len(RouteTableIds)`     |
| `security_group_id`   | string  | When Interface | `Groups[0].GroupId`                |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                |
| ---------- | ---------- | -------------- | -------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full endpoint object with PolicyDocument parsed. Empty `{}` when not found |

---

## RecordData Structure

| Path                                   | Type    | Example Value                            |
| -------------------------------------- | ------- | ---------------------------------------- |
| `VpcEndpointId`                        | string  | `"vpce-0488e6400e49c4422"`               |
| `VpcEndpointType`                      | string  | `"Interface"`                            |
| `ServiceName`                          | string  | `"com.amazonaws.us-east-1.ssm"`          |
| `State`                                | string  | `"available"`                            |
| `PrivateDnsEnabled`                    | boolean | `true`                                   |
| `SubnetIds.0`                          | string  | `"subnet-06faa62535ba6541e"`             |
| `SubnetIds.1`                          | string  | `"subnet-0765f76c6a2dda34e"`             |
| `Groups.0.GroupId`                     | string  | `"sg-099f80ed84d7834a9"`                 |
| `Groups.0.GroupName`                   | string  | `"prooflayer-demo-vpce-sg"`              |
| `RouteTableIds.0`                      | string  | `"rtb-05a3f415af05a2575"` (Gateway only) |
| `PolicyDocument.Statement.0.Effect`    | string  | `"Allow"`                                |
| `PolicyDocument.Statement.0.Principal` | string  | `"*"`                                    |
| `PolicyDocument.Statement.0.Action`    | string  | `"*"`                                    |

---

## State Fields

| State Field           | Type       | Allowed Operations              | Maps To Collected Field |
| --------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`               | boolean    | `=`, `!=`                       | `found`                 |
| `vpc_endpoint_id`     | string     | `=`, `!=`                       | `vpc_endpoint_id`       |
| `vpc_endpoint_type`   | string     | `=`, `!=`                       | `vpc_endpoint_type`     |
| `service_name`        | string     | `=`, `!=`, `contains`, `starts` | `service_name`          |
| `state`               | string     | `=`, `!=`                       | `state`                 |
| `vpc_id`              | string     | `=`, `!=`                       | `vpc_id`                |
| `private_dns_enabled` | boolean    | `=`, `!=`                       | `private_dns_enabled`   |
| `subnet_count`        | int        | `=`, `!=`, `>=`, `>`            | `subnet_count`          |
| `route_table_count`   | int        | `=`, `!=`, `>=`, `>`            | `route_table_count`     |
| `security_group_id`   | string     | `=`, `!=`                       | `security_group_id`     |
| `record`              | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                        |
| ---------------------------- | ---------------------------- |
| Collector ID                 | `aws_vpc_endpoint_collector` |
| Collector Type               | `aws_vpc_endpoint`           |
| Collection Mode              | Content                      |
| Required Capabilities        | `aws_cli`, `ec2_read`        |
| Expected Collection Time     | ~2000ms                      |
| Memory Usage                 | ~5MB                         |
| Network Intensive            | Yes                          |
| CPU Intensive                | No                           |
| Requires Elevated Privileges | No                           |
| Batch Collection             | No                           |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeVpcEndpoints"],
  "Resource": "*"
}
```

---

## ESP Examples

### SSM Interface endpoint with private DNS enabled (KSI-CNA-MAT)

```esp
OBJECT ssm_endpoint
    service_name `com.amazonaws.us-east-1.ssm`
    vpc_id `vpc-0ea38d2598962fda8`
    region `us-east-1`
OBJECT_END

STATE ssm_endpoint_compliant
    found boolean = true
    vpc_endpoint_type string = `Interface`
    state string = `available`
    private_dns_enabled boolean = true
    subnet_count int >= 1
STATE_END

CTN aws_vpc_endpoint
    TEST all all AND
    STATE_REF ssm_endpoint_compliant
    OBJECT_REF ssm_endpoint
CTN_END
```

### S3 Gateway endpoint with route table associated

```esp
OBJECT s3_endpoint
    service_name `com.amazonaws.us-east-1.s3`
    vpc_id `vpc-0ea38d2598962fda8`
    region `us-east-1`
OBJECT_END

STATE s3_endpoint_compliant
    found boolean = true
    vpc_endpoint_type string = `Gateway`
    state string = `available`
    route_table_count int >= 1
STATE_END

CTN aws_vpc_endpoint
    TEST all all AND
    STATE_REF s3_endpoint_compliant
    OBJECT_REF s3_endpoint
CTN_END
```

---

## Error Conditions

| Condition                  | Error Type                   | Outcome       |
| -------------------------- | ---------------------------- | ------------- |
| Endpoint not found         | N/A (not an error)           | `found=false` |
| No lookup fields specified | `InvalidObjectConfiguration` | Error         |
| IAM access denied          | `CollectionFailed`           | Error         |
| Incompatible CTN type      | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type             | Relationship                                              |
| -------------------- | --------------------------------------------------------- |
| `aws_vpc`            | Endpoints belong to a VPC                                 |
| `aws_security_group` | Interface endpoints use security groups to control access |
| `aws_route_table`    | Gateway endpoints are associated with route tables        |
| `aws_subnet`         | Interface endpoints are deployed into subnets             |
