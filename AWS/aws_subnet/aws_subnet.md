# aws_subnet

## Overview

Validates AWS VPC subnet configuration via a single `ec2 describe-subnets` call. Returns scalar fields for CIDR block, availability zone, state, public-IP-on-launch behavior, and free address count. The CTN selects subnets by direct ID, VPC scope, or tag filter — at least one of these MUST be provided.

**Platform:** AWS (requires `aws` CLI binary with `ec2:DescribeSubnets` permission)
**Collection Method:** Single AWS CLI call via `AwsClient.describe_subnets()`

**Note:** When multiple subnets match the filter, the collector uses the **first** result and logs a warning. Use `subnet_id` directly or combine `vpc_id` + `tags` for unambiguous lookup.

---

## Object Fields

All fields are optional, but **at least one** of `subnet_id`, `vpc_id`, or `tags` MUST be specified or collection fails with `InvalidObjectConfiguration`.

| Field       | Type   | Required          | Description                                            | Example                                  |
| ----------- | ------ | ----------------- | ------------------------------------------------------ | ---------------------------------------- |
| `subnet_id` | string | One of these reqd | Subnet ID for direct lookup                            | `subnet-0123456789abcdef0`               |
| `vpc_id`    | string | One of these reqd | VPC ID — returns subnets within that VPC               | `vpc-0123456789abcdef0`                  |
| `tags`      | string | One of these reqd | Tag filter `Key=Value` — finds subnets with that tag   | `Name=private-subnet`, `Tier=isolated`   |
| `region`    | string | No                | AWS region override (defaults to CLI-configured region) | `us-east-1`, `eu-west-1`                 |

---

## Commands Executed

### Command 1: ec2 describe-subnets

Queries the AWS EC2 API for subnet configuration. The CLI invocation depends on which object fields are set; the collector composes `--subnet-ids` and `--filters` accordingly.

**Collector call:** `client.describe_subnets(subnet_id, vpc_id, filters)`

**Resulting commands** (representative shapes):

```
# By subnet ID (direct lookup)
aws ec2 describe-subnets --subnet-ids subnet-0123456789abcdef0

# By VPC scope
aws ec2 describe-subnets --filters Name=vpc-id,Values=vpc-0123456789abcdef0

# By tag
aws ec2 describe-subnets --filters Name=tag:Name,Values=private-subnet

# By VPC + tag combined
aws ec2 describe-subnets --filters Name=vpc-id,Values=vpc-... Name=tag:Tier,Values=isolated

# With region override
aws ec2 describe-subnets --region us-east-1 --subnet-ids subnet-...
```

**Sample response:**

```json
{
  "Subnets": [
    {
      "SubnetId": "subnet-0123456789abcdef0",
      "VpcId": "vpc-0123456789abcdef0",
      "CidrBlock": "10.0.1.0/24",
      "AvailabilityZone": "us-east-1a",
      "State": "available",
      "MapPublicIpOnLaunch": false,
      "AvailableIpAddressCount": 251,
      "Tags": [
        { "Key": "Name", "Value": "private-subnet-a" },
        { "Key": "Tier", "Value": "isolated" }
      ]
    }
  ]
}
```

**Response parsing:**

- `Subnets[0].SubnetId` → `subnet_id` scalar
- `Subnets[0].VpcId` → `vpc_id` scalar
- `Subnets[0].CidrBlock` → `cidr_block` scalar
- `Subnets[0].AvailabilityZone` → `availability_zone` scalar
- `Subnets[0].State` → `state` scalar
- `Subnets[0].MapPublicIpOnLaunch` → `map_public_ip_on_launch` scalar
- `Subnets[0].AvailableIpAddressCount` → `available_ip_address_count` scalar
- `Subnets[0].Tags[?Key==Name].Value` → `tag_name` scalar
- Empty `Subnets[]` → `exists=false`, no other fields set

---

## Collected Data Fields

### Scalar Fields

| Field                        | Type    | Always Present | Source                                  |
| ---------------------------- | ------- | -------------- | --------------------------------------- |
| `exists`                     | boolean | Yes            | Derived — `true` if any subnet matched  |
| `subnet_id`                  | string  | When found     | `Subnets[0].SubnetId`                   |
| `vpc_id`                     | string  | When found     | `Subnets[0].VpcId`                      |
| `cidr_block`                 | string  | When found     | `Subnets[0].CidrBlock`                  |
| `availability_zone`          | string  | When found     | `Subnets[0].AvailabilityZone`           |
| `state`                      | string  | When found     | `Subnets[0].State`                      |
| `map_public_ip_on_launch`    | boolean | When found     | `Subnets[0].MapPublicIpOnLaunch`        |
| `available_ip_address_count` | int     | When found     | `Subnets[0].AvailableIpAddressCount`    |
| `tag_name`                   | string  | When `Name` tag set | `Subnets[0].Tags[?Key==Name].Value` |

This CTN does not expose a `resource` / RecordData field — all fields are flat scalars.

---

## State Fields

| State Field                  | Type    | Allowed Operations                              | Maps To Collected Field      |
| ---------------------------- | ------- | ----------------------------------------------- | ---------------------------- |
| `exists`                     | boolean | `=`, `!=`                                       | `exists`                     |
| `subnet_id`                  | string  | `=`, `!=`, `pattern`                            | `subnet_id`                  |
| `vpc_id`                     | string  | `=`, `!=`                                       | `vpc_id`                     |
| `cidr_block`                 | string  | `=`, `!=`, `contains`, `starts`, `pattern`      | `cidr_block`                 |
| `availability_zone`          | string  | `=`, `!=`, `contains`, `pattern`                | `availability_zone`          |
| `state`                      | string  | `=`, `!=`                                       | `state`                      |
| `map_public_ip_on_launch`    | boolean | `=`, `!=`                                       | `map_public_ip_on_launch`    |
| `available_ip_address_count` | int     | `=`, `!=`, `>`, `<`                             | `available_ip_address_count` |
| `tag_name`                   | string  | `=`, `!=`, `contains`, `pattern`                | `tag_name`                   |

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector ID                 | `aws_subnet_collector` |
| Collector Type               | `aws_subnet`         |
| Collection Mode              | `Custom("api")`      |
| Required Capabilities        | `aws_api`, `ec2_read` |
| Expected Collection Time     | ~500ms               |
| Memory Usage                 | ~5MB                 |
| Network Intensive            | Yes                  |
| CPU Intensive                | No                   |
| Requires Elevated Privileges | No                   |
| Batch Collection             | No                   |

### Required Permissions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:DescribeSubnets"],
  "Resource": "*"
}
```

---

## ESP Examples

**IMPORTANT:** OBJECT fields use `field_name \`value\`` (no type keyword).
STATE fields use `field_name type operator \`value\`` (type keyword required).
The CTN type goes on the CTN block line, NOT on the OBJECT declaration.

### Validate a private subnet doesn't auto-assign public IPs

```esp
OBJECT private_app_subnet
    subnet_id `subnet-0123456789abcdef0`
OBJECT_END

STATE subnet_is_private
    exists boolean = true
    state string = `available`
    map_public_ip_on_launch boolean = false
STATE_END

CTN aws_subnet
    TEST all all AND
    STATE_REF subnet_is_private
    OBJECT_REF private_app_subnet
CTN_END
```

### Validate VPC-scoped subnets follow CIDR convention

```esp
OBJECT prod_vpc_subnets
    vpc_id `vpc-0123456789abcdef0`
    region `us-east-1`
OBJECT_END

STATE subnet_in_10_dot_block
    exists boolean = true
    cidr_block string starts `10.`
    available_ip_address_count int > `0`
STATE_END

CTN aws_subnet
    TEST all all AND
    STATE_REF subnet_in_10_dot_block
    OBJECT_REF prod_vpc_subnets
CTN_END
```

### Validate tag-tracked isolated tier

```esp
OBJECT isolated_tier_subnet
    tags `Tier=isolated`
OBJECT_END

STATE isolated_compliant
    exists boolean = true
    map_public_ip_on_launch boolean = false
    tag_name string contains `isolated`
STATE_END

CTN aws_subnet
    TEST all all AND
    STATE_REF isolated_compliant
    OBJECT_REF isolated_tier_subnet
CTN_END
```

---

## Error Conditions

| Condition                                                             | Error Type                   | Outcome       |
| --------------------------------------------------------------------- | ---------------------------- | ------------- |
| Subnet not found (no match)                                           | N/A (not an error)           | `exists=false` |
| OBJECT specifies none of `subnet_id` / `vpc_id` / `tags`              | `InvalidObjectConfiguration` | Error         |
| AWS API failure (auth, throttle, network)                             | `CollectionFailed`           | Error         |
| Multiple subnets matched                                              | N/A — uses first, logs warning | Warning      |
| Incompatible CTN type (collector wired to wrong contract)             | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type            | Relationship                                                              |
| ------------------- | ------------------------------------------------------------------------- |
| `aws_vpc`           | Subnets belong to a VPC; validate VPC-level config first                  |
| `aws_route_table`   | Subnet routing — confirm subnet attaches to the expected route table      |
| `aws_network_acl`   | Subnet-level ACLs — complementary boundary check                          |
| `aws_security_group` | Instance-level filtering inside the subnet                               |
| `aws_flow_log`      | VPC Flow Logs scoped to a subnet for traffic visibility                   |
