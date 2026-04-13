# aws_security_group

## Overview

Validates AWS EC2 security group configurations via the AWS CLI. Returns scalar summary fields including derived open-access booleans and the full API response as RecordData for deep rule inspection of ingress/egress permissions using record checks.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EC2 API returns **PascalCase** field names (e.g., `IpPermissions`, `UserIdGroupPairs`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field        | Type   | Required | Description                                    | Example                 |
| ------------ | ------ | -------- | ---------------------------------------------- | ----------------------- |
| `group_id`   | string | No\*     | Security group ID for direct lookup            | `sg-0bbbbbbbbbbbbbbbb0`  |
| `group_name` | string | No\*     | Security group name for filter-based lookup    | `example-rds`           |
| `vpc_id`     | string | No       | VPC ID to scope the lookup (additional filter) | `vpc-0fedcba9876543210` |
| `region`     | string | No       | AWS region override (passed as `--region`)     | `us-east-1`             |

\* At least one of `group_id` or `group_name` must be specified. If neither is provided, the collector returns `InvalidObjectConfiguration`.

- `group_id` uses `--group-ids` for direct lookup. When `group_id` is provided, `group_name` is **not** added as a filter (even if both are specified).
- `group_name` is added as `--filters Name=group-name,Values=<value>` only when `group_id` is absent.
- `vpc_id` is always added as `--filters Name=vpc-id,Values=<value>` when present, regardless of other fields.
- If multiple security groups match, a warning is logged and the **first result** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-security-groups

Retrieves security group configurations matching the specified lookup.

**Collector call:** `client.execute("ec2", "describe-security-groups", &args)` where `args` is built dynamically from object fields.

**Argument assembly:**

The collector builds an argument list with this precedence logic:

1. If `group_id` is present: `--group-ids <group_id>`
2. If `vpc_id` is present: `--filters Name=vpc-id,Values=<vpc_id>`
3. If `group_name` is present **AND** `group_id` is absent: `--filters Name=group-name,Values=<group_name>`

This means when `group_id` is provided, the lookup is a direct ID lookup and `group_name` is ignored for filtering purposes. The `vpc_id` filter is always added when present.

Note: This collector uses `--filters` (plural), matching the `describe-security-groups` API.

**Resulting commands (examples):**

```
# By group ID (direct lookup)
aws ec2 describe-security-groups --group-ids sg-0bbbbbbbbbbbbbbbb0 --output json

# By group name
aws ec2 describe-security-groups --filters Name=group-name,Values=example-rds --output json

# By group name + VPC scope
aws ec2 describe-security-groups --filters Name=vpc-id,Values=vpc-0fedcba9876543210 --filters Name=group-name,Values=example-rds --output json

# By group ID + VPC (vpc_id still added as filter)
aws ec2 describe-security-groups --group-ids sg-0bbbbbbbbbbbbbbbb0 --filters Name=vpc-id,Values=vpc-0fedcba9876543210 --output json

# With region
aws ec2 describe-security-groups --region us-east-1 --output json --filters Name=group-name,Values=example-rds
```

**Response parsing:**

1. Extract `response["SecurityGroups"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. If non-empty, use `security_groups[0]` (the first element via direct indexing)
4. If multiple results exist, log a warning and use the first

**Scalar field extraction:**

Direct fields:

| Collected Field | JSON Path     | Extraction  |
| --------------- | ------------- | ----------- |
| `group_id`      | `GroupId`     | `.as_str()` |
| `group_name`    | `GroupName`   | `.as_str()` |
| `vpc_id`        | `VpcId`       | `.as_str()` |
| `description`   | `Description` | `.as_str()` |

Derived fields:

| Collected Field             | Derivation Logic                                                                                                        |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `ingress_rule_count`        | Length of `IpPermissions` array                                                                                         |
| `egress_rule_count`         | Length of `IpPermissionsEgress` array                                                                                   |
| `has_ingress_from_anywhere` | `true` if any `IpPermissions[]` entry has `IpRanges[].CidrIp == "0.0.0.0/0"` OR `Ipv6Ranges[].CidrIpv6 == "::/0"`       |
| `has_egress_to_anywhere`    | `true` if any `IpPermissionsEgress[]` entry has `IpRanges[].CidrIp == "0.0.0.0/0"` OR `Ipv6Ranges[].CidrIpv6 == "::/0"` |

The "anywhere" detection iterates through each permission entry, then checks both `IpRanges` (IPv4) and `Ipv6Ranges` (IPv6) arrays within each entry. A match on either `0.0.0.0/0` or `::/0` in any rule sets the flag to `true`.

**Sample response (abbreviated):**

```json
{
  "SecurityGroups": [
    {
      "GroupId": "sg-0bbbbbbbbbbbbbbbb0",
      "GroupName": "example-rds",
      "VpcId": "vpc-0fedcba9876543210",
      "Description": "Allow PostgreSQL access from EKS nodes",
      "OwnerId": "123456789012",
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 5432,
          "ToPort": 5432,
          "UserIdGroupPairs": [
            {
              "GroupId": "sg-0cccccccccccccccc0",
              "UserId": "123456789012",
              "Description": "PostgreSQL from EKS nodes"
            }
          ],
          "IpRanges": [],
          "Ipv6Ranges": []
        }
      ],
      "IpPermissionsEgress": [
        {
          "IpProtocol": "-1",
          "IpRanges": [{ "CidrIp": "0.0.0.0/0" }],
          "Ipv6Ranges": []
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "example-rds" }]
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

This collector does **not** have special not-found error handling — all API errors are mapped to `CollectionError::CollectionFailed`. An empty `SecurityGroups` array is the normal not-found case.

---

## Collected Data Fields

### Scalar Fields

| Field                       | Type    | Always Present | Source                                                  |
| --------------------------- | ------- | -------------- | ------------------------------------------------------- |
| `found`                     | boolean | Yes            | Derived — `true` if at least one security group matched |
| `group_id`                  | string  | When found     | `GroupId` (string)                                      |
| `group_name`                | string  | When found     | `GroupName` (string)                                    |
| `vpc_id`                    | string  | When found     | `VpcId` (string)                                        |
| `description`               | string  | When found     | `Description` (string)                                  |
| `ingress_rule_count`        | int     | When found     | Derived — length of `IpPermissions` array               |
| `egress_rule_count`         | int     | When found     | Derived — length of `IpPermissionsEgress` array         |
| `has_ingress_from_anywhere` | boolean | When found     | Derived — any ingress rule allows `0.0.0.0/0` or `::/0` |
| `has_egress_to_anywhere`    | boolean | When found     | Derived — any egress rule allows `0.0.0.0/0` or `::/0`  |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                           |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full security group object from `describe-security-groups`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete security group object as returned by the EC2 API:

```rust
let record_data = RecordData::from_json_value(sg.clone());
```

### Identity

| Path          | Type   | Example Value                              |
| ------------- | ------ | ------------------------------------------ |
| `GroupId`     | string | `"sg-0bbbbbbbbbbbbbbbb0"`                   |
| `GroupName`   | string | `"example-rds"`                            |
| `VpcId`       | string | `"vpc-0fedcba9876543210"`                  |
| `Description` | string | `"Allow PostgreSQL access from EKS nodes"` |
| `OwnerId`     | string | `"123456789012"`                           |

### Ingress rules (`IpPermissions.*`)

| Path                                             | Type    | Example Value                 |
| ------------------------------------------------ | ------- | ----------------------------- |
| `IpPermissions.0.IpProtocol`                     | string  | `"tcp"`                       |
| `IpPermissions.0.FromPort`                       | integer | `5432`                        |
| `IpPermissions.0.ToPort`                         | integer | `5432`                        |
| `IpPermissions.0.UserIdGroupPairs.0.GroupId`     | string  | `"sg-0cccccccccccccccc0"`      |
| `IpPermissions.0.UserIdGroupPairs.0.Description` | string  | `"PostgreSQL from EKS nodes"` |
| `IpPermissions.0.UserIdGroupPairs.0.UserId`      | string  | `"123456789012"`              |
| `IpPermissions.0.IpRanges.0.CidrIp`              | string  | `"10.0.0.0/16"`               |
| `IpPermissions.0.Ipv6Ranges.0.CidrIpv6`          | string  | `"::/0"`                      |
| `IpPermissions.*.FromPort`                       | integer | (all FromPort values)         |
| `IpPermissions.*.UserIdGroupPairs.*.GroupId`     | string  | (all source SG IDs)           |
| `IpPermissions.*.IpRanges.*.CidrIp`              | string  | (all ingress CIDRs)           |

### Egress rules (`IpPermissionsEgress.*`)

| Path                                      | Type   | Example Value        |
| ----------------------------------------- | ------ | -------------------- |
| `IpPermissionsEgress.0.IpProtocol`        | string | `"-1"` (all traffic) |
| `IpPermissionsEgress.0.IpRanges.0.CidrIp` | string | `"0.0.0.0/0"`        |
| `IpPermissionsEgress.*.IpRanges.*.CidrIp` | string | (all egress CIDRs)   |

### Tags

| Path           | Type   | Example Value    |
| -------------- | ------ | ---------------- |
| `Tags.0.Key`   | string | `"Name"`         |
| `Tags.0.Value` | string | `"example-rds"`  |
| `Tags.*.Key`   | string | (all tag keys)   |
| `Tags.*.Value` | string | (all tag values) |

---

## State Fields

### Scalar State Fields

| State Field                 | Type    | Allowed Operations              | Maps To Collected Field     |
| --------------------------- | ------- | ------------------------------- | --------------------------- |
| `found`                     | boolean | `=`, `!=`                       | `found`                     |
| `group_id`                  | string  | `=`, `!=`, `contains`, `starts` | `group_id`                  |
| `group_name`                | string  | `=`, `!=`, `contains`, `starts` | `group_name`                |
| `vpc_id`                    | string  | `=`, `!=`                       | `vpc_id`                    |
| `description`               | string  | `=`, `!=`, `contains`           | `description`               |
| `ingress_rule_count`        | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `ingress_rule_count`        |
| `egress_rule_count`         | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `egress_rule_count`         |
| `has_ingress_from_anywhere` | boolean | `=`, `!=`                       | `has_ingress_from_anywhere` |
| `has_egress_to_anywhere`    | boolean | `=`, `!=`                       | `has_egress_to_anywhere`    |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                             |
| ----------- | ----------------------- | --------------------------------------- |
| `record`    | `resource`              | Deep inspection of ingress/egress rules |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `aws_security_group_collector` |
| Collector Type               | `aws_security_group`           |
| Collection Mode              | Content                        |
| Required Capabilities        | `aws_cli`, `ec2_read`          |
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
  "Action": ["ec2:DescribeSecurityGroups"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                        |
| ----------- | ------------------------------------------------------------ |
| method_type | `ApiCall`                                                    |
| description | `"Query security group configuration via AWS EC2 API"`       |
| target      | `"sg:<group_id>"` or `"sg:name:<group_name>"`                |
| command     | `"aws ec2 describe-security-groups"`                         |
| inputs      | `group_id`, `group_name`, `vpc_id`, `region` (when provided) |

---

## ESP Examples

### Validate RDS security group allows only PostgreSQL from EKS

```esp
OBJECT rds_security_group
    group_name `example-rds`
    region `us-east-1`
OBJECT_END

STATE rds_sg_locked_down
    found boolean = true
    group_name string = `example-rds`
    has_ingress_from_anywhere boolean = false
    ingress_rule_count int = 1
    record
        field IpPermissions.0.IpProtocol string = `tcp`
        field IpPermissions.0.FromPort int = 5432
        field IpPermissions.0.ToPort int = 5432
        field IpPermissions.0.UserIdGroupPairs.*.GroupId string = `sg-0cccccccccccccccc0` at_least_one
    record_end
STATE_END

CTN aws_security_group
    TEST all all AND
    STATE_REF rds_sg_locked_down
    OBJECT_REF rds_security_group
CTN_END
```

### Validate EKS cluster SG has self-referencing rule

```esp
OBJECT eks_cluster_sg
    group_id `sg-0cccccccccccccccc0`
    region `us-east-1`
OBJECT_END

STATE eks_sg_self_ref
    found boolean = true
    record
        field IpPermissions.*.IpProtocol string = `-1` at_least_one
        field IpPermissions.*.UserIdGroupPairs.*.GroupId string = `sg-0cccccccccccccccc0` at_least_one
    record_end
STATE_END

CTN aws_security_group
    TEST all all AND
    STATE_REF eks_sg_self_ref
    OBJECT_REF eks_cluster_sg
CTN_END
```

### Verify no open ingress (0.0.0.0/0)

```esp
OBJECT boundary_sg
    group_name `example-rds`
    region `us-east-1`
OBJECT_END

STATE no_open_ingress
    found boolean = true
    has_ingress_from_anywhere boolean = false
STATE_END

CTN aws_security_group
    TEST all all
    STATE_REF no_open_ingress
    OBJECT_REF boundary_sg
CTN_END
```

### Validate security group belongs to correct VPC

```esp
OBJECT app_sg
    group_name `example-rds`
    region `us-east-1`
OBJECT_END

STATE correct_vpc
    found boolean = true
    vpc_id string = `vpc-0fedcba9876543210`
STATE_END

CTN aws_security_group
    TEST all all
    STATE_REF correct_vpc
    OBJECT_REF app_sg
CTN_END
```

---

## Error Conditions

| Condition                                     | Error Type                   | Outcome       | Notes                                                  |
| --------------------------------------------- | ---------------------------- | ------------- | ------------------------------------------------------ |
| No security groups match query                | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent     |
| Neither `group_id` nor `group_name` specified | `InvalidObjectConfiguration` | Error         | At least one required                                  |
| `aws` CLI binary not found                    | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                   |
| Invalid AWS credentials                       | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error        |
| IAM access denied                             | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`  |
| Invalid group_id format                       | `CollectionFailed`           | Error         | AWS API rejects the ID                                 |
| JSON parse failure                            | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                 |
| Incompatible CTN type                         | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_security_group"` |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Security group not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type          | Relationship                                                 |
| ----------------- | ------------------------------------------------------------ |
| `aws_vpc`         | Security groups belong to VPCs; validate VPC exists first    |
| `aws_subnet`      | Subnets use SGs indirectly via ENIs; validates network layer |
| `aws_route_table` | Route tables + SGs together prove boundary control           |
| `aws_network_acl` | NACLs provide defense-in-depth alongside SGs                 |
