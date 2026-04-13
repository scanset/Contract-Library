# aws_nat_gateway

## Overview

Validates AWS EC2 NAT Gateway configurations via the AWS CLI. Returns scalar summary fields including placement and address details, and the full API response as RecordData for deep inspection of EIP allocation and address status using record checks.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EC2 API returns **PascalCase** field names (e.g., `NatGatewayId`, `NatGatewayAddresses`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field            | Type   | Required | Description                                | Example                 |
| ---------------- | ------ | -------- | ------------------------------------------ | ----------------------- |
| `nat_gateway_id` | string | No\*     | NAT Gateway ID for direct lookup           | `nat-0123456789abcdef0` |
| `vpc_id`         | string | No\*     | VPC ID to find NAT Gateways                | `vpc-0fedcba9876543210` |
| `tags`           | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-nat`      |
| `region`         | string | No       | AWS region override (passed as `--region`) | `us-east-1`             |

\* At least one of `nat_gateway_id`, `vpc_id`, or `tags` must be specified. If none are provided, the collector returns `InvalidObjectConfiguration`.

- `nat_gateway_id` uses `--nat-gateway-ids` for direct lookup.
- `vpc_id` is added as a `--filter Name=vpc-id,Values=<value>` argument.
- `tags` is parsed via `parse_tag_filter()` (splits on first `=`) and added as `--filter Name=tag:<Key>,Values=<Value>`.
- Multiple lookup fields can be combined — all are passed in the same command.
- If multiple NAT gateways match, a warning is logged and the **first result** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-nat-gateways

Retrieves NAT gateway configurations matching the specified filters.

**Collector call:** `client.execute("ec2", "describe-nat-gateways", &args)` where `args` is built dynamically from object fields.

**Argument assembly:**

The collector builds an argument list from the object fields in this order:

1. If `nat_gateway_id` is present: `--nat-gateway-ids <nat_gateway_id>`
2. If `vpc_id` is present: `--filter Name=vpc-id,Values=<vpc_id>`
3. If `tags` is present and parseable: `--filter Name=tag:<Key>,Values=<Value>`
4. **Always appended:** `--filter Name=state,Values=available,pending`

The state filter is **always added** automatically by the collector, regardless of which lookup fields are specified. This excludes `deleted` and `failed` NAT gateways from results. This means the API will never return NAT gateways in `deleted` or `failed` state — those states will result in `found = false`.

Note: This collector uses `--filter` (singular) for filter arguments, matching the `describe-nat-gateways` API.

**Resulting commands (examples):**

```
# By NAT gateway ID (still includes state filter)
aws ec2 describe-nat-gateways --nat-gateway-ids nat-0123456789abcdef0 --filter Name=state,Values=available,pending --output json

# By VPC ID
aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=vpc-0fedcba9876543210 --filter Name=state,Values=available,pending --output json

# By tag
aws ec2 describe-nat-gateways --filter Name=tag:Name,Values=example-nat --filter Name=state,Values=available,pending --output json

# Combined: tag + VPC + region
aws ec2 describe-nat-gateways --region us-east-1 --output json --filter Name=vpc-id,Values=vpc-0fedcba9876543210 --filter Name=tag:Name,Values=example-nat --filter Name=state,Values=available,pending
```

**Response parsing:**

1. Extract `response["NatGateways"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. If non-empty, use `gateways[0]` (the first element via direct indexing)
4. If multiple results exist, log a warning and use the first

**Scalar field extraction from the gateway object:**

| Collected Field     | JSON Path                          | Extraction                                     |
| ------------------- | ---------------------------------- | ---------------------------------------------- |
| `nat_gateway_id`    | `NatGatewayId`                     | `.as_str()`                                    |
| `state`             | `State`                            | `.as_str()`                                    |
| `vpc_id`            | `VpcId`                            | `.as_str()`                                    |
| `subnet_id`         | `SubnetId`                         | `.as_str()`                                    |
| `connectivity_type` | `ConnectivityType`                 | `.as_str()`                                    |
| `tag_name`          | `Tags` array                       | Iterate, find `Key == "Name"`, extract `Value` |
| `public_ip`         | `NatGatewayAddresses[0].PublicIp`  | First address's PublicIp via `.as_str()`       |
| `private_ip`        | `NatGatewayAddresses[0].PrivateIp` | First address's PrivateIp via `.as_str()`      |

**Sample response:**

```json
{
  "NatGateways": [
    {
      "NatGatewayId": "nat-0123456789abcdef0",
      "State": "available",
      "VpcId": "vpc-0fedcba9876543210",
      "SubnetId": "subnet-0dddddddddddddddd",
      "ConnectivityType": "public",
      "OwnerId": "123456789012",
      "CreateTime": "2026-02-21T06:23:38+00:00",
      "NatGatewayAddresses": [
        {
          "PublicIp": "203.0.113.42",
          "PrivateIp": "10.0.0.100",
          "AllocationId": "eipalloc-00ce2060da88c68b2",
          "NetworkInterfaceId": "eni-0aaaaaaaaaaaaaaa0",
          "IsPrimary": true,
          "Status": "succeeded"
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "example-nat" }]
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

This collector does **not** have special not-found error handling — all API errors are mapped to `CollectionError::CollectionFailed`. An empty `NatGateways` array is the normal not-found case.

---

## Collected Data Fields

### Scalar Fields

| Field               | Type    | Always Present | Source                                                          |
| ------------------- | ------- | -------------- | --------------------------------------------------------------- |
| `found`             | boolean | Yes            | Derived — `true` if at least one NAT gateway matched            |
| `nat_gateway_id`    | string  | When found     | `NatGatewayId` (string)                                         |
| `state`             | string  | When found     | `State` (string)                                                |
| `vpc_id`            | string  | When found     | `VpcId` (string)                                                |
| `subnet_id`         | string  | When found     | `SubnetId` (string)                                             |
| `connectivity_type` | string  | When found     | `ConnectivityType` (string)                                     |
| `tag_name`          | string  | When found     | `Tags` array — value of the tag where `Key == "Name"`           |
| `public_ip`         | string  | When found     | `NatGatewayAddresses[0].PublicIp` — only present for public NAT |
| `private_ip`        | string  | When found     | `NatGatewayAddresses[0].PrivateIp` — first address only         |

The `public_ip` and `private_ip` fields come from `NatGatewayAddresses[0]` (the first/primary address). A private NAT gateway will not have a `public_ip` field. If the `NatGatewayAddresses` array is empty or missing, neither IP field will be present.

### RecordData Field

| Field      | Type       | Always Present | Description                                                                     |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full NAT gateway object from `describe-nat-gateways`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete NAT gateway object as returned by the EC2 API:

```rust
let record_data = RecordData::from_json_value(nat.clone());
```

### Identity and placement

| Path               | Type   | Example Value                 |
| ------------------ | ------ | ----------------------------- |
| `NatGatewayId`     | string | `"nat-0123456789abcdef0"`     |
| `State`            | string | `"available"`                 |
| `VpcId`            | string | `"vpc-0fedcba9876543210"`     |
| `SubnetId`         | string | `"subnet-0dddddddddddddddd"`  |
| `ConnectivityType` | string | `"public"`                    |
| `OwnerId`          | string | `"123456789012"`              |
| `CreateTime`       | string | `"2026-02-21T06:23:38+00:00"` |

### Address paths (`NatGatewayAddresses.*`)

| Path                                       | Type    | Example Value                  |
| ------------------------------------------ | ------- | ------------------------------ |
| `NatGatewayAddresses.0.PublicIp`           | string  | `"203.0.113.42"`               |
| `NatGatewayAddresses.0.PrivateIp`          | string  | `"10.0.0.100"`                 |
| `NatGatewayAddresses.0.AllocationId`       | string  | `"eipalloc-00ce2060da88c68b2"` |
| `NatGatewayAddresses.0.NetworkInterfaceId` | string  | `"eni-0aaaaaaaaaaaaaaa0"`      |
| `NatGatewayAddresses.0.IsPrimary`          | boolean | `true`                         |
| `NatGatewayAddresses.0.Status`             | string  | `"succeeded"`                  |
| `NatGatewayAddresses.*.PublicIp`           | string  | (all public IPs via wildcard)  |
| `NatGatewayAddresses.*.PrivateIp`          | string  | (all private IPs via wildcard) |
| `NatGatewayAddresses.*.Status`             | string  | (all address statuses)         |

### Tags

| Path           | Type   | Example Value                 |
| -------------- | ------ | ----------------------------- |
| `Tags.0.Key`   | string | `"Name"`                      |
| `Tags.0.Value` | string | `"example-nat"`               |
| `Tags.*.Key`   | string | (all tag keys via wildcard)   |
| `Tags.*.Value` | string | (all tag values via wildcard) |

---

## State Fields

### Scalar State Fields

| State Field         | Type    | Allowed Operations    | Maps To Collected Field |
| ------------------- | ------- | --------------------- | ----------------------- |
| `found`             | boolean | `=`, `!=`             | `found`                 |
| `nat_gateway_id`    | string  | `=`, `!=`, `starts`   | `nat_gateway_id`        |
| `tag_name`          | string  | `=`, `!=`, `contains` | `tag_name`              |
| `state`             | string  | `=`, `!=`             | `state`                 |
| `vpc_id`            | string  | `=`, `!=`             | `vpc_id`                |
| `subnet_id`         | string  | `=`, `!=`             | `subnet_id`             |
| `connectivity_type` | string  | `=`, `!=`             | `connectivity_type`     |
| `public_ip`         | string  | `=`, `!=`, `starts`   | `public_ip`             |
| `private_ip`        | string  | `=`, `!=`, `starts`   | `private_ip`            |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_nat_gateway_collector` |
| Collector Type               | `aws_nat_gateway`           |
| Collection Mode              | Content                     |
| Required Capabilities        | `aws_cli`, `ec2_read`       |
| Expected Collection Time     | ~2000ms                     |
| Memory Usage                 | ~5MB                        |
| Network Intensive            | Yes                         |
| CPU Intensive                | No                          |
| Requires Elevated Privileges | No                          |
| Batch Collection             | No                          |

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
  "Action": ["ec2:DescribeNatGateways"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                 |
| ----------- | --------------------------------------------------------------------- |
| method_type | `ApiCall`                                                             |
| description | `"Query NAT Gateway configuration via AWS EC2 API"`                   |
| target      | `"nat:<nat_gateway_id>"`, `"nat:vpc:<vpc_id>"`, or `"nat:tag:<tags>"` |
| command     | `"aws ec2 describe-nat-gateways"`                                     |
| inputs      | `nat_gateway_id`, `vpc_id`, `tags`, `region` (when provided)          |

---

## ESP Examples

### Validate NAT Gateway is in public subnet and available

```esp
OBJECT boundary_nat
    tags `Name=example-nat`
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE nat_valid
    found boolean = true
    state string = `available`
    subnet_id string = `subnet-0dddddddddddddddd`
    connectivity_type string = `public`
    vpc_id string = `vpc-0fedcba9876543210`
STATE_END

CTN aws_nat_gateway
    TEST all all AND
    STATE_REF nat_valid
    OBJECT_REF boundary_nat
CTN_END
```

### Validate NAT has EIP with record checks

```esp
OBJECT boundary_nat
    tags `Name=example-nat`
    region `us-east-1`
OBJECT_END

STATE nat_eip_valid
    found boolean = true
    connectivity_type string = `public`
    record
        field NatGatewayAddresses.0.IsPrimary boolean = true
        field NatGatewayAddresses.0.Status string = `succeeded`
        field NatGatewayAddresses.0.AllocationId string starts `eipalloc-`
    record_end
STATE_END

CTN aws_nat_gateway
    TEST all all AND
    STATE_REF nat_eip_valid
    OBJECT_REF boundary_nat
CTN_END
```

### Validate NAT Gateway by direct ID

```esp
OBJECT private_nat
    nat_gateway_id `nat-0123456789abcdef0`
    region `us-east-1`
OBJECT_END

STATE nat_is_route_target
    found boolean = true
    nat_gateway_id string = `nat-0123456789abcdef0`
    state string = `available`
STATE_END

CTN aws_nat_gateway
    TEST all all AND
    STATE_REF nat_is_route_target
    OBJECT_REF private_nat
CTN_END
```

---

## Error Conditions

| Condition                   | Error Type                   | Outcome       | Notes                                                     |
| --------------------------- | ---------------------------- | ------------- | --------------------------------------------------------- |
| No NAT gateways match query | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent        |
| No lookup fields specified  | `InvalidObjectConfiguration` | Error         | At least one of `nat_gateway_id`, `vpc_id`, `tags` needed |
| `aws` CLI binary not found  | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                      |
| Invalid AWS credentials     | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error           |
| IAM access denied           | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`     |
| JSON parse failure          | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                    |
| Incompatible CTN type       | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_nat_gateway"`       |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"NAT gateway not found, cannot validate record checks"`

### State Filter Behavior

Because the collector always appends `--filter Name=state,Values=available,pending`, NAT gateways in `deleted` or `failed` state are never returned by the API. If you need to validate that a NAT gateway does **not** exist in a `deleted` state, the absence result (`found = false`) already confirms this — the state filter means only operational gateways are visible.

---

## Related CTN Types

| CTN Type               | Relationship                                          |
| ---------------------- | ----------------------------------------------------- |
| `aws_vpc`              | NAT Gateway belongs to a VPC                          |
| `aws_subnet`           | NAT must be in a public subnet                        |
| `aws_route_table`      | Private route tables target NAT Gateway for 0.0.0.0/0 |
| `aws_internet_gateway` | IGW enables public NAT Gateway to reach internet      |
