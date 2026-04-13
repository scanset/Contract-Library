# aws_route_table

## Overview

Validates AWS EC2 route table configurations via the AWS CLI. Returns scalar summary fields including derived routing analysis booleans and the full API response as RecordData for detailed route and association inspection using record checks.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EC2 API returns **PascalCase** field names (e.g., `RouteTableId`, `Routes`, `Associations`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field            | Type   | Required | Description                                | Example                   |
| ---------------- | ------ | -------- | ------------------------------------------ | ------------------------- |
| `route_table_id` | string | No\*     | Route table ID for direct lookup           | `rtb-0fedcba9876543210`   |
| `vpc_id`         | string | No\*     | VPC ID to scope the lookup                 | `vpc-0fedcba9876543210`   |
| `tags`           | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-private-rt` |
| `region`         | string | No       | AWS region override (passed as `--region`) | `us-east-1`               |

\* At least one of `route_table_id`, `vpc_id`, or `tags` must be specified. If none are provided, the collector returns `InvalidObjectConfiguration`.

- `route_table_id` uses `--route-table-ids` for direct lookup.
- `vpc_id` is added as a `--filters Name=vpc-id,Values=<value>` argument.
- `tags` is parsed via `parse_tag_filter()` (splits on first `=`) and added as `--filters Name=tag:<Key>,Values=<Value>`.
- `tags` + `vpc_id` is the recommended combination for named route tables (a VPC typically has multiple route tables).
- Multiple lookup fields can be combined — all are passed in the same command.
- If multiple route tables match, a warning is logged and the **first result** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-route-tables

Retrieves route table configurations matching the specified filters.

**Collector call:** `client.execute("ec2", "describe-route-tables", &args)` where `args` is built dynamically from object fields.

**Argument assembly:**

The collector builds an argument list from the object fields in this order:

1. If `route_table_id` is present: `--route-table-ids <route_table_id>`
2. If `vpc_id` is present: `--filters Name=vpc-id,Values=<vpc_id>`
3. If `tags` is present and parseable: `--filters Name=tag:<Key>,Values=<Value>`

Note: This collector uses `--filters` (plural), matching the `describe-route-tables` API.

**Resulting commands (examples):**

```
# By route table ID
aws ec2 describe-route-tables --route-table-ids rtb-0fedcba9876543210 --output json

# By VPC ID (returns all route tables in VPC — use with caution)
aws ec2 describe-route-tables --filters Name=vpc-id,Values=vpc-0fedcba9876543210 --output json

# By tag + VPC (recommended for named route tables)
aws ec2 describe-route-tables --filters Name=vpc-id,Values=vpc-0fedcba9876543210 --filters Name=tag:Name,Values=example-private-rt --output json

# With region
aws ec2 describe-route-tables --region us-east-1 --output json --filters Name=vpc-id,Values=vpc-0fedcba9876543210 --filters Name=tag:Name,Values=example-private-rt
```

**Response parsing:**

1. Extract `response["RouteTables"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. If non-empty, use `route_tables[0]` (the first element via direct indexing)
4. If multiple results exist, log a warning and use the first

**Scalar field extraction:**

Direct fields:

| Collected Field  | JSON Path      | Extraction                                     |
| ---------------- | -------------- | ---------------------------------------------- |
| `route_table_id` | `RouteTableId` | `.as_str()`                                    |
| `vpc_id`         | `VpcId`        | `.as_str()`                                    |
| `tag_name`       | `Tags` array   | Iterate, find `Key == "Name"`, extract `Value` |

Derived fields (computed from `Routes` and `Associations` arrays):

| Collected Field      | Derivation Logic                                                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `is_main`            | `true` if any element in `Associations` has `Main == true`                                                                        |
| `route_count`        | Length of `Routes` array (includes the local route)                                                                               |
| `association_count`  | Length of `Associations` array                                                                                                    |
| `has_igw_route`      | `true` if any route's `GatewayId` starts with `"igw-"`                                                                            |
| `has_nat_route`      | `true` if any route has a `NatGatewayId` field present (non-null)                                                                 |
| `has_internet_route` | `true` if any route has `DestinationCidrBlock == "0.0.0.0/0"` AND (`GatewayId` starts with `"igw-"` OR `NatGatewayId` is present) |

**Sample response (abbreviated):**

```json
{
  "RouteTables": [
    {
      "RouteTableId": "rtb-0fedcba9876543210",
      "VpcId": "vpc-0fedcba9876543210",
      "OwnerId": "123456789012",
      "Routes": [
        {
          "DestinationCidrBlock": "10.0.0.0/16",
          "GatewayId": "local",
          "Origin": "CreateRouteTable",
          "State": "active"
        },
        {
          "DestinationCidrBlock": "0.0.0.0/0",
          "NatGatewayId": "nat-0123456789abcdef0",
          "Origin": "CreateRoute",
          "State": "active"
        }
      ],
      "Associations": [
        {
          "RouteTableAssociationId": "rtbassoc-0ac550ae75bd211a3",
          "RouteTableId": "rtb-0fedcba9876543210",
          "SubnetId": "subnet-0cccccccccccccccc",
          "Main": false,
          "AssociationState": { "State": "associated" }
        },
        {
          "RouteTableAssociationId": "rtbassoc-0bc660bf86ce322b4",
          "RouteTableId": "rtb-0fedcba9876543210",
          "SubnetId": "subnet-0eeeeeeeeeeeeeeee",
          "Main": false,
          "AssociationState": { "State": "associated" }
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "example-private-rt" }]
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

This collector does **not** have special not-found error handling — all API errors are mapped to `CollectionError::CollectionFailed`. An empty `RouteTables` array is the normal not-found case.

---

## Collected Data Fields

### Scalar Fields

| Field                | Type    | Always Present | Source                                                    |
| -------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`              | boolean | Yes            | Derived — `true` if at least one route table matched      |
| `route_table_id`     | string  | When found     | `RouteTableId` (string)                                   |
| `vpc_id`             | string  | When found     | `VpcId` (string)                                          |
| `tag_name`           | string  | When found     | `Tags` array — value of the tag where `Key == "Name"`     |
| `is_main`            | boolean | When found     | Derived — any `Associations[].Main == true`               |
| `route_count`        | int     | When found     | Derived — length of `Routes` array (includes local route) |
| `association_count`  | int     | When found     | Derived — length of `Associations` array                  |
| `has_igw_route`      | boolean | When found     | Derived — any `Routes[].GatewayId` starts with `"igw-"`   |
| `has_nat_route`      | boolean | When found     | Derived — any `Routes[].NatGatewayId` is present          |
| `has_internet_route` | boolean | When found     | Derived — `0.0.0.0/0` destination with IGW or NAT target  |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                     |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full route table object from `describe-route-tables`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete route table object as returned by the EC2 API:

```rust
let record_data = RecordData::from_json_value(rt.clone());
```

### Identity

| Path           | Type   | Example Value             |
| -------------- | ------ | ------------------------- |
| `RouteTableId` | string | `"rtb-0fedcba9876543210"` |
| `VpcId`        | string | `"vpc-0fedcba9876543210"` |
| `OwnerId`      | string | `"123456789012"`          |

### Routes (`Routes.*`)

| Path                            | Type   | Example Value             |
| ------------------------------- | ------ | ------------------------- |
| `Routes.0.DestinationCidrBlock` | string | `"10.0.0.0/16"`           |
| `Routes.0.GatewayId`            | string | `"local"`                 |
| `Routes.0.Origin`               | string | `"CreateRouteTable"`      |
| `Routes.0.State`                | string | `"active"`                |
| `Routes.1.DestinationCidrBlock` | string | `"0.0.0.0/0"`             |
| `Routes.1.NatGatewayId`         | string | `"nat-0123456789abcdef0"` |
| `Routes.*.DestinationCidrBlock` | string | (all destination CIDRs)   |
| `Routes.*.GatewayId`            | string | (all gateway targets)     |
| `Routes.*.NatGatewayId`         | string | (all NAT gateway targets) |

### Associations (`Associations.*`)

| Path                                     | Type    | Example Value                  |
| ---------------------------------------- | ------- | ------------------------------ |
| `Associations.0.SubnetId`                | string  | `"subnet-0cccccccccccccccc"`   |
| `Associations.0.Main`                    | boolean | `false`                        |
| `Associations.0.RouteTableAssociationId` | string  | `"rtbassoc-0ac550ae75bd211a3"` |
| `Associations.0.AssociationState.State`  | string  | `"associated"`                 |
| `Associations.*.SubnetId`                | string  | (all associated subnets)       |
| `Associations.*.Main`                    | boolean | (all main flags)               |

### Tags

| Path           | Type   | Example Value          |
| -------------- | ------ | ---------------------- |
| `Tags.0.Key`   | string | `"Name"`               |
| `Tags.0.Value` | string | `"example-private-rt"` |
| `Tags.*.Key`   | string | (all tag keys)         |
| `Tags.*.Value` | string | (all tag values)       |

---

## State Fields

### Scalar State Fields

| State Field          | Type    | Allowed Operations              | Maps To Collected Field |
| -------------------- | ------- | ------------------------------- | ----------------------- |
| `found`              | boolean | `=`, `!=`                       | `found`                 |
| `route_table_id`     | string  | `=`, `!=`, `starts`             | `route_table_id`        |
| `vpc_id`             | string  | `=`, `!=`                       | `vpc_id`                |
| `tag_name`           | string  | `=`, `!=`, `contains`           | `tag_name`              |
| `is_main`            | boolean | `=`, `!=`                       | `is_main`               |
| `route_count`        | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `route_count`           |
| `association_count`  | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `association_count`     |
| `has_igw_route`      | boolean | `=`, `!=`                       | `has_igw_route`         |
| `has_nat_route`      | boolean | `=`, `!=`                       | `has_nat_route`         |
| `has_internet_route` | boolean | `=`, `!=`                       | `has_internet_route`    |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                                |
| ----------- | ----------------------- | ------------------------------------------ |
| `record`    | `resource`              | Deep inspection of routes and associations |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector ID                 | `aws_route_table_collector` |
| Collector Type               | `aws_route_table`           |
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
  "Action": ["ec2:DescribeRouteTables"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                              |
| ----------- | ------------------------------------------------------------------ |
| method_type | `ApiCall`                                                          |
| description | `"Query route table configuration via AWS EC2 API"`                |
| target      | `"rt:<route_table_id>"`, `"rt:tag:<tags>"`, or `"rt:vpc:<vpc_id>"` |
| command     | `"aws ec2 describe-route-tables"`                                  |
| inputs      | `route_table_id`, `vpc_id`, `tags`, `region` (when provided)       |

---

## ESP Examples

### Validate private route table uses NAT (not IGW)

```esp
OBJECT private_rt
    tags `Name=example-private-rt`
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE private_routes_valid
    found boolean = true
    has_igw_route boolean = false
    has_nat_route boolean = true
    has_internet_route boolean = true
    is_main boolean = false
    association_count int = 2
STATE_END

CTN aws_route_table
    TEST all all AND
    STATE_REF private_routes_valid
    OBJECT_REF private_rt
CTN_END
```

### Validate public route table uses IGW

```esp
OBJECT public_rt
    tags `Name=example-public-rt`
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE public_routes_valid
    found boolean = true
    has_igw_route boolean = true
    has_nat_route boolean = false
    association_count int = 2
    record
        field Routes.*.GatewayId string = `igw-0123456789abcdef0` at_least_one
        field Routes.*.DestinationCidrBlock string = `0.0.0.0/0` at_least_one
    record_end
STATE_END

CTN aws_route_table
    TEST all all AND
    STATE_REF public_routes_valid
    OBJECT_REF public_rt
CTN_END
```

### Validate main route table has no internet route

```esp
OBJECT main_rt
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE main_rt_isolated
    found boolean = true
    is_main boolean = true
    has_internet_route boolean = false
    route_count int = 1
STATE_END

CTN aws_route_table
    TEST all all AND
    STATE_REF main_rt_isolated
    OBJECT_REF main_rt
CTN_END
```

### Validate specific route targets with record checks

```esp
OBJECT private_rt
    tags `Name=example-private-rt`
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE nat_route_details
    found boolean = true
    record
        field Routes.0.DestinationCidrBlock string = `10.0.0.0/16`
        field Routes.0.GatewayId string = `local`
        field Routes.1.DestinationCidrBlock string = `0.0.0.0/0`
        field Routes.1.NatGatewayId string starts `nat-`
        field Routes.1.State string = `active`
    record_end
STATE_END

CTN aws_route_table
    TEST all all AND
    STATE_REF nat_route_details
    OBJECT_REF private_rt
CTN_END
```

---

## Error Conditions

| Condition                   | Error Type                   | Outcome       | Notes                                                     |
| --------------------------- | ---------------------------- | ------------- | --------------------------------------------------------- |
| No route tables match query | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent        |
| No lookup fields specified  | `InvalidObjectConfiguration` | Error         | At least one of `route_table_id`, `vpc_id`, `tags` needed |
| `aws` CLI binary not found  | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                      |
| Invalid AWS credentials     | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error           |
| IAM access denied           | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`     |
| JSON parse failure          | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                    |
| Incompatible CTN type       | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_route_table"`       |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Route table not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type               | Relationship                                       |
| ---------------------- | -------------------------------------------------- |
| `aws_vpc`              | Route tables belong to VPCs                        |
| `aws_subnet`           | Subnets are associated with route tables           |
| `aws_internet_gateway` | IGW is a route target; validates IGW attachment    |
| `aws_nat_gateway`      | NAT is a route target; validates NAT placement     |
| `aws_security_group`   | SGs + route tables together prove boundary control |
