# aws_internet_gateway

## Overview

Validates AWS EC2 Internet Gateway configurations via the AWS CLI. Returns scalar summary fields including attachment details and the full API response as RecordData for deep inspection using record checks.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EC2 API returns **PascalCase** field names (e.g., `InternetGatewayId`, `Attachments`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field                 | Type   | Required | Description                                | Example                 |
| --------------------- | ------ | -------- | ------------------------------------------ | ----------------------- |
| `internet_gateway_id` | string | No\*     | IGW ID for direct lookup                   | `igw-0123456789abcdef0` |
| `vpc_id`              | string | No\*     | VPC ID to find attached IGW                | `vpc-0fedcba9876543210` |
| `tags`                | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-igw`      |
| `region`              | string | No       | AWS region override (passed as `--region`) | `us-east-1`             |

\* At least one of `internet_gateway_id`, `vpc_id`, or `tags` must be specified. If none are provided, the collector returns `InvalidObjectConfiguration`.

- `internet_gateway_id` uses `--internet-gateway-ids` for direct lookup.
- `vpc_id` is added as a `--filters Name=attachment.vpc-id,Values=<value>` argument, finding the IGW attached to a specific VPC.
- `tags` is parsed via `parse_tag_filter()` (splits on first `=`) and added as `--filters Name=tag:<Key>,Values=<Value>`.
- Multiple lookup fields can be combined — all are passed in the same command.
- If multiple IGWs match, a warning is logged and the **first result** is used.
- An IGW can only be attached to one VPC at a time.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-internet-gateways

Retrieves internet gateway configurations matching the specified filters.

**Collector call:** `client.execute("ec2", "describe-internet-gateways", &args)` where `args` is built dynamically from object fields.

**Argument assembly:**

The collector builds an argument list from the object fields in this order:

1. If `internet_gateway_id` is present: `--internet-gateway-ids <internet_gateway_id>`
2. If `vpc_id` is present: `--filters Name=attachment.vpc-id,Values=<vpc_id>`
3. If `tags` is present and parseable: `--filters Name=tag:<Key>,Values=<Value>`

Note: This collector uses `--filters` (plural) for filter arguments, unlike the flow log collector which uses `--filter` (singular). This matches the EC2 `describe-internet-gateways` API.

**Resulting commands (examples):**

```
# By IGW ID
aws ec2 describe-internet-gateways --internet-gateway-ids igw-0123456789abcdef0 --output json

# By VPC ID (find IGW attached to this VPC)
aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=vpc-0fedcba9876543210 --output json

# By tag
aws ec2 describe-internet-gateways --filters Name=tag:Name,Values=example-igw --output json

# With region
aws ec2 describe-internet-gateways --region us-east-1 --output json --filters Name=attachment.vpc-id,Values=vpc-0fedcba9876543210
```

**Response parsing:**

1. Extract `response["InternetGateways"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. If non-empty, use `gateways[0]` (the first element via direct indexing)
4. If multiple results exist, log a warning and use the first

**Scalar field extraction from the gateway object:**

| Collected Field       | JSON Path              | Extraction                                     |
| --------------------- | ---------------------- | ---------------------------------------------- |
| `internet_gateway_id` | `InternetGatewayId`    | `.as_str()`                                    |
| `tag_name`            | `Tags` array           | Iterate, find `Key == "Name"`, extract `Value` |
| `attachment_count`    | `Attachments`          | Array length as i64                            |
| `attached_vpc_id`     | `Attachments[0].VpcId` | First attachment's VpcId via `.as_str()`       |
| `attachment_state`    | `Attachments[0].State` | First attachment's State via `.as_str()`       |

**Sample response:**

```json
{
  "InternetGateways": [
    {
      "InternetGatewayId": "igw-0123456789abcdef0",
      "OwnerId": "123456789012",
      "Attachments": [
        {
          "State": "available",
          "VpcId": "vpc-0fedcba9876543210"
        }
      ],
      "Tags": [{ "Key": "Name", "Value": "example-igw" }]
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

This collector does **not** have special not-found error handling — all API errors are mapped to `CollectionError::CollectionFailed`. An empty `InternetGateways` array is the normal not-found case.

---

## Collected Data Fields

### Scalar Fields

| Field                 | Type    | Always Present | Source                                                        |
| --------------------- | ------- | -------------- | ------------------------------------------------------------- |
| `found`               | boolean | Yes            | Derived — `true` if at least one IGW matched                  |
| `internet_gateway_id` | string  | When found     | `InternetGatewayId` (string)                                  |
| `tag_name`            | string  | When found     | `Tags` array — value of the tag where `Key == "Name"`         |
| `attachment_count`    | int     | When found     | Derived — length of `Attachments` array (0 if no attachments) |
| `attached_vpc_id`     | string  | When found     | `Attachments[0].VpcId` (string) — first attachment only       |
| `attachment_state`    | string  | When found     | `Attachments[0].State` (string) — first attachment only       |

The `attached_vpc_id` and `attachment_state` fields are only present if the `Attachments` array has at least one element. An IGW that exists but is detached will have `attachment_count = 0` and no `attached_vpc_id` or `attachment_state` fields.

### RecordData Field

| Field      | Type       | Always Present | Description                                                                  |
| ---------- | ---------- | -------------- | ---------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full IGW object from `describe-internet-gateways`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete internet gateway object as returned by the EC2 API:

```rust
let record_data = RecordData::from_json_value(igw.clone());
```

| Path                  | Type   | Example Value                 |
| --------------------- | ------ | ----------------------------- |
| `InternetGatewayId`   | string | `"igw-0123456789abcdef0"`     |
| `OwnerId`             | string | `"123456789012"`              |
| `Attachments.0.State` | string | `"available"`                 |
| `Attachments.0.VpcId` | string | `"vpc-0fedcba9876543210"`     |
| `Attachments.*.VpcId` | string | (all attached VPC IDs)        |
| `Attachments.*.State` | string | (all attachment states)       |
| `Tags.0.Key`          | string | `"Name"`                      |
| `Tags.0.Value`        | string | `"example-igw"`               |
| `Tags.*.Key`          | string | (all tag keys via wildcard)   |
| `Tags.*.Value`        | string | (all tag values via wildcard) |

---

## State Fields

### Scalar State Fields

| State Field           | Type    | Allowed Operations              | Maps To Collected Field |
| --------------------- | ------- | ------------------------------- | ----------------------- |
| `found`               | boolean | `=`, `!=`                       | `found`                 |
| `internet_gateway_id` | string  | `=`, `!=`, `starts`             | `internet_gateway_id`   |
| `tag_name`            | string  | `=`, `!=`, `contains`           | `tag_name`              |
| `attached_vpc_id`     | string  | `=`, `!=`                       | `attached_vpc_id`       |
| `attachment_state`    | string  | `=`, `!=`                       | `attachment_state`      |
| `attachment_count`    | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `attachment_count`      |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                            |
| ---------------------------- | -------------------------------- |
| Collector ID                 | `aws_internet_gateway_collector` |
| Collector Type               | `aws_internet_gateway`           |
| Collection Mode              | Content                          |
| Required Capabilities        | `aws_cli`, `ec2_read`            |
| Expected Collection Time     | ~2000ms                          |
| Memory Usage                 | ~5MB                             |
| Network Intensive            | Yes                              |
| CPU Intensive                | No                               |
| Requires Elevated Privileges | No                               |
| Batch Collection             | No                               |

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
  "Action": ["ec2:DescribeInternetGateways"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                      |
| ----------- | -------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                  |
| description | `"Query Internet Gateway configuration via AWS EC2 API"`                   |
| target      | `"igw:<internet_gateway_id>"`, `"igw:vpc:<vpc_id>"`, or `"igw:tag:<tags>"` |
| command     | `"aws ec2 describe-internet-gateways"`                                     |
| inputs      | `internet_gateway_id`, `vpc_id`, `tags`, `region` (when provided)          |

---

## ESP Examples

### Validate IGW is attached to boundary VPC

```esp
OBJECT boundary_igw
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE igw_attached
    found boolean = true
    attached_vpc_id string = `vpc-0fedcba9876543210`
    attachment_state string = `available`
    attachment_count int = 1
STATE_END

CTN aws_internet_gateway
    TEST all all AND
    STATE_REF igw_attached
    OBJECT_REF boundary_igw
CTN_END
```

### Validate IGW by name tag

```esp
OBJECT scanset_igw
    tags `Name=example-igw`
    region `us-east-1`
OBJECT_END

STATE igw_correct
    found boolean = true
    tag_name string = `example-igw`
    internet_gateway_id string = `igw-0123456789abcdef0`
    attached_vpc_id string = `vpc-0fedcba9876543210`
STATE_END

CTN aws_internet_gateway
    TEST all all AND
    STATE_REF igw_correct
    OBJECT_REF scanset_igw
CTN_END
```

### Validate attachment details with record checks

```esp
OBJECT boundary_igw
    vpc_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE igw_attachment_valid
    found boolean = true
    record
        field Attachments.0.VpcId string = `vpc-0fedcba9876543210`
        field Attachments.0.State string = `available`
    record_end
STATE_END

CTN aws_internet_gateway
    TEST all all AND
    STATE_REF igw_attachment_valid
    OBJECT_REF boundary_igw
CTN_END
```

### Verify IGW exists by direct ID

```esp
OBJECT specific_igw
    internet_gateway_id `igw-0123456789abcdef0`
    region `us-east-1`
OBJECT_END

STATE igw_exists
    found boolean = true
    attachment_state string = `available`
STATE_END

CTN aws_internet_gateway
    TEST all all AND
    STATE_REF igw_exists
    OBJECT_REF specific_igw
CTN_END
```

---

## Error Conditions

| Condition                  | Error Type                   | Outcome       | Notes                                                          |
| -------------------------- | ---------------------------- | ------------- | -------------------------------------------------------------- |
| No IGWs match query        | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent             |
| No lookup fields specified | `InvalidObjectConfiguration` | Error         | At least one of `internet_gateway_id`, `vpc_id`, `tags` needed |
| `aws` CLI binary not found | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                           |
| Invalid AWS credentials    | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error                |
| IAM access denied          | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`          |
| JSON parse failure         | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                         |
| Incompatible CTN type      | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_internet_gateway"`       |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Internet gateway not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type             | Relationship                                                    |
| -------------------- | --------------------------------------------------------------- |
| `aws_vpc`            | IGW attaches to VPC                                             |
| `aws_route_table`    | Route tables reference IGW as gateway target                    |
| `aws_nat_gateway`    | NAT provides outbound-only internet; IGW provides bidirectional |
| `aws_security_group` | SGs control traffic that flows through IGW                      |
