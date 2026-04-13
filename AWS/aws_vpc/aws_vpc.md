# aws_vpc

## Overview

Validates AWS VPC configurations via the AWS CLI. Collects from up to three API calls: `describe-vpcs` (core configuration), plus two `describe-vpc-attribute` calls for DNS settings. Returns scalar fields only — this contract does not produce RecordData.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Up to three AWS CLI commands per object via `AwsClient`

**Note:** This is the only AWS contract that uses `AwsClient` helper methods (`describe_vpcs`, `describe_vpc_attribute`) instead of calling `client.execute()` directly. It also uses `exists` instead of `found` for its existence field, and does not produce a `resource` RecordData field.

---

## Object Fields

| Field    | Type   | Required | Description                                | Example                     |
| -------- | ------ | -------- | ------------------------------------------ | --------------------------- |
| `vpc_id` | string | No\*     | VPC ID for direct lookup                   | `vpc-0fedcba9876543210`     |
| `tags`   | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-toy-boundary` |
| `region` | string | No       | AWS region override (passed as `--region`) | `us-east-1`                 |

\* At least one of `vpc_id` or `tags` must be specified. If neither is provided, the collector returns `InvalidObjectConfiguration`.

- If `vpc_id` is provided, it is passed as `--vpc-ids` for direct lookup.
- `tags` is parsed via `parse_tag_filter()` (splits on first `=`) and converted to a filter tuple `("tag:<Key>", "<Value>")`.
- Both can be provided — they are passed to `AwsClient::describe_vpcs()` together.
- If multiple VPCs match, a warning is logged and the **first result** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

Unlike other AWS contracts that call `client.execute()` directly, this collector uses `AwsClient` helper methods that internally build and execute the commands.

All commands are ultimately built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command 1: describe-vpcs

Retrieves VPC configuration. Called via `client.describe_vpcs(vpc_id, filters)`.

**Internal call:** `client.execute("ec2", "describe-vpcs", &args)`

The helper method builds arguments:

- If `vpc_id` is provided: `--vpc-ids <vpc_id>`
- If tag filters are provided: `--filters Name=tag:<Key>,Values=<Value>`

**Resulting commands (examples):**

```
# By VPC ID
aws ec2 describe-vpcs --vpc-ids vpc-0fedcba9876543210 --output json

# By tag
aws ec2 describe-vpcs --filters Name=tag:Name,Values=example-toy-boundary --output json

# With region
aws ec2 describe-vpcs --region us-east-1 --output json --vpc-ids vpc-0fedcba9876543210
```

**Response parsing:**

1. The helper method extracts `response["Vpcs"]` as a JSON array
2. Each element is deserialized into a `VpcDescription` struct
3. If the array is empty, set `exists = false` and skip Commands 2 and 3

**Fields extracted from `VpcDescription`:**

| Collected Field | Struct Field     | Source JSON Key                      |
| --------------- | ---------------- | ------------------------------------ |
| `vpc_id`        | `vpc.vpc_id`     | `VpcId`                              |
| `cidr_block`    | `vpc.cidr_block` | `CidrBlock`                          |
| `state`         | `vpc.state`      | `State`                              |
| `is_default`    | `vpc.is_default` | `IsDefault`                          |
| `tag_name`      | `vpc.name()`     | `Tags` array — finds `Key == "Name"` |

### Command 2: describe-vpc-attribute (enableDnsSupport)

Retrieves DNS support setting. **Only called if Command 1 found a VPC.**

**Internal call:** `client.describe_vpc_attribute(&vpc.vpc_id, "enableDnsSupport")`

Which calls: `client.execute("ec2", "describe-vpc-attribute", &["--vpc-id", vpc_id, "--attribute", "enableDnsSupport"])`

**Resulting command:**

```
aws ec2 describe-vpc-attribute --vpc-id vpc-0fedcba9876543210 --attribute enableDnsSupport --output json
```

**Response parsing:**

Extracts `response["EnableDnsSupport"]["Value"]` as a boolean. Defaults to `false` on failure (logged as a warning).

### Command 3: describe-vpc-attribute (enableDnsHostnames)

Retrieves DNS hostnames setting. **Only called if Command 1 found a VPC.**

**Internal call:** `client.describe_vpc_attribute(&vpc.vpc_id, "enableDnsHostnames")`

Which calls: `client.execute("ec2", "describe-vpc-attribute", &["--vpc-id", vpc_id, "--attribute", "enableDnsHostnames"])`

**Resulting command:**

```
aws ec2 describe-vpc-attribute --vpc-id vpc-0fedcba9876543210 --attribute enableDnsHostnames --output json
```

**Response parsing:**

Extracts `response["EnableDnsHostnames"]["Value"]` as a boolean. Defaults to `false` on failure (logged as a warning).

### DNS attribute failure behavior

If either `describe-vpc-attribute` call fails, the collector **does not** return an error. Instead, it logs a warning and defaults the value to `false`. This means a VPC with DNS support enabled could report `enable_dns_support = false` if the attribute API call fails due to permissions or timeouts.

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

This collector does **not** have special not-found error handling for the `describe-vpcs` call. An empty `Vpcs` array is the normal not-found case. Errors from `describe-vpc-attribute` are caught and logged as warnings, not propagated.

---

## Collected Data Fields

### Scalar Fields

| Field                  | Type    | Always Present       | Source                                                                          |
| ---------------------- | ------- | -------------------- | ------------------------------------------------------------------------------- |
| `exists`               | boolean | Yes                  | Derived — `true` if at least one VPC matched                                    |
| `vpc_id`               | string  | When exists          | `VpcDescription.vpc_id` (from `VpcId`)                                          |
| `cidr_block`           | string  | When exists          | `VpcDescription.cidr_block` (from `CidrBlock`)                                  |
| `state`                | string  | When exists          | `VpcDescription.state` (from `State`)                                           |
| `is_default`           | boolean | When exists          | `VpcDescription.is_default` (from `IsDefault`)                                  |
| `enable_dns_support`   | boolean | When exists          | `describe-vpc-attribute("enableDnsSupport")` — defaults to `false` on failure   |
| `enable_dns_hostnames` | boolean | When exists          | `describe-vpc-attribute("enableDnsHostnames")` — defaults to `false` on failure |
| `tag_name`             | string  | When Name tag exists | `VpcDescription.name()` — from `Tags` array                                     |

**Key difference from other AWS contracts:** This contract uses `exists` (not `found`) as the existence field, and does not produce a `resource` RecordData field. There is no record check support.

### No RecordData Field

Unlike other AWS contracts, `aws_vpc` does not collect or produce a `resource` RecordData field. All validation is done through scalar state fields. For deep VPC inspection, use the related CTN types (`aws_subnet`, `aws_security_group`, `aws_route_table`, etc.).

---

## State Fields

| State Field            | Type    | Allowed Operations                               | Maps To Collected Field |
| ---------------------- | ------- | ------------------------------------------------ | ----------------------- |
| `exists`               | boolean | `=`, `!=`                                        | `exists`                |
| `vpc_id`               | string  | `=`, `!=`, `pattern_match`                       | `vpc_id`                |
| `cidr_block`           | string  | `=`, `!=`, `contains`, `starts`, `pattern_match` | `cidr_block`            |
| `state`                | string  | `=`, `!=`                                        | `state`                 |
| `is_default`           | boolean | `=`, `!=`                                        | `is_default`            |
| `enable_dns_support`   | boolean | `=`, `!=`                                        | `enable_dns_support`    |
| `enable_dns_hostnames` | boolean | `=`, `!=`                                        | `enable_dns_hostnames`  |
| `tag_name`             | string  | `=`, `!=`, `contains`, `pattern_match`           | `tag_name`              |

**Note:** This contract supports `pattern_match` on several string fields (`vpc_id`, `cidr_block`, `tag_name`), unlike most other AWS contracts. The executor uses `string::compare()` from the framework for all string operations, making the full set of string operations available.

---

## Collection Strategy

| Property                     | Value                 |
| ---------------------------- | --------------------- |
| Collector ID                 | `aws_vpc_collector`   |
| Collector Type               | `aws_vpc`             |
| Collection Mode              | Custom(`api`)         |
| Required Capabilities        | `aws_api`, `ec2_read` |
| Expected Collection Time     | ~500ms                |
| Memory Usage                 | ~5MB                  |
| Network Intensive            | Yes                   |
| CPU Intensive                | No                    |
| Requires Elevated Privileges | No                    |
| Batch Collection             | No                    |

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
  "Action": ["ec2:DescribeVpcs", "ec2:DescribeVpcAttribute"],
  "Resource": "*"
}
```

**Note:** Most other AWS contracts only need one IAM action. This one needs two because `DescribeVpcAttribute` is a separate API from `DescribeVpcs`. If the IAM policy only grants `DescribeVpcs`, the DNS fields will default to `false` with a warning.

### Collection Method Traceability

| Field       | Value                                       |
| ----------- | ------------------------------------------- |
| method_type | `ApiCall`                                   |
| description | `"Query VPC configuration via AWS EC2 API"` |
| target      | `"vpc:<vpc_id>"` or `"vpc:tag:<tags>"`      |
| command     | `"aws ec2 describe-vpcs"`                   |
| inputs      | `vpc_id`, `tags`, `region` (when provided)  |

---

## ESP Examples

### Basic VPC existence check

```esp
OBJECT my_vpc
    vpc_id `vpc-0fedcba9876543210`
OBJECT_END

STATE vpc_exists
    exists boolean = true
STATE_END

CTN aws_vpc
    TEST all all
    STATE_REF vpc_exists
    OBJECT_REF my_vpc
CTN_END
```

### VPC configuration validation

```esp
OBJECT boundary_vpc
    tags `Name=example-toy-boundary`
    region `us-east-1`
OBJECT_END

STATE vpc_properly_configured
    exists boolean = true
    enable_dns_support boolean = true
    enable_dns_hostnames boolean = true
    is_default boolean = false
STATE_END

CTN aws_vpc
    TEST all all
    STATE_REF vpc_properly_configured
    OBJECT_REF boundary_vpc
CTN_END
```

### Validate VPC is NOT the default

```esp
OBJECT production_vpc
    tags `Environment=production`
OBJECT_END

STATE not_default_vpc
    exists boolean = true
    is_default boolean = false
STATE_END

CTN aws_vpc
    TEST all all
    STATE_REF not_default_vpc
    OBJECT_REF production_vpc
CTN_END
```

### Validate CIDR block pattern

```esp
OBJECT internal_vpc
    vpc_id `vpc-0fedcba9876543210`
OBJECT_END

STATE uses_internal_cidr
    exists boolean = true
    cidr_block string starts `10.`
STATE_END

CTN aws_vpc
    TEST all all
    STATE_REF uses_internal_cidr
    OBJECT_REF internal_vpc
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome                 | Notes                                                 |
| ---------------------------------------- | ---------------------------- | ----------------------- | ----------------------------------------------------- |
| VPC not found                            | N/A (not an error)           | `exists=false`          | Scalar fields absent (except `exists`)                |
| Neither `vpc_id` nor `tags` specified    | `InvalidObjectConfiguration` | Error                   | At least one required                                 |
| `aws` CLI binary not found               | `CollectionFailed`           | Error                   | `Command::new("aws")` fails to spawn                  |
| Invalid AWS credentials                  | `CollectionFailed`           | Error                   | CLI returns non-zero exit with credential error       |
| IAM access denied (DescribeVpcs)         | `CollectionFailed`           | Error                   | stderr matched `AccessDenied` or `UnauthorizedAccess` |
| IAM access denied (DescribeVpcAttribute) | N/A (warning only)           | DNS defaults to `false` | Logged as warning, collection continues               |
| Invalid VPC ID format                    | `CollectionFailed`           | Error                   | AWS API rejects the ID                                |
| JSON parse failure                       | `CollectionFailed`           | Error                   | `serde_json::from_str` fails on stdout                |
| Incompatible CTN type                    | `CtnContractValidation`      | Error                   | Collector validates `ctn_type == "aws_vpc"`           |

### Executor Validation

The executor requires the `exists` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `exists` is `false`, scalar field checks against missing fields will **fail** (field not collected).

---

## Related CTN Types

| CTN Type               | Relationship                        |
| ---------------------- | ----------------------------------- |
| `aws_subnet`           | Validates subnets within a VPC      |
| `aws_security_group`   | Validates security groups in a VPC  |
| `aws_route_table`      | Validates routing for a VPC         |
| `aws_internet_gateway` | Checks IGW attachment to VPC        |
| `aws_nat_gateway`      | NAT gateway placement in VPC        |
| `aws_flow_log`         | Validates VPC flow logs are enabled |
