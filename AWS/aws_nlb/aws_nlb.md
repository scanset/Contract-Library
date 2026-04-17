# aws_nlb

## Overview

Validates AWS Network Load Balancer (NLB) configurations via the AWS CLI. Collects data from four ELBv2 API calls and returns scalar summary fields for quick checks plus the full merged API response as RecordData for deep inspection of listeners, attributes, and target groups.

**Platform:** AWS (requires `aws` CLI binary with ELBv2 read permissions)
**Collection Method:** Four AWS CLI commands per object via `AwsClient`

**Note:** The ELBv2 API returns **PascalCase** field names (e.g., `LoadBalancerName`, `Listeners`, `TargetGroups`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field               | Type   | Required | Description                                     | Example                                                                                          |
| ------------------- | ------ | -------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `load_balancer_arn` | string | No\*     | NLB ARN for direct lookup                       | `arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1234567890abcdef`   |
| `load_balancer_name`| string | No\*     | NLB name for filter-based lookup                | `my-nlb`                                                                                         |
| `region`            | string | No       | AWS region override (passed as `--region`)      | `us-east-1`                                                                                      |

\* At least one of `load_balancer_arn` or `load_balancer_name` must be specified. If neither is provided, the collector returns `InvalidObjectConfiguration`.

- `load_balancer_arn` uses `--load-balancer-arns` for direct lookup. Takes precedence over `load_balancer_name`.
- `load_balancer_name` uses `--names` flag when `load_balancer_arn` is absent.
- If multiple load balancers match, a warning is logged and the **first result with Type=network** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command 1: describe-load-balancers

Retrieves core NLB properties.

**Collector call:** `client.execute("elbv2", "describe-load-balancers", &args)`

**Argument assembly:**

1. If `load_balancer_arn` is present: `--load-balancer-arns <arn>`
2. Else if `load_balancer_name` is present: `--names <name>`

**Resulting commands (examples):**

```
# By ARN (direct lookup)
aws elbv2 describe-load-balancers --load-balancer-arns arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1234567890abcdef --output json

# By name
aws elbv2 describe-load-balancers --names my-nlb --output json

# With region
aws elbv2 describe-load-balancers --region us-east-1 --output json --names my-nlb
```

**Response parsing:**

1. Extract `response["LoadBalancers"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. Find first entry with `Type == "network"`, or fall back to `LoadBalancers[0]`
4. If multiple results exist, log a warning and use the first NLB

**Scalar field extraction:**

| Collected Field        | JSON Path           | Extraction       |
| ---------------------- | ------------------- | ---------------- |
| `load_balancer_name`   | `LoadBalancerName`  | `.as_str()`      |
| `dns_name`             | `DNSName`           | `.as_str()`      |
| `scheme`               | `Scheme`            | `.as_str()`      |
| `state`                | `State.Code`        | `.as_str()`      |
| `vpc_id`               | `VpcId`             | `.as_str()`      |
| `ip_address_type`      | `IpAddressType`     | `.as_str()`      |

**Sample response (abbreviated):**

```json
{
  "LoadBalancers": [
    {
      "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/1234567890abcdef",
      "LoadBalancerName": "my-nlb",
      "DNSName": "my-nlb-abc123.elb.us-east-1.amazonaws.com",
      "Scheme": "internal",
      "Type": "network",
      "State": { "Code": "active" },
      "VpcId": "vpc-0123456789abcdef0",
      "IpAddressType": "ipv4",
      "AvailabilityZones": [
        { "ZoneName": "us-east-1a", "SubnetId": "subnet-0123456789abcdef0" }
      ]
    }
  ]
}
```

### Command 2: describe-load-balancer-attributes

Retrieves NLB attributes (cross-zone, logging, deletion protection).

**Collector call:** `client.execute("elbv2", "describe-load-balancer-attributes", &["--load-balancer-arn", nlb_arn])`

**Scalar field extraction from attributes Key/Value array:**

| Collected Field              | Attribute Key                          | Derivation         |
| ---------------------------- | -------------------------------------- | ------------------ |
| `deletion_protection`        | `deletion_protection.enabled`          | `== "true"`        |
| `cross_zone_enabled`         | `load_balancing.cross_zone.enabled`    | `== "true"`        |
| `access_logging_enabled`     | `access_logs.s3.enabled`               | `== "true"`        |
| `access_log_s3_bucket`       | `access_logs.s3.bucket`                | String (if non-empty) |
| `connection_logging_enabled` | `connection_logs.s3.enabled`           | `== "true"`        |

The attributes are also merged into RecordData under the `Attributes` key as a flat key-value map.

**Sample response (abbreviated):**

```json
{
  "Attributes": [
    { "Key": "deletion_protection.enabled", "Value": "false" },
    { "Key": "load_balancing.cross_zone.enabled", "Value": "true" },
    { "Key": "access_logs.s3.enabled", "Value": "false" },
    { "Key": "connection_logs.s3.enabled", "Value": "false" }
  ]
}
```

### Command 3: describe-listeners

Retrieves listener configurations (protocol, port, SSL policy).

**Collector call:** `client.execute("elbv2", "describe-listeners", &["--load-balancer-arn", nlb_arn])`

**Derived fields:**

| Collected Field    | Derivation Logic                                                |
| ------------------ | --------------------------------------------------------------- |
| `listener_count`   | Length of `Listeners` array                                     |
| `has_tls_listener` | `true` if any listener has `Protocol == "TLS"`                  |

The full `Listeners` array is merged into RecordData.

**Sample response (abbreviated):**

```json
{
  "Listeners": [
    {
      "ListenerArn": "arn:aws:elasticloadbalancing:...:listener/net/my-nlb/.../abc123",
      "Protocol": "TLS",
      "Port": 443,
      "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
      "Certificates": [{ "CertificateArn": "arn:aws:acm:..." }],
      "DefaultActions": [{ "Type": "forward", "TargetGroupArn": "arn:..." }]
    }
  ]
}
```

### Command 4: describe-target-groups

Retrieves target group configurations attached to the NLB.

**Collector call:** `client.execute("elbv2", "describe-target-groups", &["--load-balancer-arn", nlb_arn])`

**Derived fields:**

| Collected Field      | Derivation Logic                   |
| -------------------- | ---------------------------------- |
| `target_group_count` | Length of `TargetGroups` array     |

The full `TargetGroups` array is merged into RecordData.

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `LoadBalancerNotFound` or `not found`        | Treated as `found=false`     |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| Anything else                                | `AwsError::CommandFailed`    |

---

## Collected Data Fields

### Scalar Fields

| Field                        | Type    | Always Present | Source                                                   |
| ---------------------------- | ------- | -------------- | -------------------------------------------------------- |
| `found`                      | boolean | Yes            | Derived - `true` if at least one NLB matched             |
| `load_balancer_name`         | string  | When found     | `LoadBalancerName` (string)                              |
| `dns_name`                   | string  | When found     | `DNSName` (string)                                       |
| `scheme`                     | string  | When found     | `Scheme` (string)                                        |
| `state`                      | string  | When found     | `State.Code` (string)                                    |
| `vpc_id`                     | string  | When found     | `VpcId` (string)                                         |
| `ip_address_type`            | string  | When found     | `IpAddressType` (string)                                 |
| `deletion_protection`        | boolean | When found     | Attribute `deletion_protection.enabled`                  |
| `cross_zone_enabled`         | boolean | When found     | Attribute `load_balancing.cross_zone.enabled`            |
| `access_logging_enabled`     | boolean | When found     | Attribute `access_logs.s3.enabled`                       |
| `access_log_s3_bucket`       | string  | When found     | Attribute `access_logs.s3.bucket` (if non-empty)         |
| `listener_count`             | int     | When found     | Derived - length of `Listeners` array                    |
| `has_tls_listener`           | boolean | When found     | Derived - any listener with Protocol=TLS                 |
| `connection_logging_enabled` | boolean | When found     | Attribute `connection_logs.s3.enabled`                   |
| `target_group_count`         | int     | When found     | Derived - length of `TargetGroups` array                 |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                           |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged NLB object + Attributes + Listeners + TargetGroups. Empty `{}` when not found  |

---

## RecordData Structure

The `resource` field contains the NLB object from `describe-load-balancers` merged with data from all subsequent API calls:

```rust
let record_data = RecordData::from_json_value(merged);
```

### Identity

| Path               | Type   | Example Value                                                                             |
| ------------------ | ------ | ----------------------------------------------------------------------------------------- |
| `LoadBalancerArn`  | string | `"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/..."` |
| `LoadBalancerName` | string | `"my-nlb"`                                                                                |
| `DNSName`          | string | `"my-nlb-abc123.elb.us-east-1.amazonaws.com"`                                            |
| `Scheme`           | string | `"internal"`                                                                              |
| `Type`             | string | `"network"`                                                                               |
| `State.Code`       | string | `"active"`                                                                                |
| `VpcId`            | string | `"vpc-0123456789abcdef0"`                                                                 |
| `IpAddressType`    | string | `"ipv4"`                                                                                  |

### Attributes (merged as flat map)

| Path                                                 | Type   | Example Value |
| ---------------------------------------------------- | ------ | ------------- |
| `Attributes.deletion_protection.enabled`             | string | `"false"`     |
| `Attributes.load_balancing.cross_zone.enabled`       | string | `"true"`      |
| `Attributes.access_logs.s3.enabled`                  | string | `"false"`     |
| `Attributes.connection_logs.s3.enabled`              | string | `"false"`     |

### Listeners (`Listeners.*`)

| Path                                        | Type    | Example Value                                |
| ------------------------------------------- | ------- | -------------------------------------------- |
| `Listeners.0.Protocol`                      | string  | `"TLS"`                                      |
| `Listeners.0.Port`                          | integer | `443`                                        |
| `Listeners.0.SslPolicy`                     | string  | `"ELBSecurityPolicy-TLS13-1-2-2021-06"`     |
| `Listeners.0.Certificates.0.CertificateArn`| string  | `"arn:aws:acm:..."`                          |
| `Listeners.0.DefaultActions.0.Type`         | string  | `"forward"`                                  |
| `Listeners.*.Protocol`                      | string  | (all listener protocols)                     |
| `Listeners.*.SslPolicy`                     | string  | (all SSL policies)                           |

### Target Groups (`TargetGroups.*`)

| Path                                    | Type    | Example Value                                       |
| --------------------------------------- | ------- | --------------------------------------------------- |
| `TargetGroups.0.TargetGroupName`        | string  | `"my-tg"`                                           |
| `TargetGroups.0.Protocol`               | string  | `"TCP"`                                             |
| `TargetGroups.0.Port`                   | integer | `443`                                               |
| `TargetGroups.0.HealthCheckProtocol`    | string  | `"TCP"`                                             |
| `TargetGroups.0.HealthCheckPath`        | string  | `"/"`                                               |
| `TargetGroups.0.TargetType`             | string  | `"instance"`                                        |
| `TargetGroups.*.TargetGroupName`        | string  | (all target group names)                            |
| `TargetGroups.*.Protocol`               | string  | (all target group protocols)                        |

---

## State Fields

### Scalar State Fields

| State Field                  | Type    | Allowed Operations              | Maps To Collected Field        |
| ---------------------------- | ------- | ------------------------------- | ------------------------------ |
| `found`                      | boolean | `=`, `!=`                       | `found`                        |
| `load_balancer_name`         | string  | `=`, `!=`, `contains`, `starts` | `load_balancer_name`           |
| `dns_name`                   | string  | `=`, `!=`, `contains`, `starts` | `dns_name`                     |
| `scheme`                     | string  | `=`, `!=`                       | `scheme`                       |
| `state`                      | string  | `=`, `!=`                       | `state`                        |
| `vpc_id`                     | string  | `=`, `!=`                       | `vpc_id`                       |
| `ip_address_type`            | string  | `=`, `!=`                       | `ip_address_type`              |
| `deletion_protection`        | boolean | `=`, `!=`                       | `deletion_protection`          |
| `cross_zone_enabled`         | boolean | `=`, `!=`                       | `cross_zone_enabled`           |
| `access_logging_enabled`     | boolean | `=`, `!=`                       | `access_logging_enabled`       |
| `access_log_s3_bucket`       | string  | `=`, `!=`, `contains`, `starts` | `access_log_s3_bucket`         |
| `listener_count`             | int     | `=`, `!=`, `>`, `>=`            | `listener_count`               |
| `has_tls_listener`           | boolean | `=`, `!=`                       | `has_tls_listener`             |
| `connection_logging_enabled` | boolean | `=`, `!=`                       | `connection_logging_enabled`   |
| `target_group_count`         | int     | `=`, `!=`, `>`, `>=`            | `target_group_count`           |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                                            |
| ----------- | ----------------------- | ------------------------------------------------------ |
| `record`    | `resource`              | Deep inspection of listeners, attributes, target groups |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector ID                 | `aws_nlb_collector`  |
| Collector Type               | `aws_nlb`            |
| Collection Mode              | Content              |
| Required Capabilities        | `aws_cli`, `elbv2_read` |
| Expected Collection Time     | ~5000ms              |
| Memory Usage                 | ~5MB                 |
| Network Intensive            | Yes                  |
| CPU Intensive                | No                   |
| Requires Elevated Privileges | No                   |
| Batch Collection             | No                   |

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
  "Action": [
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeTargetGroups"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                          |
| ----------- | ------------------------------------------------------------------------------ |
| method_type | `ApiCall`                                                                      |
| description | `"Query NLB configuration via AWS ELBv2 API"`                                  |
| target      | `"nlb:<arn>"` or `"nlb:name:<name>"`                                           |
| command     | `"aws elbv2 describe-load-balancers"`                                          |
| inputs      | `load_balancer_arn`, `load_balancer_name`, `region` (when provided)            |

---

## ESP Examples

### Validate NLB security configuration

```esp
OBJECT prod_nlb
    load_balancer_name `prod-internal-nlb`
    region `us-east-1`
OBJECT_END

STATE nlb_security
    found boolean = true
    scheme string = `internal`
    deletion_protection boolean = true
    cross_zone_enabled boolean = true
    has_tls_listener boolean = true
    target_group_count int >= 1
STATE_END

CTN aws_nlb
    TEST all all AND
    STATE_REF nlb_security
    OBJECT_REF prod_nlb
CTN_END
```

### Validate NLB TLS policy via record checks

```esp
OBJECT tls_nlb
    load_balancer_name `secure-nlb`
OBJECT_END

STATE tls_policy
    found boolean = true
    record
        field Listeners.*.Protocol string = `TLS` at_least_one
        field Listeners.*.SslPolicy string = `ELBSecurityPolicy-TLS13-1-2-2021-06` at_least_one
    record_end
STATE_END

CTN aws_nlb
    TEST all all AND
    STATE_REF tls_policy
    OBJECT_REF tls_nlb
CTN_END
```

### Validate NLB logging

```esp
OBJECT logged_nlb
    load_balancer_name `api-nlb`
OBJECT_END

STATE nlb_logging
    found boolean = true
    access_logging_enabled boolean = true
    access_log_s3_bucket string starts `nlb-logs-`
    connection_logging_enabled boolean = true
STATE_END

CTN aws_nlb
    TEST all all AND
    STATE_REF nlb_logging
    OBJECT_REF logged_nlb
CTN_END
```

### Verify NLB exists in correct VPC

```esp
OBJECT vpc_nlb
    load_balancer_name `service-nlb`
OBJECT_END

STATE correct_vpc
    found boolean = true
    vpc_id string = `vpc-0123456789abcdef0`
    state string = `active`
STATE_END

CTN aws_nlb
    TEST all all
    STATE_REF correct_vpc
    OBJECT_REF vpc_nlb
CTN_END
```

---

## Error Conditions

| Condition                                           | Error Type                   | Outcome       | Notes                                                    |
| --------------------------------------------------- | ---------------------------- | ------------- | -------------------------------------------------------- |
| No load balancers match query                       | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent       |
| Neither `load_balancer_arn` nor `name` specified    | `InvalidObjectConfiguration` | Error         | At least one required                                    |
| `aws` CLI binary not found                          | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                     |
| Invalid AWS credentials                             | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error          |
| IAM access denied                                   | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`    |
| LoadBalancerNotFound                                | N/A                          | `found=false` | Caught in error handler, returns empty result            |
| JSON parse failure                                  | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                   |
| Incompatible CTN type                               | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_nlb"`              |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"NLB not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type             | Relationship                                                           |
| -------------------- | ---------------------------------------------------------------------- |
| `aws_alb`            | Application Load Balancer - same ELBv2 API, different Type filter      |
| `aws_security_group` | NLBs can optionally reference security groups (network type)           |
| `aws_vpc`            | NLBs reside in VPCs; validate VPC exists and is configured correctly   |
| `aws_subnet`         | NLBs span subnets in availability zones                                |
| `aws_acm_certificate`| NLB TLS listeners reference ACM certificates                          |
