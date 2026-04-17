# aws_alb

## Overview

Validates AWS Application Load Balancer (ALB) configurations via the AWS CLI. Collects data from five ELBv2/WAFv2 API calls and returns scalar summary fields for quick checks plus the full merged API response as RecordData for deep inspection of listeners, attributes, WAF associations, and target groups.

**Platform:** AWS (requires `aws` CLI binary with ELBv2 and WAFv2 read permissions)
**Collection Method:** Five AWS CLI commands per object via `AwsClient`

**Note:** The ELBv2 API returns **PascalCase** field names (e.g., `LoadBalancerName`, `Listeners`, `TargetGroups`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field               | Type   | Required | Description                                     | Example                                                                                          |
| ------------------- | ------ | -------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `load_balancer_arn` | string | No\*     | ALB ARN for direct lookup                       | `arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef`   |
| `load_balancer_name`| string | No\*     | ALB name for filter-based lookup                | `my-alb`                                                                                         |
| `region`            | string | No       | AWS region override (passed as `--region`)      | `us-east-1`                                                                                      |

\* At least one of `load_balancer_arn` or `load_balancer_name` must be specified. If neither is provided, the collector returns `InvalidObjectConfiguration`.

- `load_balancer_arn` uses `--load-balancer-arns` for direct lookup. Takes precedence over `load_balancer_name`.
- `load_balancer_name` uses `--names` flag when `load_balancer_arn` is absent.
- If multiple load balancers match, a warning is logged and the **first result with Type=application** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command 1: describe-load-balancers

Retrieves core ALB properties.

**Collector call:** `client.execute("elbv2", "describe-load-balancers", &args)`

**Argument assembly:**

1. If `load_balancer_arn` is present: `--load-balancer-arns <arn>`
2. Else if `load_balancer_name` is present: `--names <name>`

**Resulting commands (examples):**

```
# By ARN (direct lookup)
aws elbv2 describe-load-balancers --load-balancer-arns arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef --output json

# By name
aws elbv2 describe-load-balancers --names my-alb --output json

# With region
aws elbv2 describe-load-balancers --region us-east-1 --output json --names my-alb
```

**Response parsing:**

1. Extract `response["LoadBalancers"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. Find first entry with `Type == "application"`, or fall back to `LoadBalancers[0]`
4. If multiple results exist, log a warning and use the first ALB

**Scalar field extraction:**

| Collected Field        | JSON Path           | Extraction       |
| ---------------------- | ------------------- | ---------------- |
| `load_balancer_name`   | `LoadBalancerName`  | `.as_str()`      |
| `dns_name`             | `DNSName`           | `.as_str()`      |
| `scheme`               | `Scheme`            | `.as_str()`      |
| `state`                | `State.Code`        | `.as_str()`      |
| `vpc_id`               | `VpcId`             | `.as_str()`      |
| `ip_address_type`      | `IpAddressType`     | `.as_str()`      |
| `security_group_count` | `SecurityGroups`    | `.len() as i64`  |

**Sample response (abbreviated):**

```json
{
  "LoadBalancers": [
    {
      "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef",
      "LoadBalancerName": "my-alb",
      "DNSName": "my-alb-123456789.us-east-1.elb.amazonaws.com",
      "Scheme": "internet-facing",
      "Type": "application",
      "State": { "Code": "active" },
      "VpcId": "vpc-0123456789abcdef0",
      "IpAddressType": "ipv4",
      "SecurityGroups": ["sg-0123456789abcdef0"],
      "AvailabilityZones": [
        { "ZoneName": "us-east-1a", "SubnetId": "subnet-0123456789abcdef0" }
      ]
    }
  ]
}
```

### Command 2: describe-load-balancer-attributes

Retrieves ALB attributes (logging, security, timeout settings).

**Collector call:** `client.execute("elbv2", "describe-load-balancer-attributes", &["--load-balancer-arn", alb_arn])`

**Scalar field extraction from attributes Key/Value array:**

| Collected Field              | Attribute Key                                          | Derivation         |
| ---------------------------- | ------------------------------------------------------ | ------------------ |
| `deletion_protection`        | `deletion_protection.enabled`                          | `== "true"`        |
| `access_logging_enabled`     | `access_logs.s3.enabled`                               | `== "true"`        |
| `access_log_s3_bucket`       | `access_logs.s3.bucket`                                | String (if non-empty) |
| `drop_invalid_header_fields` | `routing.http.drop_invalid_header_fields.enabled`      | `== "true"`        |
| `desync_mitigation_mode`     | `routing.http.desync_mitigation_mode`                  | String             |
| `idle_timeout_seconds`       | `idle_timeout.timeout_seconds`                         | Parsed as i64      |
| `connection_logging_enabled` | `connection_logs.s3.enabled`                           | `== "true"`        |

The attributes are also merged into RecordData under the `Attributes` key as a flat key-value map.

**Sample response (abbreviated):**

```json
{
  "Attributes": [
    { "Key": "deletion_protection.enabled", "Value": "false" },
    { "Key": "access_logs.s3.enabled", "Value": "true" },
    { "Key": "access_logs.s3.bucket", "Value": "my-alb-logs" },
    { "Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true" },
    { "Key": "routing.http.desync_mitigation_mode", "Value": "defensive" },
    { "Key": "idle_timeout.timeout_seconds", "Value": "60" },
    { "Key": "connection_logs.s3.enabled", "Value": "false" }
  ]
}
```

### Command 3: describe-listeners

Retrieves listener configurations (protocol, port, SSL policy, default actions).

**Collector call:** `client.execute("elbv2", "describe-listeners", &["--load-balancer-arn", alb_arn])`

**Derived fields:**

| Collected Field              | Derivation Logic                                                                                              |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `listener_count`             | Length of `Listeners` array                                                                                   |
| `has_https_listener`         | `true` if any listener has `Protocol == "HTTPS"`                                                              |
| `has_http_to_https_redirect` | `true` if any HTTP listener has a DefaultAction with `Type == "redirect"` and `RedirectConfig.Protocol == "HTTPS"` |

The full `Listeners` array is merged into RecordData.

**Sample response (abbreviated):**

```json
{
  "Listeners": [
    {
      "ListenerArn": "arn:aws:elasticloadbalancing:...:listener/app/my-alb/.../abc123",
      "Protocol": "HTTPS",
      "Port": 443,
      "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
      "Certificates": [{ "CertificateArn": "arn:aws:acm:..." }],
      "DefaultActions": [{ "Type": "forward", "TargetGroupArn": "arn:..." }]
    },
    {
      "Protocol": "HTTP",
      "Port": 80,
      "DefaultActions": [
        {
          "Type": "redirect",
          "RedirectConfig": { "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301" }
        }
      ]
    }
  ]
}
```

### Command 4: wafv2 get-web-acl-for-resource

Checks WAF Web ACL association.

**Collector call:** `client.execute("wafv2", "get-web-acl-for-resource", &["--resource-arn", alb_arn])`

**Derived fields:**

| Collected Field | Derivation Logic                                              |
| --------------- | ------------------------------------------------------------- |
| `has_waf_acl`   | `true` if `response["WebACL"]` exists                         |
| `waf_acl_arn`   | `response["WebACL"]["ARN"]` as string (only when WAF present) |

On error (no permission or WAF not configured), `has_waf_acl` is set to `false` gracefully.

If a WebACL is present, it is merged into RecordData under the `WebACL` key.

### Command 5: describe-target-groups

Retrieves target group configurations attached to the ALB.

**Collector call:** `client.execute("elbv2", "describe-target-groups", &["--load-balancer-arn", alb_arn])`

**Derived fields:**

| Collected Field                       | Derivation Logic                                                                          |
| ------------------------------------- | ----------------------------------------------------------------------------------------- |
| `target_group_count`                  | Length of `TargetGroups` array                                                            |
| `all_target_groups_https_health_check`| `true` if non-empty AND all target groups have `HealthCheckProtocol == "HTTPS"`           |

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

| Field                                | Type    | Always Present | Source                                                   |
| ------------------------------------ | ------- | -------------- | -------------------------------------------------------- |
| `found`                              | boolean | Yes            | Derived - `true` if at least one ALB matched             |
| `load_balancer_name`                 | string  | When found     | `LoadBalancerName` (string)                              |
| `dns_name`                           | string  | When found     | `DNSName` (string)                                       |
| `scheme`                             | string  | When found     | `Scheme` (string)                                        |
| `state`                              | string  | When found     | `State.Code` (string)                                    |
| `vpc_id`                             | string  | When found     | `VpcId` (string)                                         |
| `ip_address_type`                    | string  | When found     | `IpAddressType` (string)                                 |
| `security_group_count`               | int     | When found     | Derived - length of `SecurityGroups` array               |
| `deletion_protection`                | boolean | When found     | Attribute `deletion_protection.enabled`                  |
| `access_logging_enabled`             | boolean | When found     | Attribute `access_logs.s3.enabled`                       |
| `access_log_s3_bucket`               | string  | When found     | Attribute `access_logs.s3.bucket` (if non-empty)         |
| `drop_invalid_header_fields`         | boolean | When found     | Attribute `routing.http.drop_invalid_header_fields.enabled` |
| `desync_mitigation_mode`             | string  | When found     | Attribute `routing.http.desync_mitigation_mode`          |
| `idle_timeout_seconds`               | int     | When found     | Attribute `idle_timeout.timeout_seconds`                 |
| `listener_count`                     | int     | When found     | Derived - length of `Listeners` array                    |
| `has_https_listener`                 | boolean | When found     | Derived - any listener with Protocol=HTTPS               |
| `has_http_to_https_redirect`         | boolean | When found     | Derived - any HTTP listener with redirect to HTTPS       |
| `has_waf_acl`                        | boolean | When found     | Derived - WebACL present in WAFv2 response               |
| `waf_acl_arn`                        | string  | When WAF       | `WebACL.ARN` (string)                                    |
| `connection_logging_enabled`         | boolean | When found     | Attribute `connection_logs.s3.enabled`                   |
| `target_group_count`                 | int     | When found     | Derived - length of `TargetGroups` array                 |
| `all_target_groups_https_health_check`| boolean| When found     | Derived - all TGs use HTTPS health checks                |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                       |
| ---------- | ---------- | -------------- | --------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged ALB object + Attributes + Listeners + WebACL + TargetGroups. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the ALB object from `describe-load-balancers` merged with data from all subsequent API calls:

```rust
let record_data = RecordData::from_json_value(merged);
```

### Identity

| Path               | Type   | Example Value                                                                             |
| ------------------ | ------ | ----------------------------------------------------------------------------------------- |
| `LoadBalancerArn`  | string | `"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/..."` |
| `LoadBalancerName` | string | `"my-alb"`                                                                                |
| `DNSName`          | string | `"my-alb-123456789.us-east-1.elb.amazonaws.com"`                                         |
| `Scheme`           | string | `"internet-facing"`                                                                       |
| `Type`             | string | `"application"`                                                                           |
| `State.Code`       | string | `"active"`                                                                                |
| `VpcId`            | string | `"vpc-0123456789abcdef0"`                                                                 |
| `IpAddressType`    | string | `"ipv4"`                                                                                  |

### Security Groups

| Path                | Type   | Example Value                |
| ------------------- | ------ | ---------------------------- |
| `SecurityGroups.0`  | string | `"sg-0123456789abcdef0"`     |
| `SecurityGroups.*`  | string | (all attached SG IDs)        |

### Attributes (merged as flat map)

| Path                                                          | Type   | Example Value |
| ------------------------------------------------------------- | ------ | ------------- |
| `Attributes.deletion_protection.enabled`                      | string | `"false"`     |
| `Attributes.access_logs.s3.enabled`                           | string | `"true"`      |
| `Attributes.access_logs.s3.bucket`                            | string | `"my-logs"`   |
| `Attributes.routing.http.drop_invalid_header_fields.enabled`  | string | `"true"`      |
| `Attributes.routing.http.desync_mitigation_mode`              | string | `"defensive"` |
| `Attributes.idle_timeout.timeout_seconds`                     | string | `"60"`        |
| `Attributes.connection_logs.s3.enabled`                       | string | `"false"`     |

### Listeners (`Listeners.*`)

| Path                                       | Type    | Example Value                                |
| ------------------------------------------ | ------- | -------------------------------------------- |
| `Listeners.0.Protocol`                     | string  | `"HTTPS"`                                    |
| `Listeners.0.Port`                         | integer | `443`                                        |
| `Listeners.0.SslPolicy`                    | string  | `"ELBSecurityPolicy-TLS13-1-2-2021-06"`     |
| `Listeners.0.Certificates.0.CertificateArn`| string | `"arn:aws:acm:..."`                          |
| `Listeners.0.DefaultActions.0.Type`        | string  | `"forward"`                                  |
| `Listeners.*.Protocol`                     | string  | (all listener protocols)                     |
| `Listeners.*.SslPolicy`                    | string  | (all SSL policies)                           |

### WAF (`WebACL`)

| Path          | Type   | Example Value                                                   |
| ------------- | ------ | --------------------------------------------------------------- |
| `WebACL.Name` | string | `"my-web-acl"`                                                  |
| `WebACL.ARN`  | string | `"arn:aws:wafv2:us-east-1:123456789012:regional/webacl/..."`   |
| `WebACL.Id`   | string | `"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"`                       |

### Target Groups (`TargetGroups.*`)

| Path                                    | Type    | Example Value                                       |
| --------------------------------------- | ------- | --------------------------------------------------- |
| `TargetGroups.0.TargetGroupName`        | string  | `"my-tg"`                                           |
| `TargetGroups.0.Protocol`               | string  | `"HTTPS"`                                           |
| `TargetGroups.0.Port`                   | integer | `443`                                               |
| `TargetGroups.0.HealthCheckProtocol`    | string  | `"HTTPS"`                                           |
| `TargetGroups.0.HealthCheckPath`        | string  | `"/health"`                                         |
| `TargetGroups.0.TargetType`             | string  | `"instance"`                                        |
| `TargetGroups.*.TargetGroupName`        | string  | (all target group names)                            |
| `TargetGroups.*.HealthCheckProtocol`    | string  | (all health check protocols)                        |

---

## State Fields

### Scalar State Fields

| State Field                           | Type    | Allowed Operations              | Maps To Collected Field               |
| ------------------------------------- | ------- | ------------------------------- | ------------------------------------- |
| `found`                               | boolean | `=`, `!=`                       | `found`                               |
| `load_balancer_name`                  | string  | `=`, `!=`, `contains`, `starts` | `load_balancer_name`                  |
| `dns_name`                            | string  | `=`, `!=`, `contains`, `starts` | `dns_name`                            |
| `scheme`                              | string  | `=`, `!=`                       | `scheme`                              |
| `state`                               | string  | `=`, `!=`                       | `state`                               |
| `vpc_id`                              | string  | `=`, `!=`                       | `vpc_id`                              |
| `ip_address_type`                     | string  | `=`, `!=`                       | `ip_address_type`                     |
| `deletion_protection`                 | boolean | `=`, `!=`                       | `deletion_protection`                 |
| `access_logging_enabled`              | boolean | `=`, `!=`                       | `access_logging_enabled`              |
| `access_log_s3_bucket`                | string  | `=`, `!=`, `contains`, `starts` | `access_log_s3_bucket`                |
| `drop_invalid_header_fields`          | boolean | `=`, `!=`                       | `drop_invalid_header_fields`          |
| `desync_mitigation_mode`              | string  | `=`, `!=`                       | `desync_mitigation_mode`              |
| `idle_timeout_seconds`                | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `idle_timeout_seconds`                |
| `listener_count`                      | int     | `=`, `!=`, `>`, `>=`            | `listener_count`                      |
| `has_https_listener`                  | boolean | `=`, `!=`                       | `has_https_listener`                  |
| `security_group_count`                | int     | `=`, `!=`, `>`, `>=`            | `security_group_count`                |
| `has_waf_acl`                         | boolean | `=`, `!=`                       | `has_waf_acl`                         |
| `waf_acl_arn`                         | string  | `=`, `!=`, `contains`, `starts` | `waf_acl_arn`                         |
| `connection_logging_enabled`          | boolean | `=`, `!=`                       | `connection_logging_enabled`          |
| `has_http_to_https_redirect`          | boolean | `=`, `!=`                       | `has_http_to_https_redirect`          |
| `target_group_count`                  | int     | `=`, `!=`, `>`, `>=`            | `target_group_count`                  |
| `all_target_groups_https_health_check`| boolean | `=`, `!=`                       | `all_target_groups_https_health_check`|

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                                                    |
| ----------- | ----------------------- | -------------------------------------------------------------- |
| `record`    | `resource`              | Deep inspection of listeners, attributes, WAF, target groups   |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector ID                 | `aws_alb_collector`  |
| Collector Type               | `aws_alb`            |
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
    "elasticloadbalancing:DescribeTargetGroups",
    "wafv2:GetWebACLForResource"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                          |
| ----------- | ------------------------------------------------------------------------------ |
| method_type | `ApiCall`                                                                      |
| description | `"Query ALB configuration via AWS ELBv2 API"`                                  |
| target      | `"alb:<arn>"` or `"alb:name:<name>"`                                           |
| command     | `"aws elbv2 describe-load-balancers"`                                          |
| inputs      | `load_balancer_arn`, `load_balancer_name`, `region` (when provided)            |

---

## ESP Examples

### Validate ALB security configuration

```esp
OBJECT prod_alb
    load_balancer_name `prod-web-alb`
    region `us-east-1`
OBJECT_END

STATE alb_security
    found boolean = true
    scheme string = `internet-facing`
    deletion_protection boolean = true
    drop_invalid_header_fields boolean = true
    desync_mitigation_mode string = `defensive`
    has_https_listener boolean = true
    has_http_to_https_redirect boolean = true
    has_waf_acl boolean = true
    security_group_count int >= 1
STATE_END

CTN aws_alb
    TEST all all AND
    STATE_REF alb_security
    OBJECT_REF prod_alb
CTN_END
```

### Validate ALB logging and monitoring

```esp
OBJECT monitored_alb
    load_balancer_name `app-alb`
OBJECT_END

STATE alb_logging
    found boolean = true
    access_logging_enabled boolean = true
    access_log_s3_bucket string starts `alb-logs-`
    connection_logging_enabled boolean = true
STATE_END

CTN aws_alb
    TEST all all AND
    STATE_REF alb_logging
    OBJECT_REF monitored_alb
CTN_END
```

### Validate TLS policy via record checks

```esp
OBJECT tls_alb
    load_balancer_name `secure-alb`
OBJECT_END

STATE tls_policy
    found boolean = true
    record
        field Listeners.*.Protocol string = `HTTPS` at_least_one
        field Listeners.*.SslPolicy string = `ELBSecurityPolicy-TLS13-1-2-2021-06` at_least_one
    record_end
STATE_END

CTN aws_alb
    TEST all all AND
    STATE_REF tls_policy
    OBJECT_REF tls_alb
CTN_END
```

### Validate target group health checks

```esp
OBJECT health_alb
    load_balancer_name `api-alb`
OBJECT_END

STATE healthy_targets
    found boolean = true
    target_group_count int >= 1
    all_target_groups_https_health_check boolean = true
    record
        field TargetGroups.*.HealthCheckPath string = `/health` at_least_one
    record_end
STATE_END

CTN aws_alb
    TEST all all AND
    STATE_REF healthy_targets
    OBJECT_REF health_alb
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
| WAFv2 access denied                                 | N/A (graceful)               | `has_waf_acl=false` | WAF check failure does not fail the collection    |
| Incompatible CTN type                               | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_alb"`              |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"ALB not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type             | Relationship                                                           |
| -------------------- | ---------------------------------------------------------------------- |
| `aws_nlb`            | Network Load Balancer - same ELBv2 API, different Type filter          |
| `aws_security_group` | ALBs reference security groups; validate SG rules alongside ALB config |
| `aws_vpc`            | ALBs reside in VPCs; validate VPC exists and is configured correctly   |
| `aws_subnet`         | ALBs span subnets in availability zones                                |
| `aws_acm_certificate`| ALB HTTPS listeners reference ACM certificates                        |
