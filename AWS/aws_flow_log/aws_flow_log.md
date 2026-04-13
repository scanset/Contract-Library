# aws_flow_log

## Overview

Validates AWS EC2 VPC Flow Log configurations via the AWS CLI. Returns scalar summary fields and the full API response as RecordData for detailed inspection of log format, aggregation intervals, and delivery configuration.

**Platform:** AWS (requires `aws` CLI binary with EC2 read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** The EC2 API returns **PascalCase** field names (e.g., `FlowLogId`, `TrafficType`). Record check field paths must use PascalCase accordingly.

---

## Object Fields

| Field         | Type   | Required | Description                                | Example                      |
| ------------- | ------ | -------- | ------------------------------------------ | ---------------------------- |
| `flow_log_id` | string | No\*     | Flow Log ID for direct lookup              | `fl-0123456789abcdef0`       |
| `resource_id` | string | No\*     | VPC or subnet ID to find flow logs for     | `vpc-0fedcba9876543210`      |
| `tags`        | string | No\*     | Tag filter in `Key=Value` format           | `Name=example-vpc-flow-logs` |
| `region`      | string | No       | AWS region override (passed as `--region`) | `us-east-1`                  |

\* At least one of `flow_log_id`, `resource_id`, or `tags` must be specified. If none are provided, the collector returns `InvalidObjectConfiguration`.

- `flow_log_id` uses `--flow-log-ids` for direct lookup.
- `resource_id` is added as a `--filter Name=resource-id,Values=<value>` argument.
- `tags` is parsed via `parse_tag_filter()` (splits on first `=`) and added as `--filter Name=tag:<Key>,Values=<Value>`.
- Multiple lookup fields can be combined — all are passed in the same command.
- If multiple flow logs match, a warning is logged and the **first result** is used.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

### Command: describe-flow-logs

Retrieves flow log configurations matching the specified filters.

**Collector call:** `client.execute("ec2", "describe-flow-logs", &args)` where `args` is built dynamically from object fields.

**Argument assembly:**

The collector builds an argument list from the object fields in this order:

1. If `flow_log_id` is present: `--flow-log-ids <flow_log_id>`
2. If `resource_id` is present: `--filter Name=resource-id,Values=<resource_id>`
3. If `tags` is present and parseable: `--filter Name=tag:<Key>,Values=<Value>`

**Resulting commands (examples):**

```
# By flow log ID
aws ec2 describe-flow-logs --flow-log-ids fl-0123456789abcdef0 --output json

# By resource ID (VPC)
aws ec2 describe-flow-logs --filter Name=resource-id,Values=vpc-0fedcba9876543210 --output json

# By tag
aws ec2 describe-flow-logs --filter Name=tag:Name,Values=example-vpc-flow-logs --output json

# By resource ID with region
aws ec2 describe-flow-logs --region us-east-1 --output json --filter Name=resource-id,Values=vpc-0fedcba9876543210

# Combined: flow log ID + resource filter
aws ec2 describe-flow-logs --flow-log-ids fl-0123456789abcdef0 --filter Name=resource-id,Values=vpc-0fedcba9876543210 --output json
```

**Response parsing:**

1. Extract `response["FlowLogs"]` as a JSON array (defaults to empty `[]` if key is missing)
2. If the array is empty, set `found = false`
3. If non-empty, use `flow_logs[0]` (the first element via direct indexing)
4. If multiple results exist, log a warning and use the first

**Sample response:**

```json
{
  "FlowLogs": [
    {
      "FlowLogId": "fl-0123456789abcdef0",
      "FlowLogStatus": "ACTIVE",
      "ResourceId": "vpc-0fedcba9876543210",
      "TrafficType": "ALL",
      "LogDestinationType": "cloud-watch-logs",
      "LogDestination": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/example-flow-logs",
      "LogGroupName": "/aws/vpc/example-flow-logs",
      "DeliverLogsStatus": "SUCCESS",
      "DeliverLogsPermissionArn": "arn:aws:iam::123456789012:role/example-flow-logs-role",
      "MaxAggregationInterval": 600,
      "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
      "CreationTime": "2026-02-23T19:47:12.301000+00:00",
      "Tags": [{ "Key": "Name", "Value": "example-vpc-flow-logs" }]
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

Unlike the ECR and EKS collectors, this collector does **not** have special not-found handling — all API errors are mapped to `CollectionError::CollectionFailed`. An empty `FlowLogs` array is the normal not-found case.

---

## Collected Data Fields

### Scalar Fields

| Field                  | Type    | Always Present | Source                                                |
| ---------------------- | ------- | -------------- | ----------------------------------------------------- |
| `found`                | boolean | Yes            | Derived — `true` if at least one flow log matched     |
| `flow_log_id`          | string  | When found     | `FlowLogId` (string)                                  |
| `flow_log_status`      | string  | When found     | `FlowLogStatus` (string)                              |
| `resource_id`          | string  | When found     | `ResourceId` (string)                                 |
| `traffic_type`         | string  | When found     | `TrafficType` (string)                                |
| `log_destination_type` | string  | When found     | `LogDestinationType` (string)                         |
| `log_destination`      | string  | When found     | `LogDestination` (string)                             |
| `log_group_name`       | string  | When found     | `LogGroupName` (string)                               |
| `deliver_logs_status`  | string  | When found     | `DeliverLogsStatus` (string)                          |
| `tag_name`             | string  | When found     | `Tags` array — value of the tag where `Key == "Name"` |

Each field is only added if the corresponding JSON key exists and has the expected type. The `tag_name` field is extracted by iterating the `Tags` array and finding the entry with `Key == "Name"`.

### RecordData Field

| Field      | Type       | Always Present | Description                                                               |
| ---------- | ---------- | -------------- | ------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full flow log object from `describe-flow-logs`. Empty `{}` when not found |

---

## RecordData Structure

The `resource` field contains the complete flow log object as returned by the EC2 API:

```rust
let record_data = RecordData::from_json_value(fl.clone());
```

| Path                       | Type    | Example Value                                                                |
| -------------------------- | ------- | ---------------------------------------------------------------------------- |
| `FlowLogId`                | string  | `"fl-0123456789abcdef0"`                                                     |
| `FlowLogStatus`            | string  | `"ACTIVE"`                                                                   |
| `ResourceId`               | string  | `"vpc-0fedcba9876543210"`                                                    |
| `TrafficType`              | string  | `"ALL"`                                                                      |
| `LogDestinationType`       | string  | `"cloud-watch-logs"`                                                         |
| `LogDestination`           | string  | `"arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/example-flow-logs"` |
| `LogGroupName`             | string  | `"/aws/vpc/example-flow-logs"`                                               |
| `DeliverLogsStatus`        | string  | `"SUCCESS"`                                                                  |
| `DeliverLogsPermissionArn` | string  | `"arn:aws:iam::123456789012:role/example-flow-logs-role"`                    |
| `MaxAggregationInterval`   | integer | `600`                                                                        |
| `LogFormat`                | string  | `"${version} ${account-id} ${interface-id} ..."`                             |
| `CreationTime`             | string  | `"2026-02-23T19:47:12.301000+00:00"`                                         |
| `Tags.0.Key`               | string  | `"Name"`                                                                     |
| `Tags.0.Value`             | string  | `"example-vpc-flow-logs"`                                                    |

---

## State Fields

### Scalar State Fields

| State Field            | Type    | Allowed Operations              | Maps To Collected Field |
| ---------------------- | ------- | ------------------------------- | ----------------------- |
| `found`                | boolean | `=`, `!=`                       | `found`                 |
| `flow_log_id`          | string  | `=`, `!=`, `starts`             | `flow_log_id`           |
| `flow_log_status`      | string  | `=`, `!=`                       | `flow_log_status`       |
| `resource_id`          | string  | `=`, `!=`                       | `resource_id`           |
| `traffic_type`         | string  | `=`, `!=`                       | `traffic_type`          |
| `log_destination_type` | string  | `=`, `!=`                       | `log_destination_type`  |
| `log_destination`      | string  | `=`, `!=`, `contains`, `starts` | `log_destination`       |
| `log_group_name`       | string  | `=`, `!=`, `contains`, `starts` | `log_group_name`        |
| `deliver_logs_status`  | string  | `=`, `!=`                       | `deliver_logs_status`   |
| `tag_name`             | string  | `=`, `!=`, `contains`           | `tag_name`              |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the RecordData.

| State Field | Maps To Collected Field | Description                          |
| ----------- | ----------------------- | ------------------------------------ |
| `record`    | `resource`              | Deep inspection of full API response |

Record check field paths use **PascalCase** as documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                    |
| ---------------------------- | ------------------------ |
| Collector ID                 | `aws_flow_log_collector` |
| Collector Type               | `aws_flow_log`           |
| Collection Mode              | Content                  |
| Required Capabilities        | `aws_cli`, `ec2_read`    |
| Expected Collection Time     | ~2000ms                  |
| Memory Usage                 | ~5MB                     |
| Network Intensive            | Yes                      |
| CPU Intensive                | No                       |
| Requires Elevated Privileges | No                       |
| Batch Collection             | No                       |

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
  "Action": ["ec2:DescribeFlowLogs"],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                     |
| ----------- | ------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                 |
| description | `"Query VPC Flow Log configuration via AWS EC2 API"`                      |
| target      | `"fl:<flow_log_id>"`, `"fl:resource:<resource_id>"`, or `"fl:tag:<tags>"` |
| command     | `"aws ec2 describe-flow-logs"`                                            |
| inputs      | `flow_log_id`, `resource_id`, `tags`, `region` (when provided)            |

---

## ESP Examples

### Validate VPC has active flow log capturing all traffic

```esp
OBJECT vpc_flow_log
    resource_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE flow_log_compliant
    found boolean = true
    flow_log_status string = `ACTIVE`
    traffic_type string = `ALL`
    deliver_logs_status string = `SUCCESS`
    log_destination_type string = `cloud-watch-logs`
STATE_END

CTN aws_flow_log
    TEST all all AND
    STATE_REF flow_log_compliant
    OBJECT_REF vpc_flow_log
CTN_END
```

### Validate flow log delivers to correct log group

```esp
OBJECT vpc_flow_log
    resource_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE correct_destination
    found boolean = true
    log_group_name string = `/aws/vpc/example-flow-logs`
    log_destination string contains `example-flow-logs`
STATE_END

CTN aws_flow_log
    TEST all all AND
    STATE_REF correct_destination
    OBJECT_REF vpc_flow_log
CTN_END
```

### Look up flow log by tag

```esp
OBJECT vpc_flow_log
    tags `Name=example-vpc-flow-logs`
    region `us-east-1`
OBJECT_END

STATE flow_log_active
    found boolean = true
    flow_log_status string = `ACTIVE`
    traffic_type string = `ALL`
STATE_END

CTN aws_flow_log
    TEST all all AND
    STATE_REF flow_log_active
    OBJECT_REF vpc_flow_log
CTN_END
```

### Record checks for log format and aggregation interval

```esp
OBJECT vpc_flow_log
    resource_id `vpc-0fedcba9876543210`
    region `us-east-1`
OBJECT_END

STATE flow_log_details
    found boolean = true
    flow_log_status string = `ACTIVE`
    record
        field MaxAggregationInterval int <= 600
        field LogFormat string contains `${srcaddr}`
        field LogFormat string contains `${dstaddr}`
        field LogFormat string contains `${action}`
    record_end
STATE_END

CTN aws_flow_log
    TEST all all AND
    STATE_REF flow_log_details
    OBJECT_REF vpc_flow_log
CTN_END
```

---

## Error Conditions

| Condition                  | Error Type                   | Outcome       | Notes                                                       |
| -------------------------- | ---------------------------- | ------------- | ----------------------------------------------------------- |
| No flow logs match query   | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent          |
| No lookup fields specified | `InvalidObjectConfiguration` | Error         | At least one of `flow_log_id`, `resource_id`, `tags` needed |
| `aws` CLI binary not found | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                        |
| Invalid AWS credentials    | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error             |
| IAM access denied          | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess`       |
| JSON parse failure         | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                      |
| Incompatible CTN type      | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_flow_log"`            |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"Flow log not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type                   | Relationship                                               |
| -------------------------- | ---------------------------------------------------------- |
| `aws_vpc`                  | Flow logs monitor VPC network traffic                      |
| `aws_cloudwatch_log_group` | Flow log destination (when using cloud-watch-logs)         |
| `aws_cloudtrail`           | CloudTrail covers API audit; flow logs cover network audit |
