# aws_iam_role

## Overview

Validates AWS IAM Role configurations via the AWS CLI. Collects from three sequential API calls: `get-role` (configuration and trust policy), `list-attached-role-policies` (managed policies), and `list-role-policies` (inline policies). Results are merged into scalar fields and a single RecordData object for deep inspection of trust policies and policy attachments.

**Platform:** AWS (requires `aws` CLI binary with IAM read permissions)
**Collection Method:** Three sequential AWS CLI commands per object via `AwsClient`

**Note:** IAM is a global service. The `region` field mainly affects CLI profile selection, not the API endpoint.

---

## Object Fields

| Field       | Type   | Required | Description                                | Example             |
| ----------- | ------ | -------- | ------------------------------------------ | ------------------- |
| `role_name` | string | **Yes**  | IAM role name (exact match, not ARN)       | `example-node-role` |
| `region`    | string | No       | AWS region override (passed as `--region`) | `us-east-1`         |

- `role_name` is **required**. If missing, the collector returns `InvalidObjectConfiguration`.
- If `region` is omitted, the AWS CLI's default region resolution applies.

---

## Commands Executed

All commands are built by `AwsClient::execute(service, operation, args)`, which constructs a process via `Command::new("aws")` with arguments appended in this order:

```
aws <service> <operation> [--region <region>] --output json [additional args...]
```

Commands 2 and 3 are **only called if Command 1 finds the role**. If Command 1 returns `NoSuchEntity`, the collector sets `found = false` and skips the remaining calls.

### Command 1: get-role

Retrieves role configuration, trust policy, metadata, and tags.

**Collector call:** `client.execute("iam", "get-role", &["--role-name", role_name])`

**Resulting command:**

```
aws iam get-role --role-name example-node-role --output json
aws iam get-role --role-name example-node-role --region us-east-1 --output json    # with region
```

**Response parsing:**

1. Extract `response["Role"]` as a JSON object
2. If the API returns a `NoSuchEntity` error (detected in the error string), set `found = false` and skip Commands 2 and 3
3. Any other API error is returned as `CollectionError::CollectionFailed`

**Scalar field extraction:**

| Collected Field        | JSON Path                 | Extraction  |
| ---------------------- | ------------------------- | ----------- |
| `role_name`            | `Role.RoleName`           | `.as_str()` |
| `role_arn`             | `Role.Arn`                | `.as_str()` |
| `path`                 | `Role.Path`               | `.as_str()` |
| `max_session_duration` | `Role.MaxSessionDuration` | `.as_i64()` |

**Sample response (abbreviated):**

```json
{
  "Role": {
    "RoleName": "example-node-role",
    "RoleId": "AROAXCKLYU6GKQOMNQZ3N",
    "Arn": "arn:aws:iam::123456789012:role/example-node-role",
    "Path": "/",
    "MaxSessionDuration": 3600,
    "CreateDate": "2026-02-21T06:23:14+00:00",
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": { "Service": "ec2.amazonaws.com" },
          "Action": "sts:AssumeRole"
        }
      ]
    },
    "Tags": [{ "Key": "Project", "Value": "scanset" }],
    "RoleLastUsed": {
      "LastUsedDate": "2026-02-23T20:12:38+00:00",
      "Region": "us-east-1"
    }
  }
}
```

### Command 2: list-attached-role-policies

Retrieves managed (AWS-managed or customer-managed) policies attached to the role.

**Collector call:** `client.execute("iam", "list-attached-role-policies", &["--role-name", role_name])`

**Resulting command:**

```
aws iam list-attached-role-policies --role-name example-node-role --output json
```

**Response parsing:**

1. Extract `response["AttachedPolicies"]` as a JSON array (defaults to `[]`)
2. Count the array length → stored as `attached_policy_count` scalar
3. The entire `AttachedPolicies` array is inserted into the merged RecordData

**Sample response:**

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "AmazonEKS_CNI_Policy",
      "PolicyArn": "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
    },
    {
      "PolicyName": "AmazonEC2ContainerRegistryReadOnly",
      "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    },
    {
      "PolicyName": "AmazonEKSWorkerNodePolicy",
      "PolicyArn": "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
    }
  ]
}
```

### Command 3: list-role-policies

Retrieves inline policy names for the role.

**Collector call:** `client.execute("iam", "list-role-policies", &["--role-name", role_name])`

**Resulting command:**

```
aws iam list-role-policies --role-name example-node-role --output json
```

**Response parsing:**

1. Extract `response["PolicyNames"]` as a JSON array (defaults to `[]`)
2. Count the array length → stored as `inline_policy_count` scalar
3. The array is inserted into the merged RecordData as `InlinePolicyNames`

**Sample response:**

```json
{
  "PolicyNames": []
}
```

### RecordData Merge Logic

The collector merges all three responses into a single RecordData object:

```rust
let mut merged = role.clone();                              // full get-role Role object
merged["AttachedPolicies"] = attached_policies;             // from list-attached-role-policies
merged["InlinePolicyNames"] = inline_policy_names;          // PolicyNames renamed to InlinePolicyNames
let record_data = RecordData::from_json_value(merged);
```

Note: The `PolicyNames` array from `list-role-policies` is stored under the key `InlinePolicyNames` in the RecordData, not under its original API key name.

### Error Detection

`AwsClient::execute` checks the command exit code. On non-zero exit, stderr is inspected for specific patterns:

| Stderr contains                              | Error variant                |
| -------------------------------------------- | ---------------------------- |
| `AccessDenied` or `UnauthorizedAccess`       | `AwsError::AccessDenied`     |
| `InvalidParameterValue` or `ValidationError` | `AwsError::InvalidParameter` |
| `does not exist` or `not found`              | `AwsError::ResourceNotFound` |
| Anything else                                | `AwsError::CommandFailed`    |

The collector additionally checks for `NoSuchEntity` in the Command 1 error string to handle the role-not-found case gracefully. Commands 2 and 3 errors are mapped directly to `CollectionError::CollectionFailed` with a message indicating which API call failed.

---

## Collected Data Fields

### Scalar Fields

| Field                   | Type    | Always Present | Source                                       |
| ----------------------- | ------- | -------------- | -------------------------------------------- |
| `found`                 | boolean | Yes            | Derived — `true` if role was found           |
| `role_name`             | string  | When found     | get-role → `RoleName` (string)               |
| `role_arn`              | string  | When found     | get-role → `Arn` (string)                    |
| `path`                  | string  | When found     | get-role → `Path` (string)                   |
| `max_session_duration`  | int     | When found     | get-role → `MaxSessionDuration` (i64)        |
| `attached_policy_count` | int     | When found     | Derived — length of `AttachedPolicies` array |
| `inline_policy_count`   | int     | When found     | Derived — length of `PolicyNames` array      |

Each field is only added if the corresponding JSON key exists and has the expected type. The count fields are always present when the role is found (they default to 0 if the arrays are empty).

### RecordData Field

| Field      | Type       | Always Present | Description                                                                              |
| ---------- | ---------- | -------------- | ---------------------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged role config + `AttachedPolicies` + `InlinePolicyNames`. Empty `{}` when not found |

---

## RecordData Structure

### Role configuration paths (from get-role)

| Path                 | Type    | Example Value                                        |
| -------------------- | ------- | ---------------------------------------------------- |
| `RoleName`           | string  | `"example-node-role"`                                |
| `RoleId`             | string  | `"AROAXCKLYU6GKQOMNQZ3N"`                            |
| `Arn`                | string  | `"arn:aws:iam::123456789012:role/example-node-role"` |
| `Path`               | string  | `"/"`                                                |
| `MaxSessionDuration` | integer | `3600`                                               |
| `CreateDate`         | string  | `"2026-02-21T06:23:14+00:00"`                        |

### Trust policy paths (from get-role → `AssumeRolePolicyDocument`)

| Path                                                     | Type   | Example Value         |
| -------------------------------------------------------- | ------ | --------------------- |
| `AssumeRolePolicyDocument.Version`                       | string | `"2012-10-17"`        |
| `AssumeRolePolicyDocument.Statement.0.Effect`            | string | `"Allow"`             |
| `AssumeRolePolicyDocument.Statement.0.Principal.Service` | string | `"ec2.amazonaws.com"` |
| `AssumeRolePolicyDocument.Statement.0.Action`            | string | `"sts:AssumeRole"`    |

### Managed policy paths (from list-attached-role-policies, merged as `AttachedPolicies`)

| Path                            | Type   | Example Value                                    |
| ------------------------------- | ------ | ------------------------------------------------ |
| `AttachedPolicies.0.PolicyName` | string | `"AmazonEKS_CNI_Policy"`                         |
| `AttachedPolicies.0.PolicyArn`  | string | `"arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"` |
| `AttachedPolicies.*.PolicyName` | string | (all managed policy names via wildcard)          |
| `AttachedPolicies.*.PolicyArn`  | string | (all managed policy ARNs via wildcard)           |

### Inline policy paths (from list-role-policies, merged as `InlinePolicyNames`)

| Path                  | Type   | Example Value              |
| --------------------- | ------ | -------------------------- |
| `InlinePolicyNames`   | array  | `[]` (empty if none)       |
| `InlinePolicyNames.0` | string | (first inline policy name) |

### Tags and last used

| Path                        | Type   | Example Value                 |
| --------------------------- | ------ | ----------------------------- |
| `Tags.0.Key`                | string | `"Project"`                   |
| `Tags.0.Value`              | string | `"scanset"`                   |
| `Tags.*.Key`                | string | (all tag keys via wildcard)   |
| `RoleLastUsed.LastUsedDate` | string | `"2026-02-23T20:12:38+00:00"` |
| `RoleLastUsed.Region`       | string | `"us-east-1"`                 |

---

## State Fields

### Scalar State Fields

| State Field             | Type    | Allowed Operations              | Maps To Collected Field |
| ----------------------- | ------- | ------------------------------- | ----------------------- |
| `found`                 | boolean | `=`, `!=`                       | `found`                 |
| `role_name`             | string  | `=`, `!=`, `contains`, `starts` | `role_name`             |
| `role_arn`              | string  | `=`, `!=`, `contains`, `starts` | `role_arn`              |
| `path`                  | string  | `=`, `!=`                       | `path`                  |
| `max_session_duration`  | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `max_session_duration`  |
| `attached_policy_count` | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `attached_policy_count` |
| `inline_policy_count`   | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `inline_policy_count`   |

### Record Checks

The state field name `record` maps to the collected data field `resource`. Use ESP `record ... record_end` blocks to validate paths within the merged RecordData.

| State Field | Maps To Collected Field | Description                                          |
| ----------- | ----------------------- | ---------------------------------------------------- |
| `record`    | `resource`              | Deep inspection of trust policy + policy attachments |

Record check field paths use the structure documented in [RecordData Structure](#recorddata-structure) above.

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `aws_iam_role_collector`             |
| Collector Type               | `aws_iam_role`                       |
| Collection Mode              | Content                              |
| Required Capabilities        | `aws_cli`, `iam_read`                |
| Expected Collection Time     | ~4000ms (three sequential API calls) |
| Memory Usage                 | ~5MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |

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
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies"
  ],
  "Resource": "*"
}
```

### Collection Method Traceability

| Field       | Value                                                                                                      |
| ----------- | ---------------------------------------------------------------------------------------------------------- |
| method_type | `ApiCall`                                                                                                  |
| description | `"Query IAM role configuration via AWS CLI (get-role + list-attached-role-policies + list-role-policies)"` |
| target      | `"iam-role:<role_name>"`                                                                                   |
| command     | `"aws iam get-role"`                                                                                       |
| inputs      | `role_name` (always), `region` (when provided)                                                             |

---

## ESP Examples

### Validate EKS node role has correct policies

```esp
OBJECT node_role
    role_name `example-node-role`
OBJECT_END

STATE node_role_valid
    found boolean = true
    attached_policy_count int = 3
    inline_policy_count int = 0
    record
        field AssumeRolePolicyDocument.Statement.0.Principal.Service string = `ec2.amazonaws.com`
        field AttachedPolicies.*.PolicyName string = `AmazonEKSWorkerNodePolicy` at_least_one
        field AttachedPolicies.*.PolicyName string = `AmazonEKS_CNI_Policy` at_least_one
        field AttachedPolicies.*.PolicyName string = `AmazonEC2ContainerRegistryReadOnly` at_least_one
    record_end
STATE_END

CTN aws_iam_role
    TEST all all AND
    STATE_REF node_role_valid
    OBJECT_REF node_role
CTN_END
```

### Validate flow logs role trust policy

```esp
OBJECT flow_logs_role
    role_name `example-flow-logs-role`
OBJECT_END

STATE flow_role_valid
    found boolean = true
    record
        field AssumeRolePolicyDocument.Statement.0.Principal.Service string = `vpc-flow-logs.amazonaws.com`
        field AssumeRolePolicyDocument.Statement.0.Effect string = `Allow`
        field AssumeRolePolicyDocument.Statement.0.Action string = `sts:AssumeRole`
    record_end
STATE_END

CTN aws_iam_role
    TEST all all AND
    STATE_REF flow_role_valid
    OBJECT_REF flow_logs_role
CTN_END
```

### Validate no inline policies and session limits

```esp
OBJECT any_role
    role_name `example-node-role`
OBJECT_END

STATE no_inline
    found boolean = true
    inline_policy_count int = 0
    max_session_duration int <= 3600
STATE_END

CTN aws_iam_role
    TEST all all AND
    STATE_REF no_inline
    OBJECT_REF any_role
CTN_END
```

### Validate EKS cluster role trust

```esp
OBJECT cluster_role
    role_name `example-cluster-role`
OBJECT_END

STATE cluster_trust_valid
    found boolean = true
    record
        field AssumeRolePolicyDocument.Statement.0.Principal.Service string = `eks.amazonaws.com`
    record_end
STATE_END

CTN aws_iam_role
    TEST all all AND
    STATE_REF cluster_trust_valid
    OBJECT_REF cluster_role
CTN_END
```

---

## Error Conditions

| Condition                           | Error Type                   | Outcome       | Notes                                                 |
| ----------------------------------- | ---------------------------- | ------------- | ----------------------------------------------------- |
| Role not found (`NoSuchEntity`)     | N/A (not an error)           | `found=false` | `resource` set to empty `{}`, scalar fields absent    |
| `role_name` missing from object     | `InvalidObjectConfiguration` | Error         | Required field — collector returns immediately        |
| `aws` CLI binary not found          | `CollectionFailed`           | Error         | `Command::new("aws")` fails to spawn                  |
| Invalid AWS credentials             | `CollectionFailed`           | Error         | CLI returns non-zero exit with credential error       |
| IAM access denied                   | `CollectionFailed`           | Error         | stderr matched `AccessDenied` or `UnauthorizedAccess` |
| `list-attached-role-policies` fails | `CollectionFailed`           | Error         | Second API call fails after role was found            |
| `list-role-policies` fails          | `CollectionFailed`           | Error         | Third API call fails after role was found             |
| JSON parse failure                  | `CollectionFailed`           | Error         | `serde_json::from_str` fails on stdout                |
| Incompatible CTN type               | `CtnContractValidation`      | Error         | Collector validates `ctn_type == "aws_iam_role"`      |

### Executor Validation

The executor requires the `found` field to be present in collected data. If missing, validation fails with `MissingDataField`.

When `found` is `false`:

- Scalar field checks against missing fields will **fail** (field not collected)
- Record checks will **fail** with message `"IAM role not found, cannot validate record checks"`

---

## Related CTN Types

| CTN Type          | Relationship                                            |
| ----------------- | ------------------------------------------------------- |
| `aws_flow_log`    | Flow log role trust: `vpc-flow-logs.amazonaws.com`      |
| `aws_cloudtrail`  | CloudTrail may have delivery role                       |
| `aws_eks_cluster` | Cluster role + node role + IRSA roles                   |
| `k8s_resource`    | Service accounts link to IAM roles via IRSA annotations |
