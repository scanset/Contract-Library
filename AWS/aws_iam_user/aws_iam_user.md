# aws_iam_user

## Overview

Validates AWS IAM user configuration via three sequential AWS CLI calls: `get-user` for user metadata and tags, `list-user-policies` for inline policy names, and `list-attached-user-policies` for managed policy attachments. All three responses are merged into a single RecordData object, mirroring the `aws_iam_role` pattern.

**Platform:** AWS (requires `aws` CLI binary with IAM read permissions)
**Collection Method:** Three sequential AWS CLI commands per object via `AwsClient`

**Note:** IAM is a global service. The `region` field affects CLI profile selection only, not the API endpoint.

**Note:** Commands 2 and 3 are skipped if Command 1 returns `NoSuchEntity`. Tags are flattened from `[{Key, Value}]` to `tag_key:<Key>` scalar fields.

---

## Object Fields

| Field       | Type   | Required | Description                                                   | Example                          |
| ----------- | ------ | -------- | ------------------------------------------------------------- | -------------------------------- |
| `user_name` | string | **Yes**  | IAM user name (exact match, not ARN)                          | `example-org-esp-scanner` |
| `region`    | string | No       | AWS region override (IAM is global; affects CLI profile only) | `us-east-1`                      |

---

## Commands Executed

### Command 1: get-user

```
aws iam get-user --user-name example-org-esp-scanner --output json
```

**Sample response (abbreviated):**

```json
{
  "User": {
    "Path": "/esp/",
    "UserName": "example-org-esp-scanner",
    "UserId": "AIDAXCKLYU6GDIZA6BTVK",
    "Arn": "arn:aws:iam::123456789012:user/esp/example-org-esp-scanner",
    "CreateDate": "2026-03-27T23:45:41+00:00",
    "Tags": [
      { "Key": "Purpose", "Value": "ESP AWS daemon dev container identity" },
      { "Key": "ManagedBy", "Value": "terraform" }
    ]
  }
}
```

### Command 2: list-user-policies (inline)

```
aws iam list-user-policies --user-name example-org-esp-scanner --output json
```

**Sample response:**

```json
{
  "PolicyNames": ["example-org-esp-scanner-policy"]
}
```

Stored in RecordData as `InlinePolicyNames`.

### Command 3: list-attached-user-policies (managed)

```
aws iam list-attached-user-policies --user-name example-org-esp-scanner --output json
```

**Sample response:**

```json
{
  "AttachedPolicies": []
}
```

Stored in RecordData as `AttachedPolicies`.

---

## RecordData Merge Logic

```rust
let mut merged = user.clone();                    // full User object from get-user
merged["InlinePolicyNames"] = policy_names;       // from list-user-policies PolicyNames
merged["AttachedPolicies"] = attached_policies;   // from list-attached-user-policies
```

---

## Collected Data Fields

### Scalar Fields

| Field                   | Type    | Always Present | Source                            |
| ----------------------- | ------- | -------------- | --------------------------------- |
| `found`                 | boolean | Yes            | Derived — `true` if user found    |
| `user_name`             | string  | When found     | `User.UserName`                   |
| `user_arn`              | string  | When found     | `User.Arn`                        |
| `path`                  | string  | When found     | `User.Path`                       |
| `attached_policy_count` | integer | When found     | Derived — `len(AttachedPolicies)` |
| `inline_policy_count`   | integer | When found     | Derived — `len(PolicyNames)`      |
| `tag_key:<Key>`         | string  | When found     | One scalar per tag                |

### RecordData Field

| Field      | Type       | Always Present | Description                                                                   |
| ---------- | ---------- | -------------- | ----------------------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged user + InlinePolicyNames + AttachedPolicies. Empty `{}` when not found |

---

## RecordData Structure

| Path                            | Type   | Example Value                                                         |
| ------------------------------- | ------ | --------------------------------------------------------------------- |
| `UserName`                      | string | `"example-org-esp-scanner"`                                    |
| `Arn`                           | string | `"arn:aws:iam::123456789012:user/esp/example-org-esp-scanner"` |
| `Path`                          | string | `"/esp/"`                                                             |
| `UserId`                        | string | `"AIDAXCKLYU6GDIZA6BTVK"`                                             |
| `Tags.0.Key`                    | string | `"Purpose"`                                                           |
| `Tags.0.Value`                  | string | `"ESP AWS daemon dev container identity"`                             |
| `Tags.*.Key`                    | string | (all tag keys via wildcard)                                           |
| `Tags.*.Value`                  | string | (all tag values via wildcard)                                         |
| `InlinePolicyNames.0`           | string | `"example-org-esp-scanner-policy"`                             |
| `InlinePolicyNames.*`           | string | (all inline policy names via wildcard)                                |
| `AttachedPolicies.0.PolicyName` | string | (managed policy name if any)                                          |
| `AttachedPolicies.0.PolicyArn`  | string | (managed policy ARN if any)                                           |
| `AttachedPolicies.*.PolicyName` | string | (all managed policy names via wildcard)                               |

---

## State Fields

| State Field             | Type       | Allowed Operations              | Maps To Collected Field   |
| ----------------------- | ---------- | ------------------------------- | ------------------------- |
| `found`                 | boolean    | `=`, `!=`                       | `found`                   |
| `user_name`             | string     | `=`, `!=`                       | `user_name`               |
| `user_arn`              | string     | `=`, `!=`, `contains`, `starts` | `user_arn`                |
| `path`                  | string     | `=`, `!=`                       | `path`                    |
| `attached_policy_count` | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `attached_policy_count`   |
| `inline_policy_count`   | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `inline_policy_count`     |
| `tag_key:<Key>`         | string     | `=`, `!=`, `contains`           | `tag_key:<Key>` (dynamic) |
| `record`                | RecordData | (record checks)                 | `resource`                |

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `aws_iam_user_collector`             |
| Collector Type               | `aws_iam_user`                       |
| Collection Mode              | Content                              |
| Required Capabilities        | `aws_cli`, `iam_read`                |
| Expected Collection Time     | ~4000ms (three sequential API calls) |
| Memory Usage                 | ~5MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetUser",
    "iam:ListUserPolicies",
    "iam:ListAttachedUserPolicies"
  ],
  "Resource": "*"
}
```

---

## ESP Examples

### ESP daemon user scoped to /esp/ path with inline policy only (KSI-IAM-ELP)

```esp
OBJECT esp_daemon_user
    user_name `example-org-esp-scanner`
    region `us-east-1`
OBJECT_END

STATE esp_user_compliant
    found boolean = true
    path string = `/esp/`
    attached_policy_count int = 0
    inline_policy_count int = 1
    tag_key:ManagedBy string = `terraform`
STATE_END

CTN aws_iam_user
    TEST all all AND
    STATE_REF esp_user_compliant
    OBJECT_REF esp_daemon_user
CTN_END
```

### Record check for inline policy name

```esp
STATE esp_user_policy_named
    found boolean = true
    record
        field InlinePolicyNames.0 string = `example-org-esp-scanner-policy`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                           | Error Type                   | Outcome       |
| ----------------------------------- | ---------------------------- | ------------- |
| User not found (`NoSuchEntity`)     | N/A (not an error)           | `found=false` |
| `user_name` missing from object     | `InvalidObjectConfiguration` | Error         |
| IAM access denied                   | `CollectionFailed`           | Error         |
| `list-user-policies` fails          | `CollectionFailed`           | Error         |
| `list-attached-user-policies` fails | `CollectionFailed`           | Error         |
| Incompatible CTN type               | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                    | Relationship                                              |
| --------------------------- | --------------------------------------------------------- |
| `aws_iam_role`              | Roles are preferred over users for service identities     |
| `aws_secretsmanager_secret` | User access keys stored in Secrets Manager as credentials |
