# aws_ssoadmin_permission_set

## Overview

Validates AWS IAM Identity Center (SSO Admin) permission set configuration via four sequential AWS CLI calls. The collector first resolves the permission set ARN by name, then retrieves configuration, managed policy attachments, and inline policy. All responses are merged into a single RecordData object.

**Platform:** AWS (requires `aws` CLI binary with SSO Admin read permissions)
**Collection Method:** Four sequential AWS CLI commands per object via `AwsClient`

**Note:** Both `permission_set_name` and `instance_arn` are required. The SSO Admin API has no lookup-by-name operation — the collector iterates all permission sets to find a matching name.

**Note:** `InlinePolicy` is a JSON-encoded string in the API response, or an empty string when no inline policy exists. The collector parses it into a structured object stored under the `InlinePolicy` key in RecordData.

**Note:** `SessionDuration` is an ISO 8601 duration string: `PT2H` = 2 hours, `PT4H` = 4 hours, `PT8H` = 8 hours.

---

## Object Fields

| Field                 | Type   | Required | Description                                | Example                                          |
| --------------------- | ------ | -------- | ------------------------------------------ | ------------------------------------------------ |
| `permission_set_name` | string | **Yes**  | Permission set name (exact match)          | `ExampleOrgAdmin`                                |
| `instance_arn`        | string | **Yes**  | IAM Identity Center instance ARN           | `arn:aws:sso:::instance/ssoins-722365ac4d8ffe22` |
| `region`              | string | No       | AWS region override (passed as `--region`) | `us-east-1`                                      |

---

## Commands Executed

### Command 1: list-permission-sets + describe loop (ARN resolution)

The SSO Admin API provides no direct lookup by name. The collector calls `list-permission-sets` to get all ARNs, then calls `describe-permission-set` for each until finding one where `Name == permission_set_name`.

```
aws sso-admin list-permission-sets --instance-arn arn:aws:sso:::instance/ssoins-722365ac4d8ffe22 --output json
aws sso-admin describe-permission-set --instance-arn <arn> --permission-set-arn <ps-arn> --output json
# repeated until matching Name found
```

### Command 2: describe-permission-set

```
aws sso-admin describe-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-722365ac4d8ffe22 \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-722365ac4d8ffe22/ps-ca776cd98f98270a \
  --output json
```

**Sample response:**

```json
{
  "PermissionSet": {
    "Name": "ExampleOrgAdmin",
    "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-722365ac4d8ffe22/ps-ca776cd98f98270a",
    "Description": "Full admin access to ExampleOrg infrastructure",
    "CreatedDate": "2026-03-23T19:58:33.692000+00:00",
    "SessionDuration": "PT4H"
  }
}
```

### Command 3: list-managed-policies-in-permission-set

```
aws sso-admin list-managed-policies-in-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-722365ac4d8ffe22 \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-722365ac4d8ffe22/ps-ca776cd98f98270a \
  --output json
```

**Sample responses:**

```json
{ "AttachedManagedPolicies": [{ "Name": "AdministratorAccess", "Arn": "arn:aws:iam::aws:policy/AdministratorAccess" }] }
{ "AttachedManagedPolicies": [] }
```

### Command 4: get-inline-policy-for-permission-set

```
aws sso-admin get-inline-policy-for-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-722365ac4d8ffe22 \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-722365ac4d8ffe22/ps-66d746a2c9f78305 \
  --output json
```

**Sample responses:**

```json
{ "InlinePolicy": "{\"Statement\":[{\"Sid\":\"EC2ReadOnly\",...}],\"Version\":\"2012-10-17\"}" }
{ "InlinePolicy": "" }
```

Empty string = no inline policy. The collector parses the non-empty JSON string and stores the structured object under `InlinePolicy` in RecordData.

---

## Collected Data Fields

### Scalar Fields

| Field                  | Type    | Always Present | Source                                           |
| ---------------------- | ------- | -------------- | ------------------------------------------------ |
| `found`                | boolean | Yes            | Derived — `true` if permission set found by name |
| `permission_set_name`  | string  | When found     | `PermissionSet.Name`                             |
| `permission_set_arn`   | string  | When found     | ARN from list-permission-sets resolution         |
| `description`          | string  | When found     | `PermissionSet.Description`                      |
| `session_duration`     | string  | When found     | `PermissionSet.SessionDuration` (ISO 8601)       |
| `managed_policy_count` | integer | When found     | Derived — `len(AttachedManagedPolicies)`         |
| `has_inline_policy`    | boolean | When found     | Derived — `InlinePolicy` is non-empty string     |

### RecordData Field

| Field      | Type       | Always Present | Description                                                     |
| ---------- | ---------- | -------------- | --------------------------------------------------------------- |
| `resource` | RecordData | Yes            | Merged permission set + managed policies + parsed inline policy |

---

## RecordData Structure

```
PermissionSet.Name                        → "ExampleOrgAdmin"
PermissionSet.PermissionSetArn            → "arn:aws:sso:::permissionSet/..."
PermissionSet.Description                 → "Full admin access to ExampleOrg infrastructure"
PermissionSet.SessionDuration             → "PT4H"
AttachedManagedPolicies.0.Name            → "AdministratorAccess"
AttachedManagedPolicies.0.Arn             → "arn:aws:iam::aws:policy/AdministratorAccess"
AttachedManagedPolicies.*.Name            → (all managed policy names via wildcard)
InlinePolicy.Version                      → "2012-10-17"
InlinePolicy.Statement.0.Sid              → "EC2ReadOnly"
InlinePolicy.Statement.0.Effect           → "Allow"
InlinePolicy.Statement.1.Sid              → "SSMSessionManager"
InlinePolicy.Statement.2.Sid              → "LogsRead"
InlinePolicy.Statement.3.Sid              → "SecretsReadOnly"
```

---

## State Fields

| State Field            | Type       | Allowed Operations              | Maps To Collected Field |
| ---------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`                | boolean    | `=`, `!=`                       | `found`                 |
| `permission_set_name`  | string     | `=`, `!=`                       | `permission_set_name`   |
| `permission_set_arn`   | string     | `=`, `!=`, `contains`, `starts` | `permission_set_arn`    |
| `description`          | string     | `=`, `!=`, `contains`, `starts` | `description`           |
| `session_duration`     | string     | `=`, `!=`                       | `session_duration`      |
| `managed_policy_count` | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `managed_policy_count`  |
| `has_inline_policy`    | boolean    | `=`, `!=`                       | `has_inline_policy`     |
| `record`               | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                                   |
| ---------------------------- | --------------------------------------- |
| Collector ID                 | `aws_ssoadmin_permission_set_collector` |
| Collector Type               | `aws_ssoadmin_permission_set`           |
| Collection Mode              | Content                                 |
| Required Capabilities        | `aws_cli`, `sso_admin_read`             |
| Expected Collection Time     | ~6000ms (ARN resolution + three calls)  |
| Memory Usage                 | ~5MB                                    |
| Network Intensive            | Yes                                     |
| CPU Intensive                | No                                      |
| Requires Elevated Privileges | No                                      |
| Batch Collection             | No                                      |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "sso:ListPermissionSets",
    "sso:DescribePermissionSet",
    "sso:ListManagedPoliciesInPermissionSet",
    "sso:GetInlinePolicyForPermissionSet"
  ],
  "Resource": "*"
}
```

---

## ESP Examples

### Admin permission set: 4-hour session, AdministratorAccess managed policy (KSI-IAM-JIT)

```esp
OBJECT admin_permission_set
    permission_set_name `ExampleOrgAdmin`
    instance_arn `arn:aws:sso:::instance/ssoins-722365ac4d8ffe22`
    region `us-east-1`
OBJECT_END

STATE admin_ps_compliant
    found boolean = true
    session_duration string = `PT4H`
    managed_policy_count int = 1
    has_inline_policy boolean = false
    record
        field AttachedManagedPolicies.0.Name string = `AdministratorAccess`
    record_end
STATE_END

CTN aws_ssoadmin_permission_set
    TEST all all AND
    STATE_REF admin_ps_compliant
    OBJECT_REF admin_permission_set
CTN_END
```

### ReadOnly permission set: 2-hour session for auditors (KSI-IAM-ELP)

```esp
OBJECT readonly_permission_set
    permission_set_name `ExampleOrgReadOnly`
    instance_arn `arn:aws:sso:::instance/ssoins-722365ac4d8ffe22`
    region `us-east-1`
OBJECT_END

STATE readonly_ps_compliant
    found boolean = true
    session_duration string = `PT2H`
    managed_policy_count int = 1
    has_inline_policy boolean = false
    record
        field AttachedManagedPolicies.0.Name string = `ReadOnlyAccess`
    record_end
STATE_END

CTN aws_ssoadmin_permission_set
    TEST all all AND
    STATE_REF readonly_ps_compliant
    OBJECT_REF readonly_permission_set
CTN_END
```

### Developer permission set: inline policy only, no managed policy (KSI-IAM-ELP)

```esp
OBJECT developer_permission_set
    permission_set_name `ExampleOrgDeveloper`
    instance_arn `arn:aws:sso:::instance/ssoins-722365ac4d8ffe22`
    region `us-east-1`
OBJECT_END

STATE developer_ps_compliant
    found boolean = true
    session_duration string = `PT8H`
    managed_policy_count int = 0
    has_inline_policy boolean = true
    record
        field InlinePolicy.Statement.0.Sid string = `EC2ReadOnly`
        field InlinePolicy.Statement.1.Sid string = `SSMSessionManager`
    record_end
STATE_END

CTN aws_ssoadmin_permission_set
    TEST all all AND
    STATE_REF developer_ps_compliant
    OBJECT_REF developer_permission_set
CTN_END
```

---

## Error Conditions

| Condition                       | Error Type                   | Outcome       |
| ------------------------------- | ---------------------------- | ------------- |
| Permission set name not found   | N/A (not an error)           | `found=false` |
| `permission_set_name` missing   | `InvalidObjectConfiguration` | Error         |
| `instance_arn` missing          | `InvalidObjectConfiguration` | Error         |
| IAM access denied               | `CollectionFailed`           | Error         |
| `describe-permission-set` fails | `CollectionFailed`           | Error         |
| `list-managed-policies` fails   | `CollectionFailed`           | Error         |
| `get-inline-policy` fails       | `CollectionFailed`           | Error         |
| Incompatible CTN type           | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                  | Relationship                                                       |
| ------------------------- | ------------------------------------------------------------------ |
| `aws_identitystore_group` | Groups are assigned to permission sets via account assignments     |
| `aws_iam_role`            | Permission sets provision temporary roles when sessions are active |
