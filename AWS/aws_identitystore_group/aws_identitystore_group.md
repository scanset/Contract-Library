# aws_identitystore_group

## Overview

Validates AWS IAM Identity Center identity store group configuration via a single AWS CLI call using `list-groups`. The Identity Store API has no lookup-by-name operation — the collector iterates all groups and matches on `DisplayName`. Both `group_name` and `identity_store_id` are required.

**Platform:** AWS (requires `aws` CLI binary with Identity Store read permissions)
**Collection Method:** Single AWS CLI command per object via `AwsClient`

**Note:** Identity store groups have no tags. The full group object is returned by `list-groups` — no separate describe call is needed.

---

## Object Fields

| Field               | Type   | Required | Description                                            | Example            |
| ------------------- | ------ | -------- | ------------------------------------------------------ | ------------------ |
| `group_name`        | string | **Yes**  | Group display name (exact match against `DisplayName`) | `ProofLayerAdmins` |
| `identity_store_id` | string | **Yes**  | Identity store ID for the IAM Identity Center instance | `d-906607b0fb`     |
| `region`            | string | No       | AWS region override (passed as `--region`)             | `us-east-1`        |

---

## Commands Executed

### Command 1: list-groups

```
aws identitystore list-groups --identity-store-id d-906607b0fb --output json
```

The collector finds the first group where `DisplayName == group_name` exactly.

**Sample response (abbreviated):**

```json
{
  "Groups": [
    {
      "GroupId": "5428f418-1091-70f7-0b97-ead5a09be747",
      "DisplayName": "ProofLayerAdmins",
      "Description": "Maps to Entra group aws-prooflayer-demo-admins",
      "CreatedAt": "2026-03-23T19:58:33.760000+00:00",
      "UpdatedAt": "2026-03-23T19:58:33.760000+00:00",
      "IdentityStoreId": "d-906607b0fb"
    }
  ]
}
```

---

## Collected Data Fields

### Scalar Fields

| Field               | Type    | Always Present | Source                                                    |
| ------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`             | boolean | Yes            | Derived — `true` if group with matching DisplayName found |
| `group_id`          | string  | When found     | `GroupId`                                                 |
| `display_name`      | string  | When found     | `DisplayName`                                             |
| `description`       | string  | When found     | `Description`                                             |
| `identity_store_id` | string  | When found     | `IdentityStoreId`                                         |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full group object. Empty `{}` when not found |

---

## RecordData Structure

```
GroupId          → "5428f418-1091-70f7-0b97-ead5a09be747"
DisplayName      → "ProofLayerAdmins"
Description      → "Maps to Entra group aws-prooflayer-demo-admins"
IdentityStoreId  → "d-906607b0fb"
CreatedAt        → "2026-03-23T19:58:33.760000+00:00"
UpdatedAt        → "2026-03-23T19:58:33.760000+00:00"
```

---

## State Fields

| State Field         | Type       | Allowed Operations              | Maps To Collected Field |
| ------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`             | boolean    | `=`, `!=`                       | `found`                 |
| `group_id`          | string     | `=`, `!=`                       | `group_id`              |
| `display_name`      | string     | `=`, `!=`                       | `display_name`          |
| `description`       | string     | `=`, `!=`, `contains`, `starts` | `description`           |
| `identity_store_id` | string     | `=`, `!=`                       | `identity_store_id`     |
| `record`            | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                               |
| ---------------------------- | ----------------------------------- |
| Collector ID                 | `aws_identitystore_group_collector` |
| Collector Type               | `aws_identitystore_group`           |
| Collection Mode              | Metadata                            |
| Required Capabilities        | `aws_cli`, `identitystore_read`     |
| Expected Collection Time     | ~2000ms                             |
| Memory Usage                 | ~2MB                                |
| Network Intensive            | Yes                                 |
| CPU Intensive                | No                                  |
| Requires Elevated Privileges | No                                  |
| Batch Collection             | No                                  |

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": ["identitystore:ListGroups"],
  "Resource": "*"
}
```

---

## ESP Examples

### Admins group exists and maps to Entra (KSI-IAM-AAM)

```esp
OBJECT admins_group
    group_name `ProofLayerAdmins`
    identity_store_id `d-906607b0fb`
    region `us-east-1`
OBJECT_END

STATE admins_group_compliant
    found boolean = true
    display_name string = `ProofLayerAdmins`
    description string contains `Entra group`
    identity_store_id string = `d-906607b0fb`
STATE_END

CTN aws_identitystore_group
    TEST all all AND
    STATE_REF admins_group_compliant
    OBJECT_REF admins_group
CTN_END
```

---

## Error Conditions

| Condition                               | Error Type                   | Outcome       |
| --------------------------------------- | ---------------------------- | ------------- |
| Group not found                         | N/A (not an error)           | `found=false` |
| `group_name` missing from object        | `InvalidObjectConfiguration` | Error         |
| `identity_store_id` missing from object | `InvalidObjectConfiguration` | Error         |
| IAM access denied                       | `CollectionFailed`           | Error         |
| Incompatible CTN type                   | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                      | Relationship                                                   |
| ----------------------------- | -------------------------------------------------------------- |
| `aws_ssoadmin_permission_set` | Groups are assigned to permission sets via account assignments |
