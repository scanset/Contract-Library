# az_entra_group

## Overview

Validates an Azure Entra ID security group via the Azure CLI using `az ad group show --group <display_name>`. Returns group configuration including security enablement and description confirming Entra-to-AWS federation mapping.

**Platform:** Azure (requires `az` CLI binary authenticated via service principal)
**Collection Method:** Single Azure CLI command per object via `AzClient`

**Note:** Entra groups have no tags. The `description` field is the primary way to confirm federation mapping intent.

---

## Object Fields

| Field          | Type   | Required | Description                     | Example                      |
| -------------- | ------ | -------- | ------------------------------- | ---------------------------- |
| `display_name` | string | **Yes**  | Group display name or object ID | `aws-example-org-admins` |

---

## Commands Executed

```
az ad group show --group aws-example-org-admins --output json
```

**Sample response (abbreviated):**

```json
{
  "id": "a7b8c9d0-1234-5678-90ab-cdef01234567",
  "displayName": "aws-example-org-admins",
  "description": "ExampleOrg AWS admins - maps to ExampleOrgAdmin permission set",
  "securityEnabled": true,
  "mailEnabled": false,
  "groupTypes": [],
  "createdDateTime": "2026-03-23T19:58:34Z"
}
```

---

## Collected Data Fields

### Scalar Fields

| Field              | Type    | Always Present | Source                          |
| ------------------ | ------- | -------------- | ------------------------------- |
| `found`            | boolean | Yes            | Derived — `true` if group found |
| `group_id`         | string  | When found     | `id` (object ID)                |
| `display_name`     | string  | When found     | `displayName`                   |
| `description`      | string  | When found     | `description`                   |
| `security_enabled` | boolean | When found     | `securityEnabled`               |
| `mail_enabled`     | boolean | When found     | `mailEnabled`                   |

### RecordData Field

| Field      | Type       | Always Present | Description                                  |
| ---------- | ---------- | -------------- | -------------------------------------------- |
| `resource` | RecordData | Yes            | Full group object. Empty `{}` when not found |

---

## RecordData Structure

```
id                → "a7b8c9d0-1234-5678-90ab-cdef01234567"
displayName       → "aws-example-org-admins"
description       → "ExampleOrg AWS admins - maps to ExampleOrgAdmin permission set"
securityEnabled   → true
mailEnabled       → false
createdDateTime   → "2026-03-23T19:58:34Z"
```

---

## State Fields

| State Field        | Type       | Allowed Operations              | Maps To Collected Field |
| ------------------ | ---------- | ------------------------------- | ----------------------- |
| `found`            | boolean    | `=`, `!=`                       | `found`                 |
| `group_id`         | string     | `=`, `!=`                       | `group_id`              |
| `display_name`     | string     | `=`, `!=`                       | `display_name`          |
| `description`      | string     | `=`, `!=`, `contains`, `starts` | `description`           |
| `security_enabled` | boolean    | `=`, `!=`                       | `security_enabled`      |
| `mail_enabled`     | boolean    | `=`, `!=`                       | `mail_enabled`          |
| `record`           | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                 | Value                      |
| ------------------------ | -------------------------- |
| Collector ID             | `az_entra_group_collector` |
| Collector Type           | `az_entra_group`           |
| Collection Mode          | Metadata                   |
| Required Capabilities    | `az_cli`, `entra_read`     |
| Expected Collection Time | ~2000ms                    |
| Memory Usage             | ~2MB                       |
| Batch Collection         | No                         |

### Required Azure Permissions

Directory Readers role on the SPN running the daemon.

---

## ESP Examples

### Admins group exists, security-enabled, maps to AWS permission set (KSI-IAM-AAM)

```esp
OBJECT admins_group
    display_name `aws-example-org-admins`
OBJECT_END

STATE admins_group_compliant
    found boolean = true
    security_enabled boolean = true
    mail_enabled boolean = false
    description string contains `ExampleOrgAdmin`
STATE_END

CTN az_entra_group
    TEST all all AND
    STATE_REF admins_group_compliant
    OBJECT_REF admins_group
CTN_END
```

---

## Error Conditions

| Condition                          | Error Type                   | Outcome       |
| ---------------------------------- | ---------------------------- | ------------- |
| Group not found                    | N/A (not an error)           | `found=false` |
| `display_name` missing from object | `InvalidObjectConfiguration` | Error         |
| Azure CLI auth failure             | `CollectionFailed`           | Error         |
| Incompatible CTN type              | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                      | Relationship                                             |
| ----------------------------- | -------------------------------------------------------- |
| `aws_identitystore_group`     | Entra groups federate to Identity Center groups via SAML |
| `aws_ssoadmin_permission_set` | Identity Center groups are assigned to permission sets   |
