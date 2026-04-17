# az_entra_service_principal

## Overview

Validates an Azure Entra ID service principal via the Azure CLI using `az ad sp show --id <client_id>`. The `client_id` is the application (client) ID — the `appId` field — not the service principal object ID.

**Platform:** Azure (requires `az` CLI binary authenticated via service principal)
**Collection Method:** Single Azure CLI command per object via `AzClient`

**Note:** Every app registration has a corresponding service principal. The service principal is the identity used for RBAC assignments and directory role assignments. Use `az_entra_application` to validate the app registration itself.

---

## Object Fields

| Field       | Type   | Required | Description                                              | Example                                |
| ----------- | ------ | -------- | -------------------------------------------------------- | -------------------------------------- |
| `client_id` | string | **Yes**  | Application (client) ID — the `appId` of the backing app | `22222222-2222-2222-2222-222222222222` |

---

## Commands Executed

```
az ad sp show --id 22222222-2222-2222-2222-222222222222 --output json
```

**Sample response (abbreviated):**

```json
{
  "id": "33333333-3333-3333-3333-333333333333",
  "appId": "22222222-2222-2222-2222-222222222222",
  "displayName": "prooflayer-demo-esp-daemon",
  "accountEnabled": true,
  "appRoleAssignmentRequired": false,
  "servicePrincipalType": "Application",
  "signInAudience": "AzureADMyOrg",
  "tags": ["esp-daemon", "fedramp", "prooflayer"],
  "keyCredentials": [],
  "passwordCredentials": []
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                          | Type    | Always Present | Source                                      |
| ------------------------------ | ------- | -------------- | ------------------------------------------- |
| `found`                        | boolean | Yes            | Derived — `true` if service principal found |
| `sp_object_id`                 | string  | When found     | `id` (service principal object ID)          |
| `app_id`                       | string  | When found     | `appId` (application/client ID)             |
| `display_name`                 | string  | When found     | `displayName`                               |
| `account_enabled`              | boolean | When found     | `accountEnabled`                            |
| `app_role_assignment_required` | boolean | When found     | `appRoleAssignmentRequired`                 |
| `service_principal_type`       | string  | When found     | `servicePrincipalType`                      |
| `sign_in_audience`             | string  | When found     | `signInAudience`                            |
| `key_credential_count`         | integer | When found     | Derived — `len(keyCredentials)`             |

### RecordData Field

| Field      | Type       | Always Present | Description                                              |
| ---------- | ---------- | -------------- | -------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full service principal object. Empty `{}` when not found |

---

## RecordData Structure

```
id                          → "33333333-3333-3333-3333-333333333333"
appId                       → "22222222-2222-2222-2222-222222222222"
displayName                 → "prooflayer-demo-esp-daemon"
accountEnabled              → true
appRoleAssignmentRequired   → false
servicePrincipalType        → "Application"
signInAudience              → "AzureADMyOrg"
tags.0                      → "esp-daemon"
tags.*                      → (all tags via wildcard)
keyCredentials              → [] (empty array when no cert credentials)
```

---

## State Fields

| State Field                    | Type       | Allowed Operations | Maps To Collected Field        |
| ------------------------------ | ---------- | ------------------ | ------------------------------ |
| `found`                        | boolean    | `=`, `!=`          | `found`                        |
| `sp_object_id`                 | string     | `=`, `!=`          | `sp_object_id`                 |
| `app_id`                       | string     | `=`, `!=`          | `app_id`                       |
| `display_name`                 | string     | `=`, `!=`          | `display_name`                 |
| `account_enabled`              | boolean    | `=`, `!=`          | `account_enabled`              |
| `app_role_assignment_required` | boolean    | `=`, `!=`          | `app_role_assignment_required` |
| `service_principal_type`       | string     | `=`, `!=`          | `service_principal_type`       |
| `sign_in_audience`             | string     | `=`, `!=`          | `sign_in_audience`             |
| `key_credential_count`         | int        | `=`, `!=`, `>=`    | `key_credential_count`         |
| `record`                       | RecordData | (record checks)    | `resource`                     |

---

## Collection Strategy

| Property                 | Value                                  |
| ------------------------ | -------------------------------------- |
| Collector ID             | `az_entra_service_principal_collector` |
| Collector Type           | `az_entra_service_principal`           |
| Collection Mode          | Metadata                               |
| Required Capabilities    | `az_cli`, `entra_read`                 |
| Expected Collection Time | ~2000ms                                |
| Memory Usage             | ~5MB                                   |
| Batch Collection         | No                                     |

### Required Azure Permissions

Directory Readers role on the SPN running the daemon.

---

## ESP Examples

### ESP daemon SPN is enabled, single-tenant, no cert credentials (KSI-IAM-SNU)

```esp
OBJECT esp_daemon_sp
    client_id `22222222-2222-2222-2222-222222222222`
OBJECT_END

STATE esp_sp_compliant
    found boolean = true
    account_enabled boolean = true
    service_principal_type string = `Application`
    sign_in_audience string = `AzureADMyOrg`
    key_credential_count int = 0
STATE_END

CTN az_entra_service_principal
    TEST all all AND
    STATE_REF esp_sp_compliant
    OBJECT_REF esp_daemon_sp
CTN_END
```

---

## Error Conditions

| Condition                       | Error Type                   | Outcome       |
| ------------------------------- | ---------------------------- | ------------- |
| Service principal not found     | N/A (not an error)           | `found=false` |
| `client_id` missing from object | `InvalidObjectConfiguration` | Error         |
| Azure CLI auth failure          | `CollectionFailed`           | Error         |
| Incompatible CTN type           | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type               | Relationship                                           |
| ---------------------- | ------------------------------------------------------ |
| `az_entra_application` | Service principal is the identity object of an app reg |
| `az_role_assignment`   | Service principal is assigned Azure RBAC Reader role   |
