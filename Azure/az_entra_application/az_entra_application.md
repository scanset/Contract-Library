# az_entra_application

## Overview

Validates an Azure Entra ID application registration via the Azure CLI. Lookup is by display name (`az ad app list --display-name`) or directly by client ID (`az ad app show --id`). Returns configuration scalars and the full app object as RecordData.

**Platform:** Azure (requires `az` CLI binary authenticated via service principal)
**Collection Method:** Single Azure CLI command per object via `AzClient`

**Note:** Tags on Entra app registrations are a flat string array — not `[{Key,Value}]` like AWS. Example: `["esp-daemon","fedramp","example-org"]`. In record checks use `field tags.* string = \`fedramp\` at_least_one`.

**Note:** `signInAudience` should be `AzureADMyOrg` for single-tenant apps. Any other value indicates the app accepts credentials from outside the tenant.

---

## Object Fields

| Field          | Type   | Required | Description                               | Example                                |
| -------------- | ------ | -------- | ----------------------------------------- | -------------------------------------- |
| `display_name` | string | No\*     | App registration display name for lookup  | `example-org-esp-daemon`           |
| `client_id`    | string | No\*     | Application (client) ID for direct lookup | `d4e5f6a7-b8c9-0123-4567-890abcdef012` |

\* At least one of `display_name` or `client_id` must be provided.

- `client_id` uses `az ad app show --id` (single result, faster)
- `display_name` uses `az ad app list --display-name` (takes first result)

---

## Commands Executed

### By client_id:

```
az ad app show --id d4e5f6a7-b8c9-0123-4567-890abcdef012 --output json
```

### By display_name:

```
az ad app list --display-name example-org-esp-daemon --output json
```

**Sample response (abbreviated):**

```json
{
  "appId": "d4e5f6a7-b8c9-0123-4567-890abcdef012",
  "id": "e5f6a7b8-c901-2345-6789-0abcdef01234",
  "displayName": "example-org-esp-daemon",
  "signInAudience": "AzureADMyOrg",
  "publisherDomain": "binarysparklabs.com",
  "tags": ["esp-daemon", "fedramp", "example-org"],
  "passwordCredentials": [
    {
      "displayName": "esp-daemon-secret",
      "endDateTime": "2027-01-01T00:00:00Z",
      "hint": "gdo",
      "keyId": "f6a7b8c9-0123-4567-890a-bcdef0123456"
    }
  ],
  "requiredResourceAccess": [
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        { "id": "e1f2a3b4-5678-9012-abcd-ef3456789012", "type": "Scope" }
      ]
    }
  ]
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                       | Type    | Always Present | Source                                   |
| --------------------------- | ------- | -------------- | ---------------------------------------- |
| `found`                     | boolean | Yes            | Derived — `true` if app found            |
| `app_id`                    | string  | When found     | `appId` (application/client ID)          |
| `object_id`                 | string  | When found     | `id` (object ID)                         |
| `display_name`              | string  | When found     | `displayName`                            |
| `sign_in_audience`          | string  | When found     | `signInAudience`                         |
| `publisher_domain`          | string  | When found     | `publisherDomain`                        |
| `has_password_credentials`  | boolean | When found     | Derived — `len(passwordCredentials) > 0` |
| `password_credential_count` | integer | When found     | Derived — `len(passwordCredentials)`     |

### RecordData Field

| Field      | Type       | Always Present | Description                                             |
| ---------- | ---------- | -------------- | ------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full app registration object. Empty `{}` when not found |

---

## RecordData Structure

```
appId                                    → "d4e5f6a7-b8c9-0123-4567-890abcdef012"
id                                       → "e5f6a7b8-c901-2345-6789-0abcdef01234"
displayName                              → "example-org-esp-daemon"
signInAudience                           → "AzureADMyOrg"
publisherDomain                          → "binarysparklabs.com"
tags.0                                   → "esp-daemon"
tags.1                                   → "fedramp"
tags.2                                   → "example-org"
tags.*                                   → (all tags via wildcard)
passwordCredentials.0.displayName        → "esp-daemon-secret"
passwordCredentials.0.endDateTime        → "2027-01-01T00:00:00Z"
requiredResourceAccess.0.resourceAppId   → "00000003-0000-0000-c000-000000000000"
```

---

## State Fields

| State Field                 | Type       | Allowed Operations              | Maps To Collected Field     |
| --------------------------- | ---------- | ------------------------------- | --------------------------- |
| `found`                     | boolean    | `=`, `!=`                       | `found`                     |
| `app_id`                    | string     | `=`, `!=`                       | `app_id`                    |
| `object_id`                 | string     | `=`, `!=`                       | `object_id`                 |
| `display_name`              | string     | `=`, `!=`                       | `display_name`              |
| `sign_in_audience`          | string     | `=`, `!=`                       | `sign_in_audience`          |
| `publisher_domain`          | string     | `=`, `!=`, `contains`, `starts` | `publisher_domain`          |
| `has_password_credentials`  | boolean    | `=`, `!=`                       | `has_password_credentials`  |
| `password_credential_count` | int        | `=`, `!=`, `>=`, `<=`, `>`, `<` | `password_credential_count` |
| `record`                    | RecordData | (record checks)                 | `resource`                  |

---

## Collection Strategy

| Property                 | Value                            |
| ------------------------ | -------------------------------- |
| Collector ID             | `az_entra_application_collector` |
| Collector Type           | `az_entra_application`           |
| Collection Mode          | Metadata                         |
| Required Capabilities    | `az_cli`, `entra_read`           |
| Expected Collection Time | ~3000ms                          |
| Memory Usage             | ~5MB                             |
| Batch Collection         | No                               |

### Required Azure Permissions

The SPN used to run the daemon must have the **Directory Readers** Entra directory role to call `az ad app list/show`.

---

## ESP Examples

### ESP daemon app is single-tenant with one client secret (KSI-IAM-SNU)

```esp
OBJECT esp_daemon_app
    display_name `example-org-esp-daemon`
OBJECT_END

STATE esp_app_compliant
    found boolean = true
    sign_in_audience string = `AzureADMyOrg`
    has_password_credentials boolean = true
    password_credential_count int = 1
    record
        field tags.* string = `fedramp` at_least_one
        field tags.* string = `esp-daemon` at_least_one
    record_end
STATE_END

CTN az_entra_application
    TEST all all AND
    STATE_REF esp_app_compliant
    OBJECT_REF esp_daemon_app
CTN_END
```

---

## Error Conditions

| Condition              | Error Type                   | Outcome       |
| ---------------------- | ---------------------------- | ------------- |
| App not found          | N/A (not an error)           | `found=false` |
| Neither field provided | `InvalidObjectConfiguration` | Error         |
| Azure CLI auth failure | `CollectionFailed`           | Error         |
| Incompatible CTN type  | `CtnContractValidation`      | Error         |

---

## Related CTN Types

| CTN Type                     | Relationship                                           |
| ---------------------------- | ------------------------------------------------------ |
| `az_entra_service_principal` | Every app registration has a backing service principal |
| `az_role_assignment`         | Service principal is assigned Azure RBAC roles         |
