# az_role_assignment_list

## Overview

List-mode CTN that wraps `az role assignment list --all --output json`.
Returns one record per Azure RBAC role assignment visible to the
credential -- including assignments inherited from management-group
or root scope. Each record carries the principal (who), the role
definition (what permissions), and the scope (where). The `--all` flag
is critical: without it, `az role assignment list` only returns
assignments at the active subscription's exact scope and silently
drops anything inherited from above.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** The record `name` field is the role assignment's GUID, not a
friendly display name. Use `principal_name` for the human-readable
identity and `role_definition_name` for the human-readable role.

---

## Environment Variables

The agent's `SystemCommandExecutor` calls `env_clear()` before spawning
`az`, then re-injects only the variables below via `set_env_from`. Any
variable not set on the agent is silently skipped.

**You do not need to set all of these.** Pick ONE auth mode and configure
only its required vars -- the rest stay unset and are simply skipped.

### Auth mode: SPN with client secret

| Env var                              | Required | Purpose                     |
| ------------------------------------ | :------: | --------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | SPN application (client) ID |
| `AZURE_CLIENT_SECRET`                |    Yes   | SPN client secret           |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID           |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin    |

### Auth mode: SPN with client certificate

| Env var                              | Required | Purpose                                |
| ------------------------------------ | :------: | -------------------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | SPN application (client) ID            |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID                      |
| `AZURE_CLIENT_CERTIFICATE_PATH`      |    Yes   | Path to PEM/PFX cert on disk           |
| `AZURE_CLIENT_CERTIFICATE_PASSWORD`  |    opt   | Cert password if PFX is encrypted      |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin               |

### Auth mode: Workload Identity (federated OIDC)

| Env var                              | Required | Purpose                                  |
| ------------------------------------ | :------: | ---------------------------------------- |
| `AZURE_CLIENT_ID`                    |    Yes   | Federated identity application ID        |
| `AZURE_TENANT_ID`                    |    Yes   | Entra tenant GUID                        |
| `AZURE_FEDERATED_TOKEN_FILE`         |    Yes   | Path to OIDC token file                  |
| `AZURE_AUTHORITY_HOST`               |    opt   | Sovereign cloud override                 |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Default subscription pin                 |

### Auth mode: Managed Identity

No explicit env vars on the agent. Azure injects `IDENTITY_ENDPOINT` and
`IDENTITY_HEADER` (or legacy `MSI_ENDPOINT` / `MSI_SECRET`) on a VM or
App Service with an assigned identity; the passthrough list forwards
them to `az`.

### Auth mode: Cached `az login`

| Env var                              | Required | Purpose                                            |
| ------------------------------------ | :------: | -------------------------------------------------- |
| `HOME`                               |    Yes   | `az` looks for `~/.azure/` token cache under HOME  |
| `AZURE_CONFIG_DIR`                   |    opt   | Overrides `~/.azure/` location                     |
| `AZURE_SUBSCRIPTION_ID`              |    opt   | Overrides the cached default subscription          |

### Locale (all modes)

| Env var              | Required | Purpose                                     |
| -------------------- | :------: | ------------------------------------------- |
| `LANG` / `LC_ALL`    |    opt   | Suppresses Python locale warnings from `az` |

---

## Object Fields

| Field          | Type   | Required | Description                                                                              | Example                                |
| -------------- | ------ | -------- | ---------------------------------------------------------------------------------------- | -------------------------------------- |
| `scope`        | string | **Yes**  | Discovery scope. `subscription` lists every assignment at or below subscription scope (with `--all`). | `subscription`                         |
| `subscription` | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent. | `00000000-0000-0000-0000-000000000000` |

---

## Commands Executed

```
az role assignment list \
    --all \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

The `--all` flag is always emitted by the collector. Without it, Azure
returns only assignments whose scope exactly matches the active
subscription -- inherited assignments from management-group or tenant
root scope would be invisible.

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../providers/Microsoft.Authorization/roleAssignments/aaaaaaaa-aaaa-...",
    "name": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "type": "Microsoft.Authorization/roleAssignments",
    "scope": "/subscriptions/00000000-...",
    "principalId": "11111111-1111-1111-1111-111111111111",
    "principalName": "platform-team@contoso.com",
    "principalType": "Group",
    "roleDefinitionId": "/subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/...",
    "roleDefinitionName": "Reader",
    "createdOn": "2026-01-12T14:22:01.000000+00:00",
    "updatedOn": "2026-01-12T14:22:01.000000+00:00"
  }
]
```

---

## Collected Data Fields

### Scalar Fields

| Field        | Type    | Always Present | Source                                                              |
| ------------ | ------- | -------------- | ------------------------------------------------------------------- |
| `found`      | boolean | Yes            | Derived -- `true` whenever `az role assignment list` exits cleanly. |
| `role_count` | integer | Yes            | Length of the returned array (`0` if no assignments are visible).   |

### List/Records Field

| Field   | Type       | Always Present | Description                                                             |
| ------- | ---------- | -------------- | ----------------------------------------------------------------------- |
| `roles` | RecordData | Yes            | Projected record array. Empty `[]` when none visible (still `found=true`). |

---

## Record/List Structure

| Path                          | Type   | Example Value                                                              |
| ----------------------------- | ------ | -------------------------------------------------------------------------- |
| `roles.*.id`                  | string | `"/subscriptions/.../roleAssignments/aaaaaaaa-aaaa-..."`                   |
| `roles.*.name`                | string | `"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"` (assignment GUID, NOT friendly)   |
| `roles.*.type`                | string | `"Microsoft.Authorization/roleAssignments"`                                |
| `roles.*.scope`               | string | `"/subscriptions/00000000-..."` (the scope at which the role was granted) |
| `roles.*.principal_id`        | string | `"11111111-1111-1111-1111-111111111111"`                                   |
| `roles.*.principal_name`      | string | `"platform-team@contoso.com"`                                              |
| `roles.*.principal_type`      | string | `"User"`, `"Group"`, `"ServicePrincipal"`, `"ManagedIdentity"`             |
| `roles.*.role_definition_id`  | string | `"/subscriptions/.../roleDefinitions/acdd72a7-3385-..."`                   |
| `roles.*.role_definition_name`| string | `"Reader"`, `"Contributor"`, `"Owner"`, ...                                |
| `roles.*.created_on`          | string | `"2026-01-12T14:22:01.000000+00:00"`                                       |
| `roles.*.updated_on`          | string | `"2026-01-12T14:22:01.000000+00:00"`                                       |

---

## State Fields

| State Field  | Type       | Allowed Operations              | Maps To Collected Field |
| ------------ | ---------- | ------------------------------- | ----------------------- |
| `found`      | boolean    | `=`, `!=`                       | `found`                 |
| `role_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `role_count`            |
| `roles`      | RecordData | (record checks)                 | `roles`                 |

---

## Collection Strategy

| Property                     | Value                             |
| ---------------------------- | --------------------------------- |
| Collector ID                 | `az-role-assignment-list-collector` |
| Collector Type               | `az_role_assignment_list`         |
| Collection Mode              | Metadata                          |
| Required Capabilities        | `az_cli`, `reader`                |
| Expected Collection Time     | ~3000ms                           |
| Memory Usage                 | ~2MB                              |
| Network Intensive            | Yes                               |
| CPU Intensive                | No                                |
| Requires Elevated Privileges | No                                |
| Batch Collection             | No                                |
| Per-call Timeout             | 30s                               |

---

## Required Azure Permissions

`Reader` role at subscription scope is sufficient for enumeration.
Listing role assignments is itself a privilege governed by the
`Microsoft.Authorization/roleAssignments/read` permission, which
`Reader` carries. Assignments at scopes the credential cannot read
(e.g. management group above the granted scope) may still appear
because `--all` requests the full inherited set, but Azure filters
those the credential is not authorized to enumerate.

---

## ESP Examples

### No Owner role grants outside the break-glass group

```esp
OBJECT all_rbac
    scope `subscription`
OBJECT_END

STATE no_unexpected_owners
    found boolean = true
    record
        field roles.*.role_definition_name string != `Owner`
    record_end
STATE_END

CTN az_role_assignment_list
    TEST all all AND
    STATE_REF no_unexpected_owners
    OBJECT_REF all_rbac
CTN_END
```

### Subscription must have at least one Reader assignment

```esp
OBJECT all_rbac
    scope `subscription`
OBJECT_END

STATE rbac_present
    found boolean = true
    role_count int >= 1
STATE_END
```

### No User principals -- groups and SPNs only (least-privilege baseline)

```esp
STATE no_user_principals
    found boolean = true
    record
        field roles.*.principal_type string != `User`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                                       | Error Type              | Outcome                       |
| ----------------------------------------------- | ----------------------- | ----------------------------- |
| No assignments visible                          | N/A (not an error)      | `found=true`, `role_count=0`  |
| `scope` missing from OBJECT                     | `CollectionFailed`      | Error                         |
| `az` binary missing / not authenticated         | `CollectionFailed`      | Error                         |
| Non-zero exit from `az role assignment list`    | `CollectionFailed`      | Error (full stderr in reason) |
| Stdout is not a JSON array                      | `CollectionFailed`      | Error                         |
| Stdout is not valid JSON                        | `CollectionFailed`      | Error                         |
| Incompatible CTN type                           | `CtnContractValidation` | Error                         |

---

## Related CTN Types

| CTN Type             | Relationship                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------- |
| `az_role_assignment` | Typed cousin -- per-assignment lookup by id, with full role-definition expansion.             |
| `az_resource_group`  | Per-RG view -- assignments at RG scope appear here filtered by `roles.*.scope` containing the RG id. |
| `az_entra_group`     | Resolves the `Group` principals referenced by `roles.*.principal_id`.                         |
