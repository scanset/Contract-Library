# az_role_assignment

## Overview

Validates Azure RBAC role assignments for a service principal or user. Calls `az role assignment list --assignee <principal_id> [--scope <scope>]` and returns the first assignment matching `role_name` (when provided), otherwise the first result. Used for confirming least-privilege RBAC: the principal must have role X at scope Y, no broader.

**Platform:** Azure (requires `az` CLI binary authenticated as a principal with `Microsoft.Authorization/roleAssignments/read` permission)
**Collection Method:** Single Azure CLI call via `AzClient.role_assignment_list()`

**Note:** Uses the **service principal object ID**, not the appId. Get it via `az ad sp show --id <appId> --query id`. When `role_name` is provided, only the first assignment with that exact `roleDefinitionName` is returned; absent — first result wins.

---

## Object Fields

| Field          | Type   | Required | Description                                                              | Example                                              |
| -------------- | ------ | -------- | ------------------------------------------------------------------------ | ---------------------------------------------------- |
| `principal_id` | string | **Yes**  | Service principal or user object ID (NOT appId)                          | `33333333-3333-3333-3333-333333333333`               |
| `role_name`    | string | No       | Role definition name to match. Collector picks the first assignment with this `roleDefinitionName` | `Reader`, `Contributor`, `Storage Blob Data Reader` |
| `scope`        | string | No       | Scope filter — passed as `--scope` to the CLI                            | `/subscriptions/66666666-6666-6666-6666-666666666666` |

---

## Commands Executed

### Command 1: az role assignment list

Lists role assignments for the principal, optionally narrowed by scope.

**Collector call:** `client.role_assignment_list(principal_id, scope)`

**Resulting commands:**

```
# All assignments for the principal (across visible scopes)
az role assignment list --assignee 33333333-3333-3333-3333-333333333333

# Narrowed to a specific subscription
az role assignment list \
    --assignee 33333333-3333-3333-3333-333333333333 \
    --scope /subscriptions/66666666-6666-6666-6666-666666666666

# Narrowed to a resource group
az role assignment list \
    --assignee 33333333-3333-3333-3333-333333333333 \
    --scope /subscriptions/.../resourceGroups/prod-rg
```

**Sample response:**

```json
[
  {
    "id": "/subscriptions/.../providers/Microsoft.Authorization/roleAssignments/abc",
    "name": "abc",
    "principalId": "33333333-3333-3333-3333-333333333333",
    "principalType": "ServicePrincipal",
    "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "roleDefinitionName": "Reader",
    "scope": "/subscriptions/66666666-6666-6666-6666-666666666666",
    "type": "Microsoft.Authorization/roleAssignments"
  }
]
```

**Response parsing:**

- Filter array by `roleDefinitionName == role_name` (when `role_name` set), else use array[0].
- `roleDefinitionName` → `role_definition_name`
- `scope` → `scope`
- `principalId` → `principal_id`
- `principalType` → `principal_type`
- `id` → `assignment_id`
- Full assignment object → `resource` RecordData
- Empty array (no match) → `found=false`, no other fields set

---

## Collected Data Fields

### Scalar Fields

| Field                  | Type    | Always Present | Source                  |
| ---------------------- | ------- | -------------- | ----------------------- |
| `found`                | boolean | Yes            | Derived — `true` if any (matching) assignment exists |
| `role_definition_name` | string  | When found     | `roleDefinitionName`    |
| `scope`                | string  | When found     | `scope`                 |
| `principal_id`         | string  | When found     | `principalId`           |
| `principal_type`       | string  | When found     | `principalType`         |
| `assignment_id`        | string  | When found     | `id`                    |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full role assignment object. Empty `{}` when not found     |

---

## RecordData Structure

| Path                     | Type   | Example Value                                                                                  |
| ------------------------ | ------ | ---------------------------------------------------------------------------------------------- |
| `roleDefinitionName`     | string | `"Reader"`                                                                                     |
| `roleDefinitionId`       | string | `"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"`    |
| `scope`                  | string | `"/subscriptions/66666666-6666-6666-6666-666666666666"`                                        |
| `principalType`          | string | `"ServicePrincipal"`                                                                           |

---

## State Fields

| State Field            | Type       | Allowed Operations              | Maps To Collected Field |
| ---------------------- | ---------- | ------------------------------- | ----------------------- |
| `found`                | boolean    | `=`, `!=`                       | `found`                 |
| `role_definition_name` | string     | `=`, `!=`                       | `role_definition_name`  |
| `scope`                | string     | `=`, `!=`, `contains`, `starts` | `scope`                 |
| `principal_id`         | string     | `=`, `!=`                       | `principal_id`          |
| `principal_type`       | string     | `=`, `!=`                       | `principal_type`        |
| `assignment_id`        | string     | `=`, `!=`, `contains`, `starts` | `assignment_id`         |
| `record`               | RecordData | (record checks)                 | `resource`              |

---

## Collection Strategy

| Property                     | Value                              |
| ---------------------------- | ---------------------------------- |
| Collector ID                 | `az_role_assignment_collector`     |
| Collector Type               | `az_role_assignment`               |
| Collection Mode              | Metadata                           |
| Required Capabilities        | `az_cli`, `azure_rbac_read`        |
| Expected Collection Time     | ~2000ms                            |
| Memory Usage                 | ~2MB                               |
| Network Intensive            | Yes                                |
| CPU Intensive                | No                                 |
| Requires Elevated Privileges | No                                 |
| Batch Collection             | No                                 |

### Required Permissions

The principal running `az` must have `Microsoft.Authorization/roleAssignments/read` at the scope being queried. The built-in `Reader` role at subscription scope is sufficient.

---

## ESP Examples

### Validate the prooflayer SPN has exactly Reader at the subscription level

```esp
OBJECT prooflayer_spn_reader
    principal_id `33333333-3333-3333-3333-333333333333`
    role_name `Reader`
    scope `/subscriptions/66666666-6666-6666-6666-666666666666`
OBJECT_END

STATE has_reader_only
    found boolean = true
    role_definition_name string = `Reader`
    principal_type string = `ServicePrincipal`
    scope string starts `/subscriptions/66666666-6666-6666-6666-666666666666`
STATE_END

CTN az_role_assignment
    TEST all all AND
    STATE_REF has_reader_only
    OBJECT_REF prooflayer_spn_reader
CTN_END
```

### Confirm no Owner / Contributor at any scope

```esp
OBJECT spn_owner_check
    principal_id `33333333-3333-3333-3333-333333333333`
    role_name `Owner`
OBJECT_END

STATE no_owner_assignment
    found boolean = false
STATE_END

CTN az_role_assignment
    TEST all all AND
    STATE_REF no_owner_assignment
    OBJECT_REF spn_owner_check
CTN_END
```

### Validate scope hierarchy via record fields

```esp
OBJECT specific_assignment
    principal_id `33333333-3333-3333-3333-333333333333`
    role_name `Storage Blob Data Reader`
OBJECT_END

STATE narrow_scope_only
    found boolean = true
    record
        field roleDefinitionName string = `Storage Blob Data Reader`
        field scope string contains `resourceGroups/prod-rg`
    record_end
STATE_END

CTN az_role_assignment
    TEST all all AND
    STATE_REF narrow_scope_only
    OBJECT_REF specific_assignment
CTN_END
```

---

## Error Conditions

| Condition                                                 | Error Type                   | Outcome                          |
| --------------------------------------------------------- | ---------------------------- | -------------------------------- |
| `principal_id` missing in OBJECT                          | `InvalidObjectConfiguration` | Error                            |
| Principal has no assignments (or none matching role_name) | N/A (not an error)           | `found=false`                    |
| `principal_id` is appId, not object ID                    | N/A (Azure returns empty)    | `found=false` — confusing failure mode |
| Azure CLI auth failure                                    | `CollectionFailed`           | Error                            |
| Permission denied (`roleAssignments/read`)                | `CollectionFailed`           | Error                            |
| Incompatible CTN type                                     | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type                       | Relationship                                                                              |
| ------------------------------ | ----------------------------------------------------------------------------------------- |
| `az_entra_service_principal`   | Validate the SPN itself (existence, owner, secrets) before checking its role assignments  |
| `az_entra_group`               | Group-membership-based role assignments — different lookup shape                          |
| `az_role_assignment_list`      | Bulk variant — returns all assignments at a scope without role_name filtering             |
| `az_resource_graph_query`      | Discovery — KQL query against `AuthorizationResources` returns all assignments tenant-wide |
