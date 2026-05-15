# az_policy_assignment_list

## Overview

List-mode CTN that wraps `az policy assignment list --output json`.
Returns one record per Azure-native Policy assignment visible at the
active subscription scope. Each record carries the policy definition
reference, the scope it applies at, the enforcement mode (`Default`
vs `DoNotEnforce`), and `systemData` provenance fields hoisted to
top-level (`created_at`, `created_by`, `created_by_type`).

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** "Policy assignment" here refers to Azure Policy (the native
governance service), NOT to ESP `.esp` policies. The two are
unrelated -- this CTN is for verifying that Azure Policy initiatives
(e.g. Azure Security Benchmark, NIST 800-53 R5) are assigned and
enforcing.

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
| `scope`        | string | **Yes**  | Discovery scope. `subscription` lists assignments at the active subscription scope.      | `subscription`                         |
| `subscription` | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent. | `00000000-0000-0000-0000-000000000000` |

---

## Commands Executed

```
az policy assignment list \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
    "name": "SecurityCenterBuiltIn",
    "type": "Microsoft.Authorization/policyAssignments",
    "displayName": "ASC Default (subscription: 00000000-...)",
    "description": "This policy assignment was automatically created by Azure Security Center",
    "enforcementMode": "Default",
    "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
    "scope": "/subscriptions/00000000-...",
    "definitionVersion": "1.*.*",
    "systemData": {
      "createdAt": "2025-12-04T08:11:53.000Z",
      "createdBy": "policy-bootstrap@contoso.com",
      "createdByType": "User"
    }
  }
]
```

---

## Collected Data Fields

### Scalar Fields

| Field              | Type    | Always Present | Source                                                              |
| ------------------ | ------- | -------------- | ------------------------------------------------------------------- |
| `found`            | boolean | Yes            | Derived -- `true` whenever `az policy assignment list` exits cleanly. |
| `assignment_count` | integer | Yes            | Length of the returned array (`0` if no assignments are present).  |

### List/Records Field

| Field         | Type       | Always Present | Description                                                                |
| ------------- | ---------- | -------------- | -------------------------------------------------------------------------- |
| `assignments` | RecordData | Yes            | Projected record array. Empty `[]` when none configured (still `found=true`). |

---

## Record/List Structure

| Path                                | Type   | Example Value                                                                          |
| ----------------------------------- | ------ | -------------------------------------------------------------------------------------- |
| `assignments.*.id`                  | string | `"/subscriptions/.../policyAssignments/SecurityCenterBuiltIn"`                         |
| `assignments.*.name`                | string | `"SecurityCenterBuiltIn"`                                                              |
| `assignments.*.type`                | string | `"Microsoft.Authorization/policyAssignments"`                                          |
| `assignments.*.display_name`        | string | `"ASC Default (subscription: 00000000-...)"`                                           |
| `assignments.*.description`         | string | `"This policy assignment was automatically created by Azure Security Center"`         |
| `assignments.*.enforcement_mode`    | string | `"Default"` or `"DoNotEnforce"`                                                        |
| `assignments.*.policy_definition_id`| string | `"/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-..."`               |
| `assignments.*.scope`               | string | `"/subscriptions/00000000-..."` (assignment scope, may differ from query subscription) |
| `assignments.*.definition_version`  | string | `"1.*.*"`                                                                              |
| `assignments.*.created_at`          | string | `"2025-12-04T08:11:53.000Z"` (hoisted from `systemData.createdAt`)                     |
| `assignments.*.created_by`          | string | `"policy-bootstrap@contoso.com"` (hoisted from `systemData.createdBy`)                 |
| `assignments.*.created_by_type`     | string | `"User"`, `"ServicePrincipal"`, `"ManagedIdentity"`, `"Application"`                   |

---

## State Fields

| State Field        | Type       | Allowed Operations              | Maps To Collected Field |
| ------------------ | ---------- | ------------------------------- | ----------------------- |
| `found`            | boolean    | `=`, `!=`                       | `found`                 |
| `assignment_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `assignment_count`      |
| `assignments`      | RecordData | (record checks)                 | `assignments`           |

---

## Collection Strategy

| Property                     | Value                                |
| ---------------------------- | ------------------------------------ |
| Collector ID                 | `az-policy-assignment-list-collector` |
| Collector Type               | `az_policy_assignment_list`          |
| Collection Mode              | Metadata                             |
| Required Capabilities        | `az_cli`, `reader`                   |
| Expected Collection Time     | ~2000ms                              |
| Memory Usage                 | ~2MB                                 |
| Network Intensive            | Yes                                  |
| CPU Intensive                | No                                   |
| Requires Elevated Privileges | No                                   |
| Batch Collection             | No                                   |
| Per-call Timeout             | 30s                                  |

---

## Required Azure Permissions

`Reader` role at subscription scope. Listing policy assignments
requires `Microsoft.Authorization/policyAssignments/read`, which
`Reader` carries.

---

## ESP Examples

### Subscription must have ASC Default initiative assigned and enforcing

```esp
OBJECT sub_policies
    scope `subscription`
OBJECT_END

STATE asc_default_enforcing
    found boolean = true
    assignment_count int >= 1
    record
        field assignments.0.name string = `SecurityCenterBuiltIn`
        field assignments.0.enforcement_mode string = `Default`
    record_end
STATE_END

CTN az_policy_assignment_list
    TEST all all AND
    STATE_REF asc_default_enforcing
    OBJECT_REF sub_policies
CTN_END
```

### No assignments may be in DoNotEnforce mode (everything must enforce)

```esp
OBJECT sub_policies
    scope `subscription`
OBJECT_END

STATE all_enforcing
    found boolean = true
    record
        field assignments.*.enforcement_mode string = `Default`
    record_end
STATE_END

CTN az_policy_assignment_list
    TEST all all AND
    STATE_REF all_enforcing
    OBJECT_REF sub_policies
CTN_END
```

### Subscription must have at least 3 governance initiatives assigned

```esp
STATE governance_baseline
    found boolean = true
    assignment_count int >= 3
STATE_END
```

---

## Error Conditions

| Condition                                       | Error Type              | Outcome                              |
| ----------------------------------------------- | ----------------------- | ------------------------------------ |
| No policy assignments configured                | N/A (not an error)      | `found=true`, `assignment_count=0`   |
| `scope` missing from OBJECT                     | `CollectionFailed`      | Error                                |
| `az` binary missing / not authenticated         | `CollectionFailed`      | Error                                |
| Non-zero exit from `az policy assignment list`  | `CollectionFailed`      | Error (full stderr in reason)        |
| Stdout is not a JSON array                      | `CollectionFailed`      | Error                                |
| Stdout is not valid JSON                        | `CollectionFailed`      | Error                                |
| Incompatible CTN type                           | `CtnContractValidation` | Error                                |

---

## Related CTN Types

| CTN Type                  | Relationship                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `az_role_assignment_list` | Sibling list -- RBAC assignments (the "who can do what" plane).                       |
| `az_resource_group_list`  | Sibling list -- assignments at RG scope can be filtered via `assignments.*.scope`.    |
| `az_diagnostic_setting_list` | Sibling list -- often configured by the same Azure Policy initiatives.            |
