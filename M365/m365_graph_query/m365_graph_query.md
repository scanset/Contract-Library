# m365_graph_query

## Overview

Single-CTN discovery primitive: issues a `GET` against an arbitrary Microsoft Graph collection path (`https://graph.microsoft.com/v1.0/<path>`) and returns the result rows as a flat array. One CTN covers every Graph collection — users, groups, devices, conditional access policies, Intune managed devices, Purview policies, SharePoint sites, Teams. New resource types are added at the caller's discovery layer (one entry per Graph path), not by authoring a new CTN per type.

**Platform:** Microsoft Graph (requires an Entra ID app registration with read permissions for the target resource type and admin consent granted)
**Collection Method:** Single HTTPS `GET` per page via `reqwest::blocking::Client`, paginated server-side via `@odata.nextLink`

**Note:** A multi-page collection (e.g. `/users` on a tenant with several hundred users) is typically 1-3s total. The collector caps results at 100,000 rows per invocation as a safety net.

**Note:** The collector sends `ConsistencyLevel: eventual` on every request — required for advanced queries (`$filter` with `endsWith`, `$count`, etc.) and harmless on simpler ones.

---

## Object Fields

| Field    | Type    | Required | Description                                                                       | Example                                                            |
| -------- | ------- | -------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string  | **Yes**  | Graph collection path. Leading slash optional. Posted as `/v1.0/<path>`.          | `/users`, `groups`, `identity/conditionalAccess/policies`         |
| `select` | string  | No       | OData `$select` — comma-separated field list. Reduces response size.              | `id,displayName,userPrincipalName,accountEnabled`                  |
| `filter` | string  | No       | OData `$filter` expression.                                                       | `accountEnabled eq true`                                           |
| `expand` | string  | No       | OData `$expand` clause for related-resource expansion.                            | `memberOf`                                                         |
| `top`    | int     | No       | Per-page result count for `$top`. Default 999. Graph clamps per resource type. **Special value `0` skips the `$top` parameter entirely** — needed for the handful of Graph endpoints that 400 on any `$top` value (e.g. `/identity/conditionalAccess/authenticationContextClassReferences`). | `999` or `0`                                                       |
| `api_version` | string | No  | Graph API version. `v1.0` (default) or `beta`. Use `beta` for Purview / Information Protection labels not yet in v1.0. | `beta`                                                              |

---

## Commands Executed

### Command 1: GET https://graph.microsoft.com/v1.0/{path}

The collector issues a `GET` with a Graph bearer in the `Authorization` header. Pagination follows `@odata.nextLink` URLs (each fully formed) until exhausted or the `MAX_ROWS` cap is hit.

**Collector call:** `client.run_query(initial_url, initial_params, bearer)`

**Resulting request** (representative):

```
GET https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

### Authentication

The collector trades the `AZURE_CLIENT_SECRET` for a Graph bearer:

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={AZURE_CLIENT_ID}&
client_secret={AZURE_CLIENT_SECRET}&
grant_type=client_credentials&
scope=https://graph.microsoft.com/.default
```

Tokens are cached for their lifetime (typically 3600s) with a 60s refresh margin. The app registration must grant the relevant Graph **application permissions** with admin consent — `User.Read.All`, `Group.Read.All`, `Device.Read.All`, `Policy.Read.All`, etc.

**Sample response shape (Graph collection):**

```json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
  "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=X%270044...%27",
  "value": [
    {
      "id": "11111111-1111-1111-1111-111111111111",
      "displayName": "Alice Example",
      "userPrincipalName": "alice@contoso.com",
      "accountEnabled": true
    }
  ]
}
```

**Response parsing:**

- `value[*]` flattened across pagination into the `rows` array.
- Each row is the unmodified Graph object (post-`$select` projection if specified).
- `value.length` post-pagination → `row_count`.
- HTTP 2xx + valid JSON → `found=true`. Empty result still counts as "found" (`row_count=0`).
- `@odata.nextLink` is followed verbatim; the collector does not re-apply OData params on subsequent pages (the next-link URL carries them).

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                                              |
| ----------- | ------- | -------------- | --------------------------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if query executed and parsed       |
| `row_count` | int     | Yes            | `value.length` post-pagination                      |

### RecordData Field

| Field  | Type       | Always Present | Description                                                  |
| ------ | ---------- | -------------- | ------------------------------------------------------------ |
| `rows` | RecordData | Yes            | Array of Graph objects (post-`$select`). Empty `[]` on no match. |

---

## RecordData Structure

Path shape depends entirely on the Graph resource type and the optional `$select` projection. Common patterns:

| Graph collection                                | Resulting `rows.*.X` keys (subset)                                            |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| `/users`                                        | `id`, `displayName`, `userPrincipalName`, `mail`, `accountEnabled`, `userType` |
| `/groups`                                       | `id`, `displayName`, `mail`, `mailEnabled`, `securityEnabled`, `groupTypes`   |
| `/devices`                                      | `id`, `deviceId`, `displayName`, `operatingSystem`, `trustType`, `isCompliant` |
| `/identity/conditionalAccess/policies`          | `id`, `displayName`, `state`, `conditions`, `grantControls`                   |
| `/deviceManagement/managedDevices`              | `id`, `deviceName`, `operatingSystem`, `complianceState`, `lastSyncDateTime`  |

Nested objects (e.g. `signInActivity.lastSignInDateTime`) are returned as nested JSON — record checks address them with dotted paths.

---

## State Fields

| State Field | Type       | Allowed Operations              | Maps To Collected Field |
| ----------- | ---------- | ------------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                       | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`             |
| `rows`      | RecordData | (record checks)                 | `rows`                  |

---

## Collection Strategy

| Property                     | Value                                       |
| ---------------------------- | ------------------------------------------- |
| Collector ID                 | `m365_graph_query_collector`                |
| Collector Type               | `m365_graph_query`                          |
| Collection Mode              | Metadata                                    |
| Required Capabilities        | `azure_spn_env`, `graph_api_reader`         |
| Expected Collection Time     | ~800ms (single page typical; 1-3s on multi-page) |
| Memory Usage                 | ~8MB                                        |
| Network Intensive            | Yes                                         |
| CPU Intensive                | No                                          |
| Requires Elevated Privileges | No                                          |
| Batch Collection             | No                                          |

### Required Permissions

Microsoft Graph **application permissions** on the app registration, with admin consent granted. The exact permission depends on the `path`:

| Path prefix                                    | Permission                                   |
| ---------------------------------------------- | -------------------------------------------- |
| `/users`                                       | `User.Read.All`                              |
| `/groups`                                      | `Group.Read.All`                             |
| `/devices`                                     | `Device.Read.All`                            |
| `/identity/conditionalAccess/*`                | `Policy.Read.All` or `Policy.Read.ConditionalAccess` |
| `/deviceManagement/managedDevices`             | `DeviceManagementManagedDevices.Read.All`    |
| `/deviceManagement/deviceCompliancePolicies`   | `DeviceManagementConfiguration.Read.All`     |
| `/security/sensitivityLabels`                  | `InformationProtectionPolicy.Read.All`       |
| `/sites`                                       | `Sites.Read.All`                             |
| `/teams`                                       | `Team.ReadBasic.All`                         |

---

## ESP Examples

### Bulk-list every Entra user

```esp
OBJECT all_users
    path `/users`
    select `id,displayName,userPrincipalName,accountEnabled`
OBJECT_END

STATE has_users
    found boolean = true
    row_count int > `0`
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF has_users
    OBJECT_REF all_users
CTN_END
```

### Confirm every device has the expected trustType

```esp
OBJECT corp_devices
    path `/devices`
    filter `accountEnabled eq true`
    select `id,displayName,trustType,isCompliant`
OBJECT_END

STATE all_entra_joined_compliant
    found boolean = true
    record
        field rows.*.trustType string = `AzureAd`
        field rows.*.isCompliant boolean = `true`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_entra_joined_compliant
    OBJECT_REF corp_devices
CTN_END
```

### Conditional Access policies must be enabled

```esp
OBJECT ca_policies
    path `identity/conditionalAccess/policies`
    select `id,displayName,state`
OBJECT_END

STATE ca_enabled
    found boolean = true
    row_count int >= `1`
    record
        field rows.*.state string = `enabled`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF ca_enabled
    OBJECT_REF ca_policies
CTN_END
```

---

## Error Conditions

| Condition                                            | Error Type                   | Outcome                          |
| ---------------------------------------------------- | ---------------------------- | -------------------------------- |
| `path` missing                                       | `InvalidObjectConfiguration` | Error                            |
| HTTP 401 from Graph                                  | `CollectionFailed`           | Error — token invalid or refresh failed |
| HTTP 403 from Graph                                  | `CollectionFailed`           | Error — permission granted but admin consent missing |
| HTTP 400 from Graph                                  | `CollectionFailed`           | Error — malformed `$filter` or unsupported path |
| HTTP 429 (throttled)                                 | `CollectionFailed`           | Error — collector does not auto-retry today |
| `AZURE_TENANT_ID` not set in env                     | `CollectionFailed`           | Error — credential not resolved via `build_env` |
| Empty result (valid query, no matches)               | N/A (not an error)           | `found=true`, `row_count=0`      |
| Pagination timeout (60s per request)                 | `CollectionFailed`           | Error                            |
| Result truncation at 100,000 rows                    | N/A — safety cap             | Warning logged; partial rows returned |
| Incompatible CTN type                                | `CtnContractValidation`      | Error                            |

---

## Related CTN Types

| CTN Type                      | Relationship                                                                                  |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `az_resource_graph_query`     | Azure analogue — same single-query bulk discovery shape, ARM-scoped instead of Graph-scoped   |
| `aws_resource_explorer_query` | AWS analogue — same single-query bulk discovery shape                                         |
| (Future) `m365_*` enrichers   | If per-resource detail is needed beyond what Graph collections return — currently unnecessary; Graph's projection covers most uses |
