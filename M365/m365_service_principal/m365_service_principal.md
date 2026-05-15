# m365_service_principal

## Overview

Resource-shape reference for an Entra ID service principal discovered via `m365_graph_query` against `/servicePrincipals`. **Not a standalone CTN.**

A **service principal** is the tenant-local instance of an application — the *runtime identity* that consumes permissions, holds credentials, and is granted role assignments. Multiple service principals can share the same `appId` (one per tenant for a multi-tenant app), but each is a distinct security principal.

**Critical distinction:**
- `application` (see [`m365_app_registration`](../m365_app_registration/m365_app_registration.md)) = the *definition* (lives in the home tenant; carries the schema of what permissions the app requests).
- `servicePrincipal` = the *runtime instance* in this tenant (carries the actual credentials and grants).

Audit-wise, service principals are where most of the interesting questions live: which non-Microsoft app has app-only access, which SPNs have password credentials that never expire, which ones are unverified-publisher third-party apps with `Mail.ReadWrite` against `/users`.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::ServicePrincipal`
**Required permission:** `Application.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                       |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `path`   | string | **Yes**  | Must be `/servicePrincipals` (or `servicePrincipals`).                       | `servicePrincipals`                                           |
| `select` | string | No       | Reduce response payload. Use the schema fields below.                        | `id,appId,displayName,servicePrincipalType,accountEnabled`    |
| `filter` | string | No       | OData `$filter`. Common: `servicePrincipalType eq 'Application'`.            | `accountEnabled eq true and servicePrincipalType eq 'Application'` |

---

## Commands Executed

### Command 1: GET https://graph.microsoft.com/v1.0/servicePrincipals

```
GET https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,signInAudience,tags,keyCredentials,passwordCredentials,verifiedPublisher&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row — a tenant third-party app):**

```json
{
  "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "appId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "displayName": "Contoso Reporter",
  "servicePrincipalType": "Application",
  "accountEnabled": true,
  "appOwnerOrganizationId": "cccccccc-cccc-cccc-cccc-cccccccccccc",
  "createdDateTime": "2025-11-02T14:00:00Z",
  "signInAudience": "AzureADMultipleOrgs",
  "tags": ["WindowsAzureActiveDirectoryIntegratedApp"],
  "keyCredentials": [],
  "passwordCredentials": [
    { "keyId": "dddddddd-dddd-dddd-dddd-dddddddddddd",
      "displayName": "primary",
      "startDateTime": "2025-11-02T14:00:00Z",
      "endDateTime": "2027-11-02T14:00:00Z" }
  ],
  "verifiedPublisher": { "displayName": null, "verifiedPublisherId": null, "addedDateTime": null }
}
```

---

## Collected Data Fields

| Field                                       | Type    | Always Present | Description                                                                              |
| ------------------------------------------- | ------- | -------------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                 | string  | Yes            | Service principal object id (UUID).                                                      |
| `rows.*.appId`                              | string  | Yes            | The application's client id. Joins to [`m365_app_registration`](../m365_app_registration/m365_app_registration.md). |
| `rows.*.displayName`                        | string  | Yes            | Display name of the app.                                                                 |
| `rows.*.servicePrincipalType`               | string  | Yes            | `Application` (most), `ManagedIdentity`, `Legacy`, `SocialIdp`. SPN type drives policy.  |
| `rows.*.accountEnabled`                     | boolean | Yes            | Whether the SPN can sign in.                                                             |
| `rows.*.appOwnerOrganizationId`             | string  | No             | Tenant that *owns* the underlying app. ≠ your tenant id → multi-tenant / 1P / 3P app.    |
| `rows.*.createdDateTime`                    | string  | Yes            | ISO-8601.                                                                                |
| `rows.*.signInAudience`                     | string  | Yes            | `AzureADMyOrg`, `AzureADMultipleOrgs`, `AzureADandPersonalMicrosoftAccount`, `PersonalMicrosoftAccount`. |
| `rows.*.tags`                               | array   | No             | Free-form. `WindowsAzureActiveDirectoryIntegratedApp` is the common one.                 |
| `rows.*.keyCredentials[*]`                  | array   | No             | Certificate credentials. Each has `keyId`, `endDateTime`, `usage`, `type`.               |
| `rows.*.passwordCredentials[*]`             | array   | No             | Client secrets. Each has `keyId`, `endDateTime`, `displayName`. **Values never returned.** |
| `rows.*.verifiedPublisher`                  | object  | Yes            | `{displayName, verifiedPublisherId, addedDateTime}`. All-null = unverified.              |

---


## ESP Examples

### No third-party SPN may have a never-expiring secret

```esp
OBJECT third_party_spns
    path `servicePrincipals`
    filter `servicePrincipalType eq 'Application'`
    select `id,displayName,appOwnerOrganizationId,passwordCredentials`
OBJECT_END

STATE all_secrets_expire
    found boolean = true
    record
        field rows.*.passwordCredentials.*.endDateTime string != ``
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_secrets_expire
    OBJECT_REF third_party_spns
CTN_END
```

### Every third-party application SPN must have a verified publisher

```esp
OBJECT third_party_apps
    path `servicePrincipals`
    filter `servicePrincipalType eq 'Application'`
    select `id,displayName,appOwnerOrganizationId,verifiedPublisher`
OBJECT_END

STATE all_verified
    found boolean = true
    record
        field rows.*.verifiedPublisher.verifiedPublisherId string != ``
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF all_verified
    OBJECT_REF third_party_apps
CTN_END
```

*(Note: the policy that distinguishes 1P / first-party Microsoft apps from genuine third-party SPNs typically does so by allowlisting `appOwnerOrganizationId` of `f8cdef31-a31e-4b4a-93e4-5f571e91255a` — the "Microsoft Services" tenant. Filter accordingly in the OBJECT.)*

---

## Caveats

- **`Application` is the bulk type.** Of these, the *interesting subset* are the ones whose `appOwnerOrganizationId` differs from your own tenant — those are external apps the customer has consented to.
- **Managed identities (`servicePrincipalType = 'ManagedIdentity'`) also show up here.** They have no credentials of their own (Azure manages the cert), so credential-hygiene policies should filter them out.
- **`passwordCredentials.*.value` is never returned by Graph.** You only see metadata (id, expiry, displayName). Good for hygiene, useless for impersonation.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- App-definition side: [`m365_app_registration`](../m365_app_registration/m365_app_registration.md) — joins on `appId`
- Role grants made to an SPN: [`m365_role_assignment`](../m365_role_assignment/m365_role_assignment.md) — joins on `principalId = servicePrincipal.id`
