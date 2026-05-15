# m365_app_registration

## Overview

Resource-shape reference for an Entra ID application object discovered via `m365_graph_query` against `/applications`. **Not a standalone CTN.**

An **application** is the *definition* of an app in the home tenant — its declared permissions, redirect URIs, sign-in audience, identifier URIs, and credential schema. The corresponding *runtime identity* in any tenant where the app is consented is a [`m365_service_principal`](../m365_service_principal/m365_service_principal.md), joined on `appId`.

For an audit lens:
- **`/applications`** (this resource) shows apps **owned by THIS tenant** — typically internal line-of-business apps the customer has authored.
- **`/servicePrincipals`** shows ALL apps with a runtime identity in this tenant — including third-party / Microsoft apps the customer has consented to.

So `/applications ⊂ /servicePrincipals` by `appId` (every tenant-owned app has an SPN in the same tenant), and the *additional* SPN rows represent external apps that have no application object here.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::AppRegistration`
**Required permission:** `Application.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                       |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `path`   | string | **Yes**  | Must be `/applications` (or `applications`).                                 | `applications`                                                |
| `select` | string | No       | Reduce response payload. Use the schema fields below.                        | `id,appId,displayName,signInAudience`                         |
| `filter` | string | No       | OData `$filter`. Common: `signInAudience eq 'AzureADMyOrg'`.                 | `signInAudience eq 'AzureADMyOrg'`                            |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,publisherDomain,identifierUris,keyCredentials,passwordCredentials,requiredResourceAccess,tags,api,web&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single row — internal LOB app):**

```json
{
  "id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
  "appId": "ffffffff-ffff-ffff-ffff-ffffffffffff",
  "displayName": "Compliance Scanner",
  "createdDateTime": "2025-08-01T12:00:00Z",
  "signInAudience": "AzureADMyOrg",
  "publisherDomain": "contoso.onmicrosoft.com",
  "identifierUris": [],
  "keyCredentials": [],
  "passwordCredentials": [
    { "keyId": "11111111-1111-1111-1111-111111111111",
      "displayName": "compliance-scanner",
      "endDateTime": "2026-08-01T12:00:00Z" }
  ],
  "requiredResourceAccess": [
    { "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        { "id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role" }
      ]
    }
  ],
  "tags": [],
  "api": { "requestedAccessTokenVersion": 2, "acceptMappedClaims": null, "knownClientApplications": [], "oauth2PermissionScopes": [], "preAuthorizedApplications": [] },
  "web": { "redirectUris": [], "homePageUrl": null, "logoutUrl": null, "implicitGrantSettings": { "enableIdTokenIssuance": false, "enableAccessTokenIssuance": false } }
}
```

---

## Collected Data Fields

| Field                                       | Type    | Always Present | Description                                                                              |
| ------------------------------------------- | ------- | -------------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                                 | string  | Yes            | Application object id (UUID).                                                            |
| `rows.*.appId`                              | string  | Yes            | Client id. Joins to [`m365_service_principal`](../m365_service_principal/m365_service_principal.md). |
| `rows.*.displayName`                        | string  | Yes            | App display name.                                                                        |
| `rows.*.createdDateTime`                    | string  | Yes            | ISO-8601.                                                                                |
| `rows.*.signInAudience`                     | string  | Yes            | `AzureADMyOrg` (single-tenant), `AzureADMultipleOrgs` (multi-tenant), `AzureADandPersonalMicrosoftAccount`, `PersonalMicrosoftAccount`. |
| `rows.*.publisherDomain`                    | string  | No             | Verified publisher domain.                                                               |
| `rows.*.identifierUris`                     | array   | No             | The app's URIs (used for SAML / on-behalf-of flows).                                     |
| `rows.*.keyCredentials[*]`                  | array   | No             | Certificate credentials with `keyId`, `endDateTime`, `usage`, `type`.                    |
| `rows.*.passwordCredentials[*]`             | array   | No             | Client secrets with `keyId`, `endDateTime`, `displayName`. Values never returned.        |
| `rows.*.requiredResourceAccess[*]`          | array   | Yes (often empty) | Declared permission *requests* — `{resourceAppId, resourceAccess: [{id, type}]}`. Type = `Role` (app perm) or `Scope` (delegated). |
| `rows.*.tags`                               | array   | No             | Free-form admin tags.                                                                    |
| `rows.*.api`                                | object  | No             | OAuth2 / OBO config: `requestedAccessTokenVersion`, `oauth2PermissionScopes`, etc.       |
| `rows.*.web`                                | object  | No             | Web-platform config: `redirectUris`, `implicitGrantSettings`. Implicit grant is a red flag. |

---


## ESP Examples

### No internal app may declare implicit grant tokens

Implicit-grant (OAuth2 `response_type=token`) is deprecated and unsafe in modern flows. Apps should use auth-code + PKCE.

```esp
OBJECT internal_apps
    path `applications`
    select `id,displayName,web`
OBJECT_END

STATE no_implicit_grant
    found boolean = true
    record
        field rows.*.web.implicitGrantSettings.enableIdTokenIssuance boolean = `false`
        field rows.*.web.implicitGrantSettings.enableAccessTokenIssuance boolean = `false`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_implicit_grant
    OBJECT_REF internal_apps
CTN_END
```

### Every internal app must be single-tenant

For tenants that explicitly do not federate, `signInAudience` should always be `AzureADMyOrg`.

```esp
OBJECT internal_apps
    path `applications`
    select `id,displayName,signInAudience`
OBJECT_END

STATE single_tenant
    found boolean = true
    record
        field rows.*.signInAudience string = `AzureADMyOrg`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF single_tenant
    OBJECT_REF internal_apps
CTN_END
```

---

## Caveats

- **`/applications` does NOT include consented external apps.** A Microsoft 1P app like "Exchange Online" has an SPN in your tenant but no application object — to enumerate everything the tenant trusts, query `/servicePrincipals`.
- **`requiredResourceAccess` is a *request*, not a grant.** The actual grants live on the service principal (`oauth2PermissionGrants` for delegated, `appRoleAssignments` for app permissions). Two separate object spaces, both worth discovering.
- **Phase 7 stops at the declaration.** Discovering the granted-permission objects (`oauth2PermissionGrants`, `appRoleAssignments`) — i.e. *what was actually consented to* — is a natural Phase 7+ extension under the same `Application.Read.All` permission.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Runtime side: [`m365_service_principal`](../m365_service_principal/m365_service_principal.md) — joins on `appId`
