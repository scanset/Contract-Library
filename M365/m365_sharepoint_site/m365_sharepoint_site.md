# m365_sharepoint_site

## Overview

Resource-shape reference for a SharePoint site discovered via `m365_graph_query` against `/sites?search=*`. **Not a standalone CTN** — `m365_graph_query` handles all Graph collections.

**Important:** Graph's `/sites` endpoint does **not** return all tenant sites by default — without the `?search=*` query parameter it only returns the root site collection. Using `search=*` is the documented pattern for enumerating sites the SPN can read tenant-wide; `Sites.Read.All` is required for the result to include non-root sites.

Discovery covers team sites, communication sites, and OneDrive (personal) site collections that surface through the same endpoint.

**Platform:** Microsoft Graph
**Underlying CTN:** [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
**Asset type:** `M365::SharePointSite`
**Required permission:** `Sites.Read.All` (application, admin consent)

---

## Object Fields

| Field    | Type   | Required | Description                                                                  | Example                                                            |
| -------- | ------ | -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `path`   | string | **Yes**  | Must be `sites?search=*` to enumerate tenant-wide.                           | `sites?search=*`                                                   |
| `select` | string | No       | Reduce payload — site objects can be large.                                  | `id,displayName,name,webUrl,createdDateTime,lastModifiedDateTime`  |
| `filter` | string | No       | OData `$filter`. Not commonly used here.                                     | (none)                                                             |

---

## Commands Executed

```
GET https://graph.microsoft.com/v1.0/sites?search=*&$select=id,displayName,name,webUrl,createdDateTime,lastModifiedDateTime&$top=999
Authorization: Bearer <token>
ConsistencyLevel: eventual
```

**Sample response (single site):**

```json
{
  "id": "contoso.sharepoint.com,11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222",
  "displayName": "Finance",
  "name": "Finance",
  "webUrl": "https://contoso.sharepoint.com/sites/Finance",
  "createdDateTime": "2024-01-15T08:00:00Z",
  "lastModifiedDateTime": "2026-05-08T14:00:00Z",
  "siteCollection": {
    "hostname": "contoso.sharepoint.com"
  }
}
```

The site `id` is a **composite** string: `{hostname},{site collection id},{web id}`. Use it as-is when calling deeper site endpoints (drives, lists, etc) — Graph parses it back internally.

---

## Collected Data Fields

Inside `rows.*`:

| Field                                | Type    | Description                                                                              |
| ------------------------------------ | ------- | ---------------------------------------------------------------------------------------- |
| `rows.*.id`                          | string  | Composite site id.                                                                       |
| `rows.*.displayName`                 | string  | Site title shown in SharePoint nav.                                                      |
| `rows.*.name`                        | string  | URL-safe site name (last segment of the path).                                           |
| `rows.*.webUrl`                      | string  | Absolute site URL.                                                                       |
| `rows.*.createdDateTime`             | string  | ISO-8601.                                                                                |
| `rows.*.lastModifiedDateTime`        | string  | ISO-8601; last content change.                                                           |
| `rows.*.siteCollection.hostname`     | string  | Tenant SharePoint hostname.                                                              |

---


## ESP Examples

### Every site must be under the official tenant hostname

```esp
OBJECT all_sites
    path `sites?search=*`
    select `id,displayName,webUrl,siteCollection`
OBJECT_END

STATE on_tenant_host
    found boolean = true
    record
        field rows.*.siteCollection.hostname string = `contoso.sharepoint.com`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF on_tenant_host
    OBJECT_REF all_sites
CTN_END
```

### No site name should contain "test" or "demo" in production

```esp
OBJECT prod_sites
    path `sites?search=*`
    select `id,displayName,name,webUrl`
OBJECT_END

STATE no_test_sites
    found boolean = true
    record
        field rows.*.name string != `test`
        field rows.*.name string != `demo`
    record_end
STATE_END

CTN m365_graph_query
    TEST all all AND
    STATE_REF no_test_sites
    OBJECT_REF prod_sites
CTN_END
```

---

## Caveats

- **Visibility scope.** `Sites.Read.All` lets the SPN see every site, but Microsoft Graph's `/sites?search=*` is search-indexed — newly-created sites may take a few hours to appear. For tenant-fresh validation, give the search index time to catch up before asserting on counts.
- **OneDrive sites.** Personal OneDrive sites *are* included in the search results — they show up with hostnames like `contoso-my.sharepoint.com`. Filter explicitly if you want to exclude them.

---

## Related

- CTN: [`m365_graph_query`](../m365_graph_query/m365_graph_query.md)
- Collaboration sibling: [`m365_team`](../m365_team/m365_team.md)
