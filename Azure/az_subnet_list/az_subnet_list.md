# az_subnet_list

## Overview

Parent-scoped list-mode CTN that wraps
`az network vnet subnet list --resource-group <rg> --vnet-name <vnet> --output json`.
Returns one record per subnet on the parent VNet. Used by the discovery
cascade -- after each VNet is discovered via `az_resource_list`, this
CTN is dispatched once per VNet to enumerate its subnets. Each
projected record carries the address prefix, provisioning state,
private-endpoint / private-link-service network policies, and the
`defaultOutboundAccess` flag (Azure's deprecation gate for implicit
internet egress).

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** Because this CTN is parent-scoped, it is invoked once per VNet
in a typical scan. The `delegations` and `serviceEndpoints` arrays are
surfaced only when non-empty -- they're absent on the projected record
for plain unlinked subnets.

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

| Field            | Type   | Required | Description                                                                              | Example                                |
| ---------------- | ------ | -------- | ---------------------------------------------------------------------------------------- | -------------------------------------- |
| `resource_group` | string | **Yes**  | Resource group of the parent VNet.                                                       | `rg-prooflayer-platform`               |
| `vnet_name`      | string | **Yes**  | Parent VNet name.                                                                        | `vnet-prooflayer-hub`                  |
| `subscription`   | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent. | `00000000-0000-0000-0000-000000000000` |

---

## Commands Executed

```
az network vnet subnet list \
    --resource-group rg-prooflayer-platform \
    --vnet-name vnet-prooflayer-hub \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../virtualNetworks/vnet-prooflayer-hub/subnets/snet-app",
    "name": "snet-app",
    "type": "Microsoft.Network/virtualNetworks/subnets",
    "resourceGroup": "rg-prooflayer-platform",
    "addressPrefix": "10.10.1.0/24",
    "provisioningState": "Succeeded",
    "privateEndpointNetworkPolicies": "Disabled",
    "privateLinkServiceNetworkPolicies": "Enabled",
    "defaultOutboundAccess": false,
    "delegations": [],
    "serviceEndpoints": []
  }
]
```

---

## Collected Data Fields

### Scalar Fields

| Field          | Type    | Always Present | Source                                                               |
| -------------- | ------- | -------------- | -------------------------------------------------------------------- |
| `found`        | boolean | Yes            | Derived -- `true` whenever `az network vnet subnet list` exits cleanly. |
| `subnet_count` | integer | Yes            | Length of the returned array.                                        |

### List/Records Field

| Field     | Type       | Always Present | Description                                                                         |
| --------- | ---------- | -------------- | ----------------------------------------------------------------------------------- |
| `subnets` | RecordData | Yes            | Projected record array. Empty `[]` if the VNet has no subnets (still `found=true`). |

---

## Record/List Structure

| Path                                                 | Type    | Example Value                                                              |
| ---------------------------------------------------- | ------- | -------------------------------------------------------------------------- |
| `subnets.*.id`                                       | string  | `"/subscriptions/.../virtualNetworks/vnet-hub/subnets/snet-app"`           |
| `subnets.*.name`                                     | string  | `"snet-app"`                                                               |
| `subnets.*.type`                                     | string  | `"Microsoft.Network/virtualNetworks/subnets"`                              |
| `subnets.*.resource_group`                           | string  | `"rg-prooflayer-platform"`                                                 |
| `subnets.*.address_prefix`                           | string  | `"10.10.1.0/24"`                                                           |
| `subnets.*.provisioning_state`                       | string  | `"Succeeded"`                                                              |
| `subnets.*.private_endpoint_network_policies`        | string  | `"Disabled"` or `"Enabled"`                                                |
| `subnets.*.private_link_service_network_policies`    | string  | `"Disabled"` or `"Enabled"`                                                |
| `subnets.*.default_outbound_access`                  | boolean | `true` (legacy default) or `false` (Azure's hardened default)              |
| `subnets.*.delegations[]`                            | array   | Present only when non-empty                                                |
| `subnets.*.service_endpoints[]`                      | array   | Present only when non-empty                                                |

---

## State Fields

| State Field    | Type       | Allowed Operations              | Maps To Collected Field |
| -------------- | ---------- | ------------------------------- | ----------------------- |
| `found`        | boolean    | `=`, `!=`                       | `found`                 |
| `subnet_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `subnet_count`          |
| `subnets`      | RecordData | (record checks)                 | `subnets`               |

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `az-subnet-list-collector`     |
| Collector Type               | `az_subnet_list`               |
| Collection Mode              | Metadata                       |
| Required Capabilities        | `az_cli`, `reader`             |
| Expected Collection Time     | ~2000ms                        |
| Memory Usage                 | ~1MB                           |
| Network Intensive            | Yes                            |
| CPU Intensive                | No                             |
| Requires Elevated Privileges | No                             |
| Batch Collection             | No                             |
| Per-call Timeout             | 30s                            |

---

## Required Azure Permissions

`Reader` role at the parent VNet scope (or any inherited scope --
RG, subscription). Listing subnets requires
`Microsoft.Network/virtualNetworks/subnets/read`, carried by `Reader`.

---

## ESP Examples

### Every subnet must explicitly opt out of default outbound access

```esp
OBJECT hub_subnets
    resource_group `rg-prooflayer-platform`
    vnet_name `vnet-prooflayer-hub`
OBJECT_END

STATE no_implicit_egress
    found boolean = true
    record
        field subnets.*.default_outbound_access boolean = false
    record_end
STATE_END

CTN az_subnet_list
    TEST all all AND
    STATE_REF no_implicit_egress
    OBJECT_REF hub_subnets
CTN_END
```

### Hub VNet must have at least one subnet, all in Succeeded state

```esp
OBJECT hub_subnets
    resource_group `rg-prooflayer-platform`
    vnet_name `vnet-prooflayer-hub`
OBJECT_END

STATE subnets_healthy
    found boolean = true
    subnet_count int >= 1
    record
        field subnets.*.provisioning_state string = `Succeeded`
    record_end
STATE_END

CTN az_subnet_list
    TEST all all AND
    STATE_REF subnets_healthy
    OBJECT_REF hub_subnets
CTN_END
```

### Private-endpoint network policies must be disabled on app subnet

```esp
OBJECT app_subnet_scope
    resource_group `rg-prooflayer-platform`
    vnet_name `vnet-prooflayer-hub`
OBJECT_END

STATE pe_policies_disabled
    found boolean = true
    record
        field subnets.0.name string = `snet-app`
        field subnets.0.private_endpoint_network_policies string = `Disabled`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                                       | Error Type              | Outcome                       |
| ----------------------------------------------- | ----------------------- | ----------------------------- |
| VNet has zero subnets                           | N/A (not an error)      | `found=true`, `subnet_count=0` |
| `resource_group` missing from OBJECT            | `CollectionFailed`      | Error                         |
| `vnet_name` missing from OBJECT                 | `CollectionFailed`      | Error                         |
| Parent VNet does not exist / no access          | `CollectionFailed`      | Error (`ResourceNotFound` / `AuthorizationFailed` in stderr) |
| `az` binary missing / not authenticated         | `CollectionFailed`      | Error                         |
| Stdout is not a JSON array                      | `CollectionFailed`      | Error                         |
| Stdout is not valid JSON                        | `CollectionFailed`      | Error                         |
| Incompatible CTN type                           | `CtnContractValidation` | Error                         |

Note: unlike single-resource CTNs (`az_resource_group`, `az_virtual_machine`),
this CTN does **not** soft-fail on parent VNet not-found -- a missing
parent surfaces as a real `CollectionFailed`, since the cascade
shouldn't be dispatching against ghost VNets in the first place.

---

## Related CTN Types

| CTN Type                | Relationship                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `az_virtual_network`    | Parent typed CTN -- the VNet whose `resource_group` and `name` feed this list.              |
| `az_vnet_peering_list`  | Sibling list on the same parent VNet -- enumerates peerings (cross-VNet links).             |
| `az_nsg_rule_list`      | Companion list -- subnets often have an attached NSG whose rules need separate enumeration. |
| `az_resource_list`      | Discovery feed -- each VNet in `az_resource_list` triggers one `az_subnet_list` cascade.    |
