# az_vnet_peering_list

## Overview

Parent-scoped list-mode CTN that wraps
`az network vnet peering list --resource-group <rg> --vnet-name <vnet> --output json`.
Returns one record per peering attached to the parent VNet. The
collector hoists `remoteVirtualNetwork.id` to a top-level
`remote_vnet_id` field -- the single most useful piece of data for
reconstructing the hub-spoke topology in the asset graph -- and lifts
the four boolean traffic flags (`allow_forwarded_traffic`,
`allow_gateway_transit`, `allow_virtual_network_access`,
`use_remote_gateways`) plus any non-empty `remote_address_prefixes`.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** A peering is one-directional in Azure's data model. A working
hub-spoke pair produces two records: one when scanning the hub VNet
(hub-to-spoke) and one when scanning the spoke (spoke-to-hub). The
discovery cascade naturally generates both as it iterates the VNet
inventory.

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
az network vnet peering list \
    --resource-group rg-prooflayer-platform \
    --vnet-name vnet-prooflayer-hub \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../virtualNetworks/vnet-hub/virtualNetworkPeerings/hub-to-spoke-a",
    "name": "hub-to-spoke-a",
    "type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
    "resourceGroup": "rg-prooflayer-platform",
    "peeringState": "Connected",
    "peeringSyncLevel": "FullyInSync",
    "provisioningState": "Succeeded",
    "allowForwardedTraffic": false,
    "allowGatewayTransit": true,
    "allowVirtualNetworkAccess": true,
    "useRemoteGateways": false,
    "remoteVirtualNetwork": {
      "id": "/subscriptions/.../resourceGroups/rg-spoke-a/providers/Microsoft.Network/virtualNetworks/vnet-spoke-a",
      "resourceGroup": "rg-spoke-a"
    },
    "remoteAddressSpace": {
      "addressPrefixes": ["10.20.0.0/16"]
    }
  }
]
```

---

## Collected Data Fields

### Scalar Fields

| Field           | Type    | Always Present | Source                                                                  |
| --------------- | ------- | -------------- | ----------------------------------------------------------------------- |
| `found`         | boolean | Yes            | Derived -- `true` whenever `az network vnet peering list` exits cleanly. |
| `peering_count` | integer | Yes            | Length of the returned array.                                           |

### List/Records Field

| Field      | Type       | Always Present | Description                                                                            |
| ---------- | ---------- | -------------- | -------------------------------------------------------------------------------------- |
| `peerings` | RecordData | Yes            | Projected record array. Empty `[]` if the VNet has no peerings (still `found=true`).   |

---

## Record/List Structure

| Path                                        | Type    | Example Value                                                                |
| ------------------------------------------- | ------- | ---------------------------------------------------------------------------- |
| `peerings.*.id`                             | string  | `"/subscriptions/.../virtualNetworkPeerings/hub-to-spoke-a"`                 |
| `peerings.*.name`                           | string  | `"hub-to-spoke-a"`                                                           |
| `peerings.*.type`                           | string  | `"Microsoft.Network/virtualNetworks/virtualNetworkPeerings"`                 |
| `peerings.*.resource_group`                 | string  | `"rg-prooflayer-platform"`                                                   |
| `peerings.*.peering_state`                  | string  | `"Connected"` / `"Initiated"` / `"Disconnected"`                             |
| `peerings.*.peering_sync_level`             | string  | `"FullyInSync"` / `"RemoteNotInSync"` / `"LocalNotInSync"` / `"LocalAndRemoteNotInSync"` |
| `peerings.*.provisioning_state`             | string  | `"Succeeded"`                                                                |
| `peerings.*.allow_forwarded_traffic`        | boolean | `true` or `false`                                                            |
| `peerings.*.allow_gateway_transit`          | boolean | `true` or `false`                                                            |
| `peerings.*.allow_virtual_network_access`   | boolean | `true` or `false`                                                            |
| `peerings.*.use_remote_gateways`            | boolean | `true` or `false`                                                            |
| `peerings.*.remote_vnet_id`                 | string  | `"/subscriptions/.../virtualNetworks/vnet-spoke-a"` (hoisted from `remoteVirtualNetwork.id`) |
| `peerings.*.remote_vnet_resource_group`     | string  | `"rg-spoke-a"` (hoisted from `remoteVirtualNetwork.resourceGroup`)           |
| `peerings.*.remote_address_prefixes[]`      | array   | `["10.20.0.0/16"]` (present only when non-empty)                             |

---

## State Fields

| State Field     | Type       | Allowed Operations              | Maps To Collected Field |
| --------------- | ---------- | ------------------------------- | ----------------------- |
| `found`         | boolean    | `=`, `!=`                       | `found`                 |
| `peering_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `peering_count`         |
| `peerings`      | RecordData | (record checks)                 | `peerings`              |

---

## Collection Strategy

| Property                     | Value                            |
| ---------------------------- | -------------------------------- |
| Collector ID                 | `az-vnet-peering-list-collector` |
| Collector Type               | `az_vnet_peering_list`           |
| Collection Mode              | Metadata                         |
| Required Capabilities        | `az_cli`, `reader`               |
| Expected Collection Time     | ~2000ms                          |
| Memory Usage                 | ~1MB                             |
| Network Intensive            | Yes                              |
| CPU Intensive                | No                               |
| Requires Elevated Privileges | No                               |
| Batch Collection             | No                               |
| Per-call Timeout             | 30s                              |

---

## Required Azure Permissions

`Reader` role at the parent VNet scope. Listing peerings requires
`Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read`,
carried by `Reader`.

---

## ESP Examples

### Every peering on the hub must be Connected and FullyInSync

```esp
OBJECT hub_peerings
    resource_group `rg-prooflayer-platform`
    vnet_name `vnet-prooflayer-hub`
OBJECT_END

STATE peerings_healthy
    found boolean = true
    record
        field peerings.*.peering_state string = `Connected`
        field peerings.*.peering_sync_level string = `FullyInSync`
    record_end
STATE_END

CTN az_vnet_peering_list
    TEST all all AND
    STATE_REF peerings_healthy
    OBJECT_REF hub_peerings
CTN_END
```

### No peering may allow forwarded traffic (transit denied)

```esp
OBJECT hub_peerings
    resource_group `rg-prooflayer-platform`
    vnet_name `vnet-prooflayer-hub`
OBJECT_END

STATE no_transit_forwarding
    found boolean = true
    record
        field peerings.*.allow_forwarded_traffic boolean = false
    record_end
STATE_END

CTN az_vnet_peering_list
    TEST all all AND
    STATE_REF no_transit_forwarding
    OBJECT_REF hub_peerings
CTN_END
```

### Hub VNet must have exactly the expected number of spokes

```esp
STATE expected_spoke_count
    found boolean = true
    peering_count int = 3
STATE_END
```

---

## Error Conditions

| Condition                                       | Error Type              | Outcome                       |
| ----------------------------------------------- | ----------------------- | ----------------------------- |
| VNet has zero peerings                          | N/A (not an error)      | `found=true`, `peering_count=0` |
| `resource_group` missing from OBJECT            | `CollectionFailed`      | Error                         |
| `vnet_name` missing from OBJECT                 | `CollectionFailed`      | Error                         |
| Parent VNet does not exist / no access          | `CollectionFailed`      | Error                         |
| `az` binary missing / not authenticated         | `CollectionFailed`      | Error                         |
| Stdout is not a JSON array                      | `CollectionFailed`      | Error                         |
| Stdout is not valid JSON                        | `CollectionFailed`      | Error                         |
| Incompatible CTN type                           | `CtnContractValidation` | Error                         |

---

## Related CTN Types

| CTN Type             | Relationship                                                                            |
| -------------------- | --------------------------------------------------------------------------------------- |
| `az_virtual_network` | Parent typed CTN -- the VNet whose `resource_group` and `name` feed this list.          |
| `az_subnet_list`     | Sibling list on the same parent VNet -- enumerates subnets.                             |
| `az_resource_list`   | Discovery feed -- each VNet in `az_resource_list` triggers one `az_vnet_peering_list`.  |
