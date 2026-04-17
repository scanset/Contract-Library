# az_virtual_network

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Virtual
Network's configuration surface via a single Azure CLI call --
`az network vnet show --name <name> --resource-group <rg>
[--subscription <id>] --output json`. Returns compliance scalars for
address space, subnet inventory with NSG/route-table/delegation analysis,
peering status, DDoS protection, DNS config, encryption, and flow log
presence, plus the full VNet document as RecordData for tag-based and
per-subnet record_checks.

The CTN never modifies any resource, never calls data-plane APIs, and
never requires any Azure permission above `Reader`. See "Non-Goals" at
the bottom for the full list of things this CTN will never do.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode)
**Collection Method:** Single Azure CLI command per object via the shared
hardened `SystemCommandExecutor`.
**Scope:** Control-plane only, read-only.

---

## Environment Variables

All Azure CTNs share a single executor factory -
`agent::contract_kit::commands::az::create_az_executor()` - wired in via
`registry.rs`. The hardened `SystemCommandExecutor` calls `env_clear()` before
spawning, so anything not explicitly re-injected is stripped. The factory
re-injects the following via `set_env_from` (each line passes through the
named var from the agent process if set, skipped silently otherwise):

| Purpose                       | Env Var(s)                                                          |
| ----------------------------- | ------------------------------------------------------------------- |
| SPN + client secret           | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`         |
| Subscription pin              | `AZURE_SUBSCRIPTION_ID`                                             |
| SPN + client certificate      | `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_CLIENT_CERTIFICATE_PASSWORD`|
| Workload identity (federated) | `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`                |
| Managed identity              | `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `MSI_ENDPOINT`, `MSI_SECRET`|
| Cached `az login`             | `HOME`, `AZURE_CONFIG_DIR`                                          |
| Python locale (az is Python)  | `LANG`, `LC_ALL`                                                    |

The factory also pins `PATH` to `/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin`
and whitelists the `az` binary (plus common absolute paths) on the executor.

`az_virtual_network` inherits this env surface unchanged - no per-CTN
overrides, no per-collector env. If `az_resource_group` can authenticate
successfully, so can `az_virtual_network`.

### Supported auth modes

| Mode                         | Required agent env                                                        |
| ---------------------------- | ------------------------------------------------------------------------- |
| SPN with client secret       | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`               |
| SPN with client certificate  | `AZURE_CLIENT_ID`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_TENANT_ID`     |
| Workload identity (federated)| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`        |
| Managed Identity             | (none - Azure VM injects `IDENTITY_ENDPOINT` automatically)               |
| Cached `az login`            | `HOME` (or `AZURE_CONFIG_DIR`) - tokens read from `~/.azure/`             |

Subscription selection precedence: `--subscription` arg on the call >
`AZURE_SUBSCRIPTION_ID` env > cached-config default.

---

## Object Fields

| Field            | Type   | Required | Description                               | Example                                 |
| ---------------- | ------ | -------- | ----------------------------------------- | --------------------------------------- |
| `name`           | string | **Yes**  | VNet name                                 | `vnet-prooflayer-demo`                  |
| `resource_group` | string | **Yes**  | Resource group that owns the VNet         | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                  | `00000000-0000-0000-0000-000000000000`  |

Both `name` and `resource_group` are required -- VNet names are only unique
within an RG, and `az network vnet show` demands `-g`. Azure performs no
client-side validation of the name: malformed inputs return
`ResourceNotFound` at runtime.

---

## Commands Executed

```
az network vnet show --name vnet-prooflayer-demo \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per VNet object. Returns all subnets, peerings, address space,
DDoS config, DNS options, flow log references, and tags inline.

**Sample response (abbreviated):**

```json
{
  "name": "vnet-prooflayer-demo",
  "id": "/subscriptions/.../virtualNetworks/vnet-prooflayer-demo",
  "type": "Microsoft.Network/virtualNetworks",
  "location": "eastus",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "provisioningState": "Succeeded",
  "addressSpace": {
    "addressPrefixes": ["10.0.0.0/16"]
  },
  "dhcpOptions": {
    "dnsServers": []
  },
  "enableDdosProtection": false,
  "privateEndpointVNetPolicies": "Disabled",
  "subnets": [
    {
      "name": "snet-private-endpoints",
      "addressPrefix": "10.0.3.0/27",
      "networkSecurityGroup": { "id": "/sub/.../nsg-snet-private-endpoints" },
      "routeTable": null,
      "delegations": [],
      "serviceEndpoints": []
    },
    {
      "name": "snet-app-gw",
      "addressPrefix": "10.0.1.0/24",
      "networkSecurityGroup": { "id": "/sub/.../nsg-snet-app-gw" }
    },
    {
      "name": "snet-private",
      "addressPrefix": "10.0.2.0/24",
      "networkSecurityGroup": { "id": "/sub/.../nsg-snet-private" }
    },
    {
      "name": "AzureBastionSubnet",
      "addressPrefix": "10.0.4.0/26",
      "networkSecurityGroup": null
    }
  ],
  "virtualNetworkPeerings": [],
  "flowLogs": [
    {
      "id": "/sub/.../flowLogs/fl-vnet-prooflayer-demo",
      "resourceGroup": "NetworkWatcherRG"
    }
  ],
  "tags": {
    "Environment": "demo",
    "FedRAMPImpactLevel": "moderate"
  }
}
```

---

## Collected Data Fields

### Scalar Fields

| Field                                  | Type    | Always Present | Source                                                    |
| -------------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`                               | boolean | Yes            | Derived - true on successful show, false on NotFound      |
| `name`                                | string  | When found     | `name`                                                    |
| `id`                                  | string  | When found     | `id`                                                      |
| `type`                                | string  | When found     | `type`                                                    |
| `location`                            | string  | When found     | `location`                                                |
| `resource_group`                      | string  | When found     | `resourceGroup`                                           |
| `provisioning_state`                  | string  | When found     | `provisioningState`                                       |
| `etag`                                | string  | When found     | `etag`                                                    |
| `address_prefix`                      | string  | When found     | First entry from `addressSpace.addressPrefixes[]`         |
| `private_endpoint_vnet_policies`      | string  | When present   | `privateEndpointVNetPolicies` (`Disabled` / `Enabled`)    |
| `encryption_enforcement`              | string  | When encryption present | `encryption.enforcement`                         |

### Boolean Fields

| Field                                  | Type    | Always Present | Source                                                    |
| -------------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `has_subnets`                          | boolean | When found     | Derived: `subnets.len() > 0`                              |
| `all_subnets_have_nsg`                 | boolean | When found     | Derived: every subnet has a non-null `networkSecurityGroup` |
| `has_custom_dns`                       | boolean | When found     | Derived: `dhcpOptions.dnsServers.len() > 0`               |
| `ddos_protection_enabled`             | boolean | When found     | `enableDdosProtection`                                    |
| `has_peerings`                         | boolean | When found     | Derived: `virtualNetworkPeerings.len() > 0`               |
| `has_flow_logs`                        | boolean | When found     | Derived: `flowLogs.len() > 0`                             |
| `encryption_enabled`                   | boolean | When encryption present | `encryption.enabled`                             |

### Integer Fields

| Field                                  | Type    | Always Present | Source                                                    |
| -------------------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `address_prefix_count`                 | integer | When found     | `addressSpace.addressPrefixes.len()`                      |
| `subnet_count`                         | integer | When found     | `subnets.len()`                                           |
| `subnets_without_nsg_count`            | integer | When found     | Subnets where `networkSecurityGroup` is null or absent    |
| `subnets_with_route_table_count`       | integer | When found     | Subnets where `routeTable` is non-null                    |
| `subnets_with_service_endpoints_count` | integer | When found     | Subnets where `serviceEndpoints[]` is non-empty           |
| `subnets_with_delegations_count`       | integer | When found     | Subnets where `delegations[]` is non-empty                |
| `peering_count`                        | integer | When found     | `virtualNetworkPeerings.len()`                            |
| `dns_server_count`                     | integer | When found     | `dhcpOptions.dnsServers.len()`                            |
| `flow_log_count`                       | integer | When found     | `flowLogs.len()`                                          |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az network vnet show` object. Empty `{}` when not found |

### Derived-field semantics

- **`all_subnets_have_nsg`** -- true when subnet_count > 0 AND every subnet
  has a non-null `networkSecurityGroup` reference. Note that
  `AzureBastionSubnet` intentionally has no NSG per Azure requirements, so
  this field will be `false` on VNets with a Bastion subnet. Use
  `subnets_without_nsg_count` for more granular control.
- **`has_custom_dns`** -- false means the VNet uses Azure-provided DNS
  (168.63.129.16). True means custom DNS servers are configured.
- **`ddos_protection_enabled`** -- false means only Azure DDoS Protection
  Basic (free tier). True means DDoS Protection Standard plan is attached.
- **`encryption_enabled`** / **`encryption_enforcement`** -- only present
  when the VNet has the `encryption` object in its response. Absent on
  older or non-encryption-enabled VNets.

---

## RecordData Structure

```
name                                         -> "vnet-prooflayer-demo"
id                                           -> "/subscriptions/.../virtualNetworks/..."
type                                         -> "Microsoft.Network/virtualNetworks"
location                                     -> "eastus"
resourceGroup                                -> "rg-prooflayer-demo-eastus"
provisioningState                            -> "Succeeded"
addressSpace.addressPrefixes[]               -> ["10.0.0.0/16"]
dhcpOptions.dnsServers[]                     -> [] | ["10.0.0.4", "10.0.0.5"]
enableDdosProtection                         -> true | false
privateEndpointVNetPolicies                  -> "Disabled" | "Enabled"
subnets[].name                               -> "snet-app-gw"
subnets[].addressPrefix                      -> "10.0.1.0/24"
subnets[].networkSecurityGroup.id            -> "/sub/.../nsg-snet-app-gw" | null
subnets[].routeTable.id                      -> "/sub/.../rt-default" | null
subnets[].delegations[]                      -> [] | [{"name": "d1", "serviceName": "..."}]
subnets[].serviceEndpoints[]                 -> [] | [{"service": "Microsoft.Storage"}]
virtualNetworkPeerings[].name                -> "peer-to-hub"
virtualNetworkPeerings[].peeringState        -> "Connected" | "Disconnected"
virtualNetworkPeerings[].allowForwardedTraffic -> true | false
virtualNetworkPeerings[].remoteVirtualNetwork.id -> "/sub/.../vnet-hub"
flowLogs[].id                                -> "/sub/.../flowLogs/fl-vnet-demo"
tags.<Key>                                   -> "<Value>"
```

Use `field <path> <type> = \`<value>\`` in `record_checks` to enforce
nested properties. Example:
`field subnets[0].name string = \`snet-app-gw\``.

---

## State Fields

| State Field                            | Type       | Allowed Operations                           | Maps To Collected Field                    |
| -------------------------------------- | ---------- | -------------------------------------------- | ------------------------------------------ |
| `found`                                | boolean    | `=`, `!=`                                    | `found`                                    |
| `name`                                 | string     | `=`, `!=`, `contains`, `starts`              | `name`                                     |
| `id`                                   | string     | `=`, `!=`, `contains`, `starts`              | `id`                                       |
| `type`                                 | string     | `=`, `!=`                                    | `type`                                     |
| `location`                             | string     | `=`, `!=`                                    | `location`                                 |
| `resource_group`                       | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                           |
| `provisioning_state`                   | string     | `=`, `!=`                                    | `provisioning_state`                       |
| `etag`                                 | string     | `=`, `!=`                                    | `etag`                                     |
| `address_prefix`                       | string     | `=`, `!=`, `contains`, `starts`              | `address_prefix`                           |
| `private_endpoint_vnet_policies`       | string     | `=`, `!=`                                    | `private_endpoint_vnet_policies`           |
| `encryption_enforcement`               | string     | `=`, `!=`                                    | `encryption_enforcement`                   |
| `has_subnets`                          | boolean    | `=`, `!=`                                    | `has_subnets`                              |
| `all_subnets_have_nsg`                 | boolean    | `=`, `!=`                                    | `all_subnets_have_nsg`                     |
| `has_custom_dns`                       | boolean    | `=`, `!=`                                    | `has_custom_dns`                           |
| `ddos_protection_enabled`              | boolean    | `=`, `!=`                                    | `ddos_protection_enabled`                  |
| `has_peerings`                         | boolean    | `=`, `!=`                                    | `has_peerings`                             |
| `has_flow_logs`                        | boolean    | `=`, `!=`                                    | `has_flow_logs`                            |
| `encryption_enabled`                   | boolean    | `=`, `!=`                                    | `encryption_enabled`                       |
| `address_prefix_count`                 | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `address_prefix_count`                     |
| `subnet_count`                         | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnet_count`                             |
| `subnets_without_nsg_count`            | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnets_without_nsg_count`                |
| `subnets_with_route_table_count`       | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnets_with_route_table_count`           |
| `subnets_with_service_endpoints_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnets_with_service_endpoints_count`     |
| `subnets_with_delegations_count`       | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnets_with_delegations_count`           |
| `peering_count`                        | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `peering_count`                            |
| `dns_server_count`                     | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `dns_server_count`                         |
| `flow_log_count`                       | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `flow_log_count`                           |
| `record`                               | RecordData | (record checks)                              | `resource`                                 |

---

## Collection Strategy

| Property                 | Value                                |
| ------------------------ | ------------------------------------ |
| Collector ID             | `az-virtual-network-collector`       |
| Collector Type           | `az_virtual_network`                 |
| Collection Mode          | Metadata                             |
| Required Capabilities    | `az_cli`, `reader`                   |
| Expected Collection Time | ~2000ms                              |
| Memory Usage             | ~2MB                                 |
| Batch Collection         | No                                   |
| Per-call Timeout         | 30s                                  |
| API Calls                | 1                                    |

---

## Required Azure Permissions

`Reader` role at subscription, RG, or VNet scope. That's all.
`az network vnet show` is a pure ARM GET; no data plane exists for
VNets, so there's no second-tier permission to elevate to.

---

## ESP Policy Examples

### Baseline -- VNet exists, subnets present, flow logs, address space

```esp
META
    esp_id `example-vnet-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-CNA-RNT`
    title `VNet baseline - subnets, flow logs, address space`
META_END

DEF
    OBJECT vnet_demo
        name `vnet-prooflayer-demo`
        resource_group `rg-prooflayer-demo-eastus`
    OBJECT_END

    STATE vnet_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        address_prefix string = `10.0.0.0/16`
        has_subnets boolean = true
        subnet_count int >= 1
        has_flow_logs boolean = true
        ddos_protection_enabled boolean = false
    STATE_END

    CRI AND
        CTN az_virtual_network
            TEST all all AND
            STATE_REF vnet_baseline
            OBJECT_REF vnet_demo
        CTN_END
    CRI_END
DEF_END
```

### NSG coverage check -- all subnets have NSGs

```esp
STATE vnet_nsg_coverage
    found boolean = true
    all_subnets_have_nsg boolean = true
    subnets_without_nsg_count int = 0
STATE_END
```

### Network isolation -- no peerings, custom DNS

```esp
STATE vnet_isolated
    found boolean = true
    has_peerings boolean = false
    peering_count int = 0
    has_custom_dns boolean = true
    dns_server_count int >= 1
STATE_END
```

### DDoS Protection Standard required

```esp
STATE vnet_ddos_protected
    found boolean = true
    ddos_protection_enabled boolean = true
STATE_END
```

### Per-subnet assertion via record_checks

```esp
STATE vnet_subnet_layout
    found boolean = true
    record
        field subnets[0].name string = `snet-private-endpoints`
        field subnets[0].addressPrefix string = `10.0.3.0/27`
        field tags.Environment string = `demo`
        field tags.FedRAMPImpactLevel string = `moderate`
    record_end
STATE_END
```

### NotFound path -- VNet must not exist

```esp
STATE vnet_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                             | Collector behavior                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| VNet does not exist (real RG + missing/malformed name)| `found=false`, `resource={}` - stderr matches `(ResourceNotFound)`  |
| RG does not exist / caller has no access              | `found=false` - stderr matches `(AuthorizationFailed)` scoped to VNet |
| `name` missing from OBJECT                            | `InvalidObjectConfiguration` - Error                               |
| `resource_group` missing from OBJECT                  | `InvalidObjectConfiguration` - Error                               |
| `az` binary missing / not authenticated               | `CollectionError::CollectionFailed` - bubbles up                    |
| Unexpected non-zero exit with non-NotFound stderr     | `CollectionError::CollectionFailed`                                 |
| Malformed JSON in stdout on success                   | `CollectionError::CollectionFailed`                                 |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr
matches either:

1. `(ResourceNotFound)` / `Code: ResourceNotFound` - covers real RG with
   missing or malformed VNet name (exit code 3).
2. `(AuthorizationFailed)` **and** the scope string contains
   `/virtualNetworks/` (case-insensitive) - covers fake or inaccessible
   RG (exit code 1). An `AuthorizationFailed` that does NOT mention
   `/virtualNetworks/` is treated as a real error, not a NotFound.

---

## Non-Goals

These are **never** in scope for this CTN:

1. **No mutation.** The CTN will never call `az network vnet create`,
   `update`, or `delete`, or any subnet/peering create/update/delete
   commands. All inspection is via `show` only.
2. **No effective-route evaluation.** `az network nic show-effective-route-table`
   requires NIC-level access and runtime VM state. If policy needs to
   reason about actual routing, that's a separate CTN.
3. **No cross-VNet correlation.** The CTN validates one VNet at a time.
   Policies needing "all VNets in subscription" semantics must enumerate
   via the policy generation layer or a future batch-mode CTN.
4. **No data-plane probing.** No connectivity tests, DNS resolution checks,
   or traffic flow analysis.

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the VNet                                      |
| `az_nsg`                          | NSGs attached to subnets within this VNet                       |
| `az_storage_account`              | Private endpoints may land in VNet subnets                      |
| `az_key_vault`                    | Network ACLs may reference VNet subnets                         |
| `az_diagnostic_setting`           | Diagnostic settings on VNet-associated resources                |
