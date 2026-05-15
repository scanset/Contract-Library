# az_nsg_rule_list

## Overview

Parent-scoped list-mode CTN that wraps
`az network nsg rule list --resource-group <rg> --nsg-name <nsg> --output json`.
Returns one record per **custom** security rule on the parent NSG.
Default rules (`AllowVnetInBound`, `DenyAllInBound`,
`AllowAzureLoadBalancerInBound`, etc.) are not returned by this command
-- those live on the parent NSG's `defaultSecurityRules` array, which
this CTN does not capture (a future `az_nsg_default_rule_list` would
cover them if needed).

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via
any supported mode)
**Collection Method:** Single Azure CLI command via the shared hardened
`SystemCommandExecutor`.

**Note:** Multi-value prefix and port-range arrays
(`destinationAddressPrefixes`, `destinationPortRanges`,
`sourceAddressPrefixes`, `sourcePortRanges`) are surfaced only when
non-empty. Single-value rules use the singular `*_prefix` /
`*_port_range` fields; multi-value rules use the plural arrays. Most
record_checks should branch on whichever shape applies.

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
| `resource_group` | string | **Yes**  | Resource group of the parent NSG.                                                        | `rg-prooflayer-tenant-b`               |
| `nsg_name`       | string | **Yes**  | Parent NSG name.                                                                         | `nsg-prooflayer-tenant-b`              |
| `subscription`   | string | opt      | Subscription ID override -- uses `AZURE_SUBSCRIPTION_ID` env or cached default if absent. | `00000000-0000-0000-0000-000000000000` |

---

## Commands Executed

```
az network nsg rule list \
    --resource-group rg-prooflayer-tenant-b \
    --nsg-name nsg-prooflayer-tenant-b \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

**Sample response (abbreviated):**

```json
[
  {
    "id": "/subscriptions/.../networkSecurityGroups/nsg-prooflayer-tenant-b/securityRules/allow-https-from-cf",
    "name": "allow-https-from-cf",
    "type": "Microsoft.Network/networkSecurityGroups/securityRules",
    "resourceGroup": "rg-prooflayer-tenant-b",
    "access": "Allow",
    "direction": "Inbound",
    "priority": 1000,
    "protocol": "Tcp",
    "provisioningState": "Succeeded",
    "destinationAddressPrefix": "*",
    "destinationPortRange": "443",
    "sourceAddressPrefix": "AzureFrontDoor.Backend",
    "sourcePortRange": "*",
    "destinationAddressPrefixes": [],
    "destinationPortRanges": [],
    "sourceAddressPrefixes": [],
    "sourcePortRanges": []
  }
]
```

---

## Collected Data Fields

### Scalar Fields

| Field        | Type    | Always Present | Source                                                              |
| ------------ | ------- | -------------- | ------------------------------------------------------------------- |
| `found`      | boolean | Yes            | Derived -- `true` whenever `az network nsg rule list` exits cleanly. |
| `rule_count` | integer | Yes            | Length of the returned array (custom rules only -- excludes defaults). |

### List/Records Field

| Field   | Type       | Always Present | Description                                                                       |
| ------- | ---------- | -------------- | --------------------------------------------------------------------------------- |
| `rules` | RecordData | Yes            | Projected record array. Empty `[]` when the NSG has no custom rules.              |

---

## Record/List Structure

| Path                                      | Type    | Example Value                                                          |
| ----------------------------------------- | ------- | ---------------------------------------------------------------------- |
| `rules.*.id`                              | string  | `"/subscriptions/.../securityRules/allow-https-from-cf"`               |
| `rules.*.name`                            | string  | `"allow-https-from-cf"`                                                |
| `rules.*.type`                            | string  | `"Microsoft.Network/networkSecurityGroups/securityRules"`              |
| `rules.*.resource_group`                  | string  | `"rg-prooflayer-tenant-b"`                                             |
| `rules.*.access`                          | string  | `"Allow"` or `"Deny"`                                                  |
| `rules.*.direction`                       | string  | `"Inbound"` or `"Outbound"`                                            |
| `rules.*.priority`                        | integer | `1000` (Azure range: 100--4096)                                        |
| `rules.*.protocol`                        | string  | `"Tcp"`, `"Udp"`, `"Icmp"`, `"*"`                                      |
| `rules.*.provisioning_state`              | string  | `"Succeeded"`                                                          |
| `rules.*.destination_address_prefix`      | string  | `"*"` or a CIDR or service tag (single-value rules)                    |
| `rules.*.destination_port_range`          | string  | `"443"`, `"80-8080"`, `"*"` (single-value rules)                       |
| `rules.*.source_address_prefix`           | string  | `"AzureFrontDoor.Backend"`, `"10.0.0.0/8"`, `"*"` (single-value rules) |
| `rules.*.source_port_range`               | string  | `"*"` (single-value rules)                                             |
| `rules.*.destination_address_prefixes[]`  | array   | `["10.0.0.0/8", "172.16.0.0/12"]` (multi-value rules; absent when empty) |
| `rules.*.destination_port_ranges[]`       | array   | `["443", "8443"]` (multi-value rules; absent when empty)               |
| `rules.*.source_address_prefixes[]`       | array   | `["1.2.3.4/32", "5.6.7.8/32"]` (multi-value rules; absent when empty)  |
| `rules.*.source_port_ranges[]`            | array   | `["80", "443"]` (multi-value rules; absent when empty)                 |

---

## State Fields

| State Field  | Type       | Allowed Operations              | Maps To Collected Field |
| ------------ | ---------- | ------------------------------- | ----------------------- |
| `found`      | boolean    | `=`, `!=`                       | `found`                 |
| `rule_count` | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=` | `rule_count`            |
| `rules`      | RecordData | (record checks)                 | `rules`                 |

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `az-nsg-rule-list-collector`   |
| Collector Type               | `az_nsg_rule_list`             |
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

`Reader` role at the parent NSG scope. Listing rules requires
`Microsoft.Network/networkSecurityGroups/securityRules/read`,
carried by `Reader`.

---

## ESP Examples

### No NSG rule may permit inbound SSH (port 22) from the internet

```esp
OBJECT tenant_b_nsg
    resource_group `rg-prooflayer-tenant-b`
    nsg_name `nsg-prooflayer-tenant-b`
OBJECT_END

STATE no_open_ssh
    found boolean = true
    record
        field rules.*.destination_port_range string != `22`
        field rules.*.source_address_prefix string != `0.0.0.0/0`
        field rules.*.source_address_prefix string != `*`
        field rules.*.source_address_prefix string != `Internet`
    record_end
STATE_END

CTN az_nsg_rule_list
    TEST all all AND
    STATE_REF no_open_ssh
    OBJECT_REF tenant_b_nsg
CTN_END
```

### No inbound Allow rule may use a wildcard source

```esp
OBJECT tenant_b_nsg
    resource_group `rg-prooflayer-tenant-b`
    nsg_name `nsg-prooflayer-tenant-b`
OBJECT_END

STATE no_wildcard_inbound_allow
    found boolean = true
    record
        field rules.*.direction string = `Inbound`
        field rules.*.access string = `Allow`
        field rules.*.source_address_prefix string != `*`
    record_end
STATE_END

CTN az_nsg_rule_list
    TEST all all AND
    STATE_REF no_wildcard_inbound_allow
    OBJECT_REF tenant_b_nsg
CTN_END
```

### NSG must have at least one explicit Deny rule (defense in depth)

```esp
STATE has_explicit_deny
    found boolean = true
    rule_count int >= 1
    record
        field rules.0.access string = `Deny`
    record_end
STATE_END
```

---

## Error Conditions

| Condition                                       | Error Type              | Outcome                     |
| ----------------------------------------------- | ----------------------- | --------------------------- |
| NSG has zero custom rules (defaults only)       | N/A (not an error)      | `found=true`, `rule_count=0` |
| `resource_group` missing from OBJECT            | `CollectionFailed`      | Error                       |
| `nsg_name` missing from OBJECT                  | `CollectionFailed`      | Error                       |
| Parent NSG does not exist / no access           | `CollectionFailed`      | Error                       |
| `az` binary missing / not authenticated         | `CollectionFailed`      | Error                       |
| Stdout is not a JSON array                      | `CollectionFailed`      | Error                       |
| Stdout is not valid JSON                        | `CollectionFailed`      | Error                       |
| Incompatible CTN type                           | `CtnContractValidation` | Error                       |

---

## Related CTN Types

| CTN Type           | Relationship                                                                                |
| ------------------ | ------------------------------------------------------------------------------------------- |
| `az_nsg`           | Parent typed CTN -- the NSG whose `resource_group` and `name` feed this list.               |
| `az_subnet_list`   | Companion list -- subnets referencing this NSG via their `networkSecurityGroup.id`.         |
| `az_resource_list` | Discovery feed -- each NSG in `az_resource_list` triggers one `az_nsg_rule_list` cascade.   |
