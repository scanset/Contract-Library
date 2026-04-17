# az_nsg

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Network
Security Group's configuration surface via a single Azure CLI call —
`az network nsg show --name <name> --resource-group <rg>
[--subscription <id>] --output json`. Returns compliance scalars
(provisioning state, attachment posture, per-direction rule counts, internet
exposure) plus the full NSG document as RecordData for tag-based and
per-rule record_checks.

The CTN never calls any data-plane API (NSGs have none), never creates or
modifies rules, and never requires any Azure permission above `Reader`.
See "Non-Goals" at the bottom for the full list of things this CTN will
never do.

**Platform:** Azure (requires `az` CLI binary on PATH, authenticated via any
supported mode — see `az_resource_group.md` for the full env-var matrix)
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

`az_nsg` inherits this env surface unchanged - no per-CTN overrides, no
per-collector env. If `az_resource_group` can authenticate successfully, so
can `az_nsg`.

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
| `name`           | string | **Yes**  | NSG name                                  | `nsg-snet-app-gw`                       |
| `resource_group` | string | **Yes**  | Resource group that owns the NSG          | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                  | `00000000-0000-0000-0000-000000000000`  |

Both `name` and `resource_group` are required -- NSG names are only unique
within an RG, and `az network nsg show` demands `-g`. Azure performs no
client-side validation of the name: malformed inputs return
`ResourceNotFound` at runtime.

### Behavior Modifiers

| Behavior                      | Type | Default | Description                                          |
| ----------------------------- | ---- | ------- | ---------------------------------------------------- |
| `include_flow_log_status`     | bool | false   | Triggers a second API call to `az network watcher flow-log list --location <loc>` to check flow log status for this NSG |

When `behavior include_flow_log_status true` is set on an OBJECT, the
collector makes an additional call after the base `az network nsg show`. This
populates up to 5 additional fields (see Behavior-Gated Fields below). If
the second call fails, those fields stay absent and any STATE assertions
against them produce Error (field missing) -- the base collection still
succeeds.

**Note:** The flow log query requires `Network Contributor` or equivalent
role on the Network Watcher resource. If the scanner only has `Reader`, the
behavior-gated call will fail silently (non-fatal).

---

## Commands Executed

### Base command (always)

```
az network nsg show --name nsg-snet-app-gw \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per NSG object. Returns all rules, default rules, subnet bindings,
NIC bindings, and tags inline. No per-rule follow-up call is needed --
`az network nsg rule list` was cross-checked during discovery and returns
the same rule shape as the nested `securityRules[]` array.

### Behavior-gated command (when `include_flow_log_status` is true)

```
az network watcher flow-log list \
    --location eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

Returns all flow log configs in the region. The collector matches
`targetResourceId` (case-insensitive) against the NSG's full ARM ID to
find the relevant flow log entry.

---

## Collected Data Fields (scalars)

| Field                          | Type    | Source                                                | Notes                                                                       |
| ------------------------------ | ------- | ----------------------------------------------------- | --------------------------------------------------------------------------- |
| `found`                        | bool    | Exit-code + stderr                                    | `true` on 0; `false` on `ResourceNotFound` or `AuthorizationFailed`/NSG     |
| `name`                         | string  | `name`                                                |                                                                             |
| `id`                           | string  | `id`                                                  | Full ARM ID                                                                 |
| `type`                         | string  | `type`                                                | Always `Microsoft.Network/networkSecurityGroups`                            |
| `location`                     | string  | `location`                                            | Azure region                                                                |
| `resource_group`               | string  | `resourceGroup`                                       |                                                                             |
| `provisioning_state`           | string  | `provisioningState`                                   | `Succeeded`, `Updating`, `Deleting`, etc.                                   |
| `resource_guid`                | string  | `resourceGuid`                                        |                                                                             |
| `etag`                         | string  | `etag`                                                | Changes on every NSG update                                                 |
| `security_rule_count`          | int     | `securityRules.len()`                                 | Custom rule count                                                           |
| `default_security_rule_count`  | int     | `defaultSecurityRules.len()`                          | Always 6 (Azure-fixed)                                                      |
| `subnet_binding_count`         | int     | `subnets.len()`                                       |                                                                             |
| `nic_binding_count`            | int     | `networkInterfaces.len()`                             | 0 when field absent                                                         |
| `inbound_allow_count`          | int     | derived from `securityRules`                          | direction=Inbound, access=Allow                                             |
| `inbound_deny_count`           | int     | derived                                               | direction=Inbound, access=Deny                                              |
| `outbound_allow_count`         | int     | derived                                               |                                                                             |
| `outbound_deny_count`          | int     | derived                                               |                                                                             |
| `has_custom_rules`             | bool    | derived: `security_rule_count > 0`                    |                                                                             |
| `has_subnet_bindings`          | bool    | derived: `subnet_binding_count > 0`                   |                                                                             |
| `has_nic_bindings`             | bool    | derived: `nic_binding_count > 0`                      |                                                                             |
| `is_attached`                  | bool    | derived: `(subnet+nic) > 0`                           | Composite attachment signal                                                 |
| `has_internet_inbound_allow`   | bool    | derived from `securityRules`                          | Any Inbound Allow with source in {`Internet`, `*`, `0.0.0.0/0`}             |
| `has_ssh_open_to_internet`     | bool    | derived from `securityRules`                          | Any Inbound Allow exposing port 22 from internet source                     |
| `has_rdp_open_to_internet`     | bool    | derived from `securityRules`                          | Any Inbound Allow exposing port 3389 from internet source                   |
| `has_all_ports_open_to_internet`| bool   | derived from `securityRules`                          | Any Inbound Allow with dest port `*` from internet source                   |
| `total_rule_count`             | int     | derived: `security_rule_count + default_security_rule_count` | Combined custom + Azure default rules                              |

### Behavior-Gated Fields (require `behavior include_flow_log_status true`)

These fields are only populated when the OBJECT includes `behavior include_flow_log_status true`.
They come from the second API call to `az network watcher flow-log list`.

| Field                                  | Type    | Source                                             | Notes                                      |
| -------------------------------------- | ------- | -------------------------------------------------- | ------------------------------------------ |
| `flow_log_enabled`                     | bool    | `enabled` on matching flow log entry               | `false` when no flow log config found      |
| `flow_log_retention_enabled`           | bool    | `retentionPolicy.enabled`                          | Whether retention policy is active         |
| `flow_log_retention_days`              | int     | `retentionPolicy.days`                             | Absent when retention not configured       |
| `flow_log_traffic_analytics_enabled`   | bool    | `flowAnalyticsConfiguration...enabled`             | Whether Traffic Analytics is on            |
| `flow_log_analytics_interval_minutes`  | int     | `flowAnalyticsConfiguration...trafficAnalyticsInterval` | Typically 10 or 60                   |

### Derived-field semantics

- **`has_internet_inbound_allow`** -- scans custom rules only (`securityRules[]`),
  not defaults. Checks both the singular `sourceAddressPrefix` and the
  plural `sourceAddressPrefixes[]` array. Azure's defaults never contain
  an inbound internet allow, so the custom-rule scope is sufficient for a
  "did the operator punch a hole in the perimeter" check.
- **`has_ssh_open_to_internet`** -- checks destination port for port 22 match.
  Handles single ports (`"22"`), ranges containing 22 (`"20-25"`), and
  wildcard (`"*"`). Same internet-source detection as `has_internet_inbound_allow`.
- **`has_rdp_open_to_internet`** -- same logic as SSH but for port 3389.
- **`has_all_ports_open_to_internet`** -- only matches the literal wildcard `*`
  on destination port, not large ranges like `1-65535`. This is deliberate:
  an explicit `*` signals "allow everything" intent, while a range may be a
  misconfigured but narrower intent.
- **`is_attached`** -- true when the NSG is bound to at least one subnet OR
  at least one NIC. An unattached NSG is effectively dead config.
- **`has_custom_rules`** -- distinguishes "operator put work into this NSG"
  from "NSG exists with only the 6 Azure defaults".

---

## RecordData Structure

The full `az network nsg show` JSON is exposed as the `resource` field,
castable to `RecordData`. Use `record_checks` in ESP policies to assert on:

- Per-rule fields: `field securityRules[?name==\`AllowHTTPS\`].access string = \`Allow\``
- Default rule priorities: `field defaultSecurityRules[?name==\`DenyAllInBound\`].priority int = 65500`
- Tag values: `field tags.Environment string = \`demo\``
- Subnet bindings: `field subnets[0].id string contains \`snet-app-gw\``

### Rule-object shape (both `securityRules[]` and `defaultSecurityRules[]`)

| Field                            | Type            | Notes                                                      |
| -------------------------------- | --------------- | ---------------------------------------------------------- |
| `name`                           | string          |                                                            |
| `priority`                       | int             | 100-4096 for custom; 65000-65500 for defaults              |
| `direction`                      | string          | `Inbound` or `Outbound`                                    |
| `access`                         | string          | `Allow` or `Deny`                                          |
| `protocol`                       | string          | `Tcp`, `Udp`, `Icmp`, `Esp`, `Ah`, `*`                     |
| `sourceAddressPrefix`            | string / null   | Singular form - set when no prefixes array                 |
| `sourceAddressPrefixes`          | string array    | Plural form - empty `[]` when singular is set              |
| `destinationAddressPrefix`       | string / null   | Same singular/plural pattern                               |
| `destinationAddressPrefixes`     | string array    |                                                            |
| `sourcePortRange`                | string / null   |                                                            |
| `sourcePortRanges`               | string array    |                                                            |
| `destinationPortRange`           | string / null   | Can be single port (`80`), range (`65200-65535`), or `*`   |
| `destinationPortRanges`          | string array    |                                                            |
| `provisioningState`              | string          |                                                            |
| `description`                    | string / absent | Present on defaults; may be absent on custom rules         |

**Singular/plural gotcha:** Azure uses two mutually-exclusive forms for
every prefix/port field. When one is set, the other is an empty array (or
null). Policies asserting on address prefixes must check both forms, or
use a JMESPath-ish record_check that covers both.

---

## State Fields (for ESP STATE blocks)

| State Field                            | Type       | Allowed Operations                           | Maps To Collected Field                    |
| -------------------------------------- | ---------- | -------------------------------------------- | ------------------------------------------ |
| `found`                                | boolean    | `=`, `!=`                                    | `found`                                    |
| `name`                                 | string     | `=`, `!=`, `contains`, `starts`              | `name`                                     |
| `id`                                   | string     | `=`, `!=`, `contains`, `starts`              | `id`                                       |
| `type`                                 | string     | `=`, `!=`                                    | `type`                                     |
| `location`                             | string     | `=`, `!=`                                    | `location`                                 |
| `resource_group`                       | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                           |
| `provisioning_state`                   | string     | `=`, `!=`                                    | `provisioning_state`                       |
| `resource_guid`                        | string     | `=`, `!=`                                    | `resource_guid`                            |
| `etag`                                 | string     | `=`, `!=`                                    | `etag`                                     |
| `has_subnet_bindings`                  | boolean    | `=`, `!=`                                    | `has_subnet_bindings`                      |
| `has_nic_bindings`                     | boolean    | `=`, `!=`                                    | `has_nic_bindings`                         |
| `is_attached`                          | boolean    | `=`, `!=`                                    | `is_attached`                              |
| `has_custom_rules`                     | boolean    | `=`, `!=`                                    | `has_custom_rules`                         |
| `has_internet_inbound_allow`           | boolean    | `=`, `!=`                                    | `has_internet_inbound_allow`               |
| `has_ssh_open_to_internet`             | boolean    | `=`, `!=`                                    | `has_ssh_open_to_internet`                 |
| `has_rdp_open_to_internet`             | boolean    | `=`, `!=`                                    | `has_rdp_open_to_internet`                 |
| `has_all_ports_open_to_internet`       | boolean    | `=`, `!=`                                    | `has_all_ports_open_to_internet`           |
| `security_rule_count`                  | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `security_rule_count`                      |
| `default_security_rule_count`          | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `default_security_rule_count`              |
| `subnet_binding_count`                 | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `subnet_binding_count`                     |
| `nic_binding_count`                    | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `nic_binding_count`                        |
| `inbound_allow_count`                  | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `inbound_allow_count`                      |
| `inbound_deny_count`                   | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `inbound_deny_count`                       |
| `outbound_allow_count`                 | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `outbound_allow_count`                     |
| `outbound_deny_count`                  | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `outbound_deny_count`                      |
| `total_rule_count`                     | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `total_rule_count`                         |
| `flow_log_enabled`                     | boolean    | `=`, `!=`                                    | `flow_log_enabled` *                       |
| `flow_log_retention_enabled`           | boolean    | `=`, `!=`                                    | `flow_log_retention_enabled` *             |
| `flow_log_retention_days`              | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `flow_log_retention_days` *                |
| `flow_log_traffic_analytics_enabled`   | boolean    | `=`, `!=`                                    | `flow_log_traffic_analytics_enabled` *     |
| `flow_log_analytics_interval_minutes`  | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `flow_log_analytics_interval_minutes` *    |
| `record`                               | RecordData | (record checks)                              | `resource`                                 |

\* Requires `behavior include_flow_log_status true` on the OBJECT. Without the
behavior modifier, these fields are absent and any STATE assertion produces Error.

---

## Collection Strategy

| Property                 | Value                                |
| ------------------------ | ------------------------------------ |
| Collector ID             | `az-nsg-collector`                   |
| Collector Type           | `az_nsg`                             |
| Collection Mode          | Metadata                             |
| Required Capabilities    | `az_cli`, `reader`                   |
| Expected Collection Time | ~2000ms (base), ~4000ms (with flow log) |
| Memory Usage             | ~2MB                                 |
| Batch Collection         | No                                   |
| Per-call Timeout         | 30s per CLI call                     |
| API Calls                | 1 (base) or 2 (with `include_flow_log_status`) |

---

## Required Azure Permissions

**Base command:** `Reader` role at subscription, RG, or NSG scope. That's
all. `az network nsg show` is a pure ARM GET; no data plane exists for
NSGs, so there's no second-tier permission to elevate to.

**Flow log behavior (optional):** `az network watcher flow-log list` requires
at minimum `Reader` on the Network Watcher resource in the same region.
Some environments may require `Network Contributor` depending on RBAC
configuration. If the permission is insufficient, the behavior-gated call
fails silently (non-fatal) and flow log fields remain absent.

---

## ESP Policy Examples

### Baseline — NSG exists, is attached, no internet inbound allow

```esp
META
    esp_id `ksi-cna-rnt-nsg-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-CNA-RNT`
    title `NSG baseline - attached, provisioned, no internet inbound`
META_END

DEF
    OBJECT nsg_app_gw
        name `nsg-snet-app-gw`
        resource_group `rg-prooflayer-demo-eastus`
    OBJECT_END

    STATE nsg_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        is_attached boolean = true
        has_internet_inbound_allow boolean = false
    STATE_END

    CRI AND
        CTN az_nsg
            TEST all all AND
            STATE_REF nsg_baseline
            OBJECT_REF nsg_app_gw
        CTN_END
    CRI_END
DEF_END
```

### Dangerous port detection -- no SSH/RDP open to internet

```esp
STATE nsg_no_dangerous_ports
    found boolean = true
    has_ssh_open_to_internet boolean = false
    has_rdp_open_to_internet boolean = false
    has_all_ports_open_to_internet boolean = false
    total_rule_count int <= 20
STATE_END
```

### Flow log compliance via behavior modifier

```esp
OBJECT nsg_with_flow_log
    name `nsg-snet-app-gw`
    resource_group `rg-prooflayer-demo-eastus`
    behavior include_flow_log_status true
OBJECT_END

STATE nsg_flow_log_compliant
    found boolean = true
    flow_log_enabled boolean = true
    flow_log_retention_enabled boolean = true
    flow_log_retention_days int >= 90
STATE_END

CTN az_nsg
    TEST all all AND
    STATE_REF nsg_flow_log_compliant
    OBJECT_REF nsg_with_flow_log
CTN_END
```

Note: the `behavior` directive must be inside the OBJECT block, not the CTN
block. Without the behavior modifier, flow log fields are absent and STATE
assertions against them produce Error (field missing).

### Per-rule assertion via record_checks

```esp
STATE nsg_https_only_inbound
    found boolean = true
    record
        field securityRules[?name==`AllowInternetHTTPS`].access string = `Allow`
        field securityRules[?name==`AllowInternetHTTPS`].protocol string = `Tcp`
        field securityRules[?name==`AllowInternetHTTPS`].destinationPortRange string = `443`
        field defaultSecurityRules[?name==`DenyAllInBound`].priority int = 65500
    record_end
STATE_END
```

### NotFound path

```esp
OBJECT nsg_missing
    name `nsg-does-not-exist-xyz`
    resource_group `rg-prooflayer-demo-eastus`
OBJECT_END

STATE nsg_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                             | Collector behavior                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| NSG does not exist (real RG + missing/malformed name) | `found=false`, `resource={}` - stderr matches `(ResourceNotFound)`  |
| RG does not exist / caller has no access              | `found=false` - stderr matches `(AuthorizationFailed)` scoped to NSG |
| `az` binary missing / not authenticated               | `CollectionError::CollectionFailed` - bubbles up                    |
| Unexpected non-zero exit with non-NotFound stderr     | `CollectionError::CollectionFailed`                                 |
| Malformed JSON in stdout on success                   | `CollectionError::CollectionFailed`                                 |
| Flow log list call fails (behavior on)                | N/A (non-fatal) - base collection succeeds; flow log fields absent  |

**NotFound dual-pattern detection:** Azure maps "RG does not exist" to
`AuthorizationFailed` (exit 1) instead of `ResourceNotFound` (exit 3)
because the RBAC layer is scoped at the RG level and can't distinguish
"forbidden" from "missing". The collector's `is_not_found` matches both
patterns but gates the `AuthorizationFailed` branch on the scope substring
`/networksecuritygroups/` (case-insensitive) so unrelated RBAC failures
still surface as errors.

---

## Non-Goals

These are **never** in scope for this CTN. Adding any of them would break
the read-only invariant or the Reader-only permission model:

1. **No rule mutation.** The CTN will never call `az network nsg rule
   create`, `update`, or `delete` — or the NSG-level `create`/`update`/
   `delete` commands. All inspection is via `show` only.
2. **No effective-rules evaluation.** `az network nic list-effective-nsg`
   and the effective-security-rules API require VM-level runtime state and
   additional permissions beyond Reader. If policy needs to reason about
   which NIC would be hit by which rule in practice, that's a separate CTN.
3. **No flow log / NSG diagnostic-setting mutation.** Reading diagnostic
   settings on an NSG is in scope for the future `az_diagnostic_setting`
   CTN; configuring them is not, and is out of scope forever.
4. **No cross-NSG correlation.** The CTN validates one NSG at a time as
   specified by the OBJECT block. Policies that need "all NSGs in RG"
   semantics must enumerate via the policy generation layer or a future
   batch-mode CTN.

---

## Related CTN Types

- `az_resource_group` — parent RG context
- `az_key_vault` — another single-call, control-plane-only Azure CTN
- `az_storage_account` — closest analogue; same dual NotFound pattern,
  same single-call shape
- `az_diagnostic_setting` (planned) — will cover flow-log / diagnostic
  settings on NSGs and other Azure resources
