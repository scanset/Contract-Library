# az_application_gateway

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Application
Gateway's configuration surface via a single Azure CLI call --
`az network application-gateway show --name <name> --resource-group <rg>
[--subscription <id>] --output json`. Returns compliance scalars for SKU
(tier, name, capacity), WAF configuration (enabled/mode/ruleset), SSL
policy (predefined or custom, minimum TLS version), HTTP/2 support,
autoscale settings, zone redundancy, listener and backend pool inventory,
HTTP-to-HTTPS redirect detection, SSL certificate count, and health probe
count, plus the full gateway document as RecordData for tag-based and
per-listener/per-rule record_checks.

The CTN never modifies any resource, never sends traffic through the
gateway, never accesses backend pools or health probe results, and never
requires any Azure permission above `Reader`. See "Non-Goals" at the
bottom for the full list of things this CTN will never do.

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

`az_application_gateway` inherits this env surface unchanged - no per-CTN
overrides, no per-collector env. If `az_resource_group` can authenticate
successfully, so can `az_application_gateway`.

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
| `name`           | string | **Yes**  | Application Gateway name                  | `appgw-prooflayer-demo`                 |
| `resource_group` | string | **Yes**  | Resource group that owns the gateway      | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                  | `00000000-0000-0000-0000-000000000000`  |

Both `name` and `resource_group` are required. Azure performs no
client-side validation of the name: malformed inputs return
`ResourceNotFound` at runtime.

---

## Commands Executed

```
az network application-gateway show \
    --name appgw-prooflayer-demo \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per gateway object. Returns SKU, WAF config, SSL policy,
autoscale, zones, frontend IPs/ports, HTTP listeners, backend pools,
backend HTTP settings, routing rules, redirect configurations,
SSL certificates, health probes, and tags inline.

**Sample response (abbreviated):**

```json
{
  "name": "appgw-prooflayer-demo",
  "id": "/subscriptions/.../applicationGateways/appgw-prooflayer-demo",
  "type": "Microsoft.Network/applicationGateways",
  "location": "eastus",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "provisioningState": "Succeeded",
  "operationalState": "Running",
  "sku": {
    "name": "Standard_v2",
    "tier": "Standard_v2",
    "family": "Generation_1"
  },
  "autoscaleConfiguration": {
    "minCapacity": 2,
    "maxCapacity": 10
  },
  "sslPolicy": {
    "policyType": "Predefined",
    "policyName": "AppGwSslPolicy20220101"
  },
  "enableHttp2": false,
  "zones": ["1", "2", "3"],
  "frontendIPConfigurations": [
    { "name": "frontend-public", "publicIPAddress": { "id": "..." } }
  ],
  "frontendPorts": [
    { "name": "port-443", "port": 443 },
    { "name": "port-80", "port": 80 }
  ],
  "httpListeners": [
    { "name": "listener-http", "protocol": "Http" },
    { "name": "listener-https", "protocol": "Https",
      "sslCertificate": { "id": ".../appgw-wildcard" } }
  ],
  "backendAddressPools": [
    { "name": "backend-vm", "backendAddresses": [{ "ipAddress": "10.0.2.4" }] }
  ],
  "backendHttpSettingsCollection": [
    { "name": "http-settings", "port": 80, "protocol": "Http", "requestTimeout": 30 }
  ],
  "requestRoutingRules": [
    { "name": "rule-http-redirect", "priority": 10, "redirectConfiguration": { "id": "..." } },
    { "name": "rule-https", "priority": 20, "backendAddressPool": { "id": "..." } }
  ],
  "redirectConfigurations": [
    { "name": "redirect-http-to-https", "redirectType": "Permanent",
      "includePath": true, "includeQueryString": true }
  ],
  "sslCertificates": [
    { "name": "appgw-wildcard" }
  ],
  "probes": [
    { "name": "probe-health", "path": "/health", "protocol": "Http",
      "interval": 30, "timeout": 10, "unhealthyThreshold": 3 }
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

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `found`                     | boolean | Yes            | Derived - true on successful show, false on NotFound      |
| `name`                      | string  | When found     | `name`                                                    |
| `id`                        | string  | When found     | `id`                                                      |
| `type`                      | string  | When found     | `type`                                                    |
| `location`                  | string  | When found     | `location`                                                |
| `resource_group`            | string  | When found     | `resourceGroup`                                           |
| `provisioning_state`        | string  | When found     | `provisioningState`                                       |
| `operational_state`         | string  | When found     | `operationalState` (`Running`, `Starting`, `Stopped`)     |
| `sku_name`                  | string  | When found     | `sku.name` (`Standard_v2`, `WAF_v2`)                      |
| `sku_tier`                  | string  | When found     | `sku.tier` (`Standard_v2`, `WAF_v2`)                      |
| `ssl_policy_type`           | string  | When found     | `sslPolicy.policyType` (`Predefined`, `Custom`)           |
| `ssl_policy_name`           | string  | When present   | `sslPolicy.policyName` (predefined policy name)           |
| `ssl_min_protocol_version`  | string  | When custom    | `sslPolicy.minProtocolVersion` (`TLSv1_2`, `TLSv1_3`)    |
| `identity_type`             | string  | When identity  | `identity.type`                                           |

### WAF Fields (only present when WAF_v2 tier)

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `waf_enabled`               | boolean | When found     | `webApplicationFirewallConfiguration.enabled` (false if absent) |
| `waf_mode`                  | string  | When WAF       | `webApplicationFirewallConfiguration.firewallMode` (`Prevention`, `Detection`) |
| `waf_rule_set_type`         | string  | When WAF       | `webApplicationFirewallConfiguration.ruleSetType` (`OWASP`) |
| `waf_rule_set_version`      | string  | When WAF       | `webApplicationFirewallConfiguration.ruleSetVersion` (`3.2`) |

### Boolean Fields

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `http2_enabled`             | boolean | When found     | `enableHttp2`                                             |
| `zone_redundant`            | boolean | When found     | Derived: `zones[]` has more than one entry                |
| `autoscale_enabled`         | boolean | When found     | Derived: `autoscaleConfiguration` block is present        |
| `has_https_listener`        | boolean | When found     | Derived: any listener has `protocol == Https`             |
| `has_http_to_https_redirect`| boolean | When found     | Derived: any redirect config has `redirectType` of `Permanent` or `Found` |
| `has_managed_identity`      | boolean | When found     | Derived: `identity` block is present                      |

### Integer Fields

| Field                              | Type    | Always Present | Source                                          |
| ---------------------------------- | ------- | -------------- | ----------------------------------------------- |
| `sku_capacity`                    | integer | When fixed     | `sku.capacity` (absent when autoscale is used)  |
| `autoscale_min_capacity`          | integer | When autoscale | `autoscaleConfiguration.minCapacity`            |
| `autoscale_max_capacity`          | integer | When autoscale | `autoscaleConfiguration.maxCapacity`            |
| `zone_count`                      | integer | When found     | `zones[]` array length                          |
| `frontend_ip_count`               | integer | When found     | `frontendIPConfigurations[]` length             |
| `frontend_port_count`             | integer | When found     | `frontendPorts[]` length                        |
| `http_listener_count`             | integer | When found     | `httpListeners[]` length                        |
| `backend_pool_count`              | integer | When found     | `backendAddressPools[]` length                  |
| `backend_http_settings_count`     | integer | When found     | `backendHttpSettingsCollection[]` length         |
| `request_routing_rule_count`      | integer | When found     | `requestRoutingRules[]` length                  |
| `ssl_certificate_count`           | integer | When found     | `sslCertificates[]` length                      |
| `probe_count`                     | integer | When found     | `probes[]` length                               |
| `redirect_configuration_count`    | integer | When found     | `redirectConfigurations[]` length               |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az network application-gateway show` object. Empty `{}` when not found |

### Derived-field semantics

- **`waf_enabled`** -- false when the `webApplicationFirewallConfiguration`
  block is absent (Standard_v2 tier) or when `.enabled` is false.
  WAF requires the `WAF_v2` SKU tier.
- **`zone_redundant`** -- true when the gateway spans 2+ availability
  zones. A single-zone deployment has `zones: ["1"]`, which sets this
  to false.
- **`has_https_listener`** -- true when any HTTP listener uses protocol
  `Https`. Does not verify the certificate is valid or trusted.
- **`has_http_to_https_redirect`** -- true when any redirect configuration
  has `redirectType` of `Permanent` (301) or `Found` (302). This covers
  the common pattern of redirecting HTTP port-80 traffic to HTTPS.
- **`autoscale_enabled`** -- true when `autoscaleConfiguration` block is
  present. When false, `sku.capacity` contains the fixed instance count.

---

## State Fields

| State Field                        | Type       | Allowed Operations                           | Maps To Collected Field                    |
| ---------------------------------- | ---------- | -------------------------------------------- | ------------------------------------------ |
| `found`                           | boolean    | `=`, `!=`                                    | `found`                                    |
| `name`                            | string     | `=`, `!=`, `contains`, `starts`              | `name`                                     |
| `id`                              | string     | `=`, `!=`, `contains`, `starts`              | `id`                                       |
| `type`                            | string     | `=`, `!=`                                    | `type`                                     |
| `location`                        | string     | `=`, `!=`                                    | `location`                                 |
| `resource_group`                  | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                           |
| `provisioning_state`              | string     | `=`, `!=`                                    | `provisioning_state`                       |
| `operational_state`               | string     | `=`, `!=`                                    | `operational_state`                        |
| `sku_name`                        | string     | `=`, `!=`                                    | `sku_name`                                 |
| `sku_tier`                        | string     | `=`, `!=`                                    | `sku_tier`                                 |
| `ssl_policy_type`                 | string     | `=`, `!=`                                    | `ssl_policy_type`                          |
| `ssl_policy_name`                 | string     | `=`, `!=`, `contains`, `starts`              | `ssl_policy_name`                          |
| `ssl_min_protocol_version`        | string     | `=`, `!=`                                    | `ssl_min_protocol_version`                 |
| `waf_mode`                        | string     | `=`, `!=`                                    | `waf_mode`                                 |
| `waf_rule_set_type`               | string     | `=`, `!=`                                    | `waf_rule_set_type`                        |
| `waf_rule_set_version`            | string     | `=`, `!=`                                    | `waf_rule_set_version`                     |
| `identity_type`                   | string     | `=`, `!=`                                    | `identity_type`                            |
| `waf_enabled`                     | boolean    | `=`, `!=`                                    | `waf_enabled`                              |
| `http2_enabled`                   | boolean    | `=`, `!=`                                    | `http2_enabled`                            |
| `zone_redundant`                  | boolean    | `=`, `!=`                                    | `zone_redundant`                           |
| `autoscale_enabled`               | boolean    | `=`, `!=`                                    | `autoscale_enabled`                        |
| `has_https_listener`              | boolean    | `=`, `!=`                                    | `has_https_listener`                       |
| `has_http_to_https_redirect`      | boolean    | `=`, `!=`                                    | `has_http_to_https_redirect`               |
| `has_managed_identity`            | boolean    | `=`, `!=`                                    | `has_managed_identity`                     |
| `sku_capacity`                    | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `sku_capacity`                             |
| `autoscale_min_capacity`          | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `autoscale_min_capacity`                   |
| `autoscale_max_capacity`          | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `autoscale_max_capacity`                   |
| `zone_count`                      | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `zone_count`                               |
| `frontend_ip_count`               | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `frontend_ip_count`                        |
| `frontend_port_count`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `frontend_port_count`                      |
| `http_listener_count`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `http_listener_count`                      |
| `backend_pool_count`              | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `backend_pool_count`                       |
| `backend_http_settings_count`     | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `backend_http_settings_count`              |
| `request_routing_rule_count`      | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `request_routing_rule_count`               |
| `ssl_certificate_count`           | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `ssl_certificate_count`                    |
| `probe_count`                     | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `probe_count`                              |
| `redirect_configuration_count`    | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `redirect_configuration_count`             |
| `record`                          | RecordData | (record checks)                              | `resource`                                 |

---

## Collection Strategy

| Property                 | Value                                       |
| ------------------------ | ------------------------------------------- |
| Collector ID             | `az-application-gateway-collector`          |
| Collector Type           | `az_application_gateway`                    |
| Collection Mode          | Metadata                                    |
| Required Capabilities    | `az_cli`, `reader`                          |
| Expected Collection Time | ~3000ms                                     |
| Memory Usage             | ~8MB                                        |
| Batch Collection         | No                                          |
| Per-call Timeout         | 30s                                         |
| API Calls                | 1                                           |

---

## Required Azure Permissions

`Reader` role at subscription, RG, or Application Gateway scope. That's all.
`az network application-gateway show` is a pure ARM GET; the CTN never
sends traffic through the gateway, never accesses backends, and never
reads WAF logs or access logs.

---

## ESP Policy Examples

### Baseline -- gateway exists, running, zone-redundant, HTTPS enforced

```esp
META
    esp_id `example-appgw-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-CNA-RNT`
    title `AppGW baseline - running, zone-redundant, HTTPS enforced`
META_END

DEF
    OBJECT appgw_prod
        name `appgw-prooflayer-demo`
        resource_group `rg-prooflayer-demo-eastus`
    OBJECT_END

    STATE appgw_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        operational_state string = `Running`
        zone_redundant boolean = true
        has_https_listener boolean = true
        has_http_to_https_redirect boolean = true
    STATE_END

    CRI AND
        CTN az_application_gateway
            TEST all all AND
            STATE_REF appgw_baseline
            OBJECT_REF appgw_prod
        CTN_END
    CRI_END
DEF_END
```

### WAF required -- WAF_v2 tier with prevention mode

```esp
STATE appgw_waf_enforced
    found boolean = true
    sku_tier string = `WAF_v2`
    waf_enabled boolean = true
    waf_mode string = `Prevention`
STATE_END
```

### TLS hardening -- modern SSL policy

```esp
STATE appgw_tls_hardened
    found boolean = true
    ssl_policy_type string = `Predefined`
    ssl_policy_name string = `AppGwSslPolicy20220101`
    has_https_listener boolean = true
STATE_END
```

### Autoscale -- minimum capacity check

```esp
STATE appgw_autoscale
    found boolean = true
    autoscale_enabled boolean = true
    autoscale_min_capacity int >= 2
    autoscale_max_capacity int <= 20
STATE_END
```

### Zone redundancy required

```esp
STATE appgw_zone_redundant
    found boolean = true
    zone_redundant boolean = true
    zone_count int >= 3
STATE_END
```

### Backend pool inventory

```esp
STATE appgw_backend_check
    found boolean = true
    backend_pool_count int >= 1
    probe_count int >= 1
    backend_http_settings_count int >= 1
STATE_END
```

### Tag compliance via record_checks

```esp
STATE appgw_tagged
    found boolean = true
    record
        field tags.Environment string = `demo`
        field tags.FedRAMPImpactLevel string = `moderate`
    record_end
STATE_END
```

### NotFound path -- gateway must not exist

```esp
STATE appgw_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                             | Collector behavior                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------------ |
| Gateway does not exist (real RG + missing name)       | `found=false`, `resource={}` - stderr matches `(ResourceNotFound)`       |
| RG does not exist / caller has no access              | `found=false` - stderr matches `(AuthorizationFailed)` scoped to `/applicationGateways/` |
| `name` missing from OBJECT                            | `InvalidObjectConfiguration` - Error                                    |
| `resource_group` missing from OBJECT                  | `InvalidObjectConfiguration` - Error                                    |
| `az` binary missing / not authenticated               | `CollectionError::CollectionFailed` - bubbles up                         |
| Unexpected non-zero exit with non-NotFound stderr     | `CollectionError::CollectionFailed`                                      |
| Malformed JSON in stdout on success                   | `CollectionError::CollectionFailed`                                      |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr
matches either:

1. `(ResourceNotFound)` / `Code: ResourceNotFound` - covers real RG with
   missing or malformed gateway name (exit code 3).
2. `(AuthorizationFailed)` **and** the scope string contains
   `/applicationGateways/` (case-insensitive) - covers fake or
   inaccessible RG (exit code 1). An `AuthorizationFailed` that does
   NOT mention `/applicationGateways/` is treated as a real error.

---

## Non-Goals

These are **never** in scope for this CTN:

1. **No mutation.** The CTN will never call `create`, `update`, `delete`,
   `start`, `stop`, or any modification command. All inspection is via
   `show` only.
2. **No traffic inspection.** The CTN never sends traffic through the
   gateway, never reads access logs, and never inspects live connections.
3. **No WAF log analysis.** WAF log data requires diagnostic settings
   and Log Analytics queries. Use `az_diagnostic_setting` and
   `az_log_analytics_workspace` for WAF log compliance.
4. **No SSL certificate validation.** The CTN counts certificates and
   records their names but does not check expiry dates, trust chains,
   or key sizes. Use record_checks to inspect certificate properties
   from the RecordData.
5. **No backend health probing.** The CTN does not call
   `az network application-gateway show-backend-health`, which requires
   network reachability to backends.

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the gateway                                   |
| `az_virtual_network`              | VNet containing the gateway subnet                              |
| `az_nsg`                          | NSG on the gateway subnet (required for v2 SKU)                 |
| `az_public_ip`                    | Public IP attached to the frontend                              |
| `az_key_vault`                    | Key Vault holding SSL certificates (when using KV integration)  |
| `az_log_analytics_workspace`      | LAW receiving WAF and access logs via diagnostic settings       |
| `az_diagnostic_setting`           | Diagnostic settings on the gateway resource                     |
