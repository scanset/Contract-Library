# az_defender_pricing CTN

## Overview

Validates Azure Defender for Cloud pricing plan configuration via `az security pricing show`.

**CLI command:** `az security pricing show --name <plan> [--subscription <id>] --output json`

**Scope:** Subscription-level (no resource group required)

---

## OBJECT Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Defender plan name (e.g., VirtualMachines, KeyVaults) |
| `subscription` | string | No | Subscription ID override |

---

## STATE Fields

### String Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `name` | = != contains startswith | Plan name | `VirtualMachines` |
| `id` | = != contains startswith | Full ARM resource ID | `/subscriptions/.../pricings/VirtualMachines` |
| `type` | = != | ARM resource type | `Microsoft.Security/pricings` |
| `pricing_tier` | = != | Pricing tier | `Standard` or `Free` |
| `sub_plan` | = != | Sub-plan name or "none" | `P2` |
| `enablement_time` | = != contains startswith | ISO8601 enablement timestamp | `2026-01-01T00:00:00.000000+00:00` |
| `free_trial_remaining` | = != contains startswith | Free trial time remaining | `30 days, 0:00:00` |

### Boolean Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `found` | = != | Whether the plan was found | `true` |
| `is_enabled` | = != | Whether pricing tier is Standard | `true` |
| `deprecated` | = != | Whether the plan is deprecated | `false` |
| `has_extensions` | = != | Whether the plan has extensions | `true` |

### Integer Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `extension_count` | = != > >= < <= | Number of extensions on this plan | `3` |

### RecordData

| Field | Ops | Description |
|-------|-----|-------------|
| `record` | = | Full pricing object as RecordData (use record_checks for extensions) |

---

## NotFound Handling

- `(InvalidResourceName)` with exit code 1 -- sets `found=false`
- Unlike ARM resources which return `ResourceNotFound` exit 3

---

## Known Plan Names

| Plan | Description | Sub-plans |
|------|-------------|-----------|
| `VirtualMachines` | Defender for Servers | P1, P2 |
| `SqlServers` | Defender for SQL | - |
| `AppServices` | Defender for App Service | - |
| `StorageAccounts` | Defender for Storage | DefenderForStorageV2 |
| `KeyVaults` | Defender for Key Vault | PerKeyVault |
| `Arm` | Defender for ARM | PerSubscription |
| `Containers` | Defender for Containers | - |
| `CloudPosture` | Defender CSPM | - |
| `OpenSourceRelationalDatabases` | Defender for OSS DBs | - |
| `CosmosDbs` | Defender for Cosmos DB | - |
| `Api` | Defender for APIs | - |
| `AI` | Defender for AI | - |
| `Discovery` | Asset Discovery | - |
| `FoundationalCspm` | Foundational CSPM | - |

Deprecated: `KubernetesService` (replaced by Containers), `ContainerRegistry` (replaced by Containers), `Dns` (replaced by VirtualMachines)

---

## Example ESP Policy

```esp
OBJECT plan_vm
    name `VirtualMachines`
OBJECT_END

STATE st_defender_enabled
    found boolean = true
    pricing_tier string = `Standard`
    is_enabled boolean = true
    deprecated boolean = false
STATE_END

CRI AND
    CTN az_defender_pricing
        TEST all all AND
        STATE_REF st_defender_enabled
        OBJECT_REF plan_vm
    CTN_END
CRI_END
```

---

## Notes

- Subscription-scoped resource -- no resource_group in OBJECT
- `sub_plan` is set to `"none"` when the API returns null (plans without sub-plans)
- `is_enabled` is a convenience boolean derived from `pricing_tier == "Standard"`
- Extensions represent optional add-ons per plan (e.g., AgentlessVmScanning, FileIntegrityMonitoring)
- Use record_checks to assert on specific extension states within the extensions array
- `deprecated` plans should generally be skipped in compliance policies
