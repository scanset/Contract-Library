# az_recovery_services_vault CTN

## Overview

Validates Azure Recovery Services Vault configuration via `az backup vault show`.

**CLI command:** `az backup vault show --name <name> --resource-group <rg> [--subscription <id>] --output json`

---

## OBJECT Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Recovery Services vault name |
| `resource_group` | string | Yes | Resource group that owns the vault |
| `subscription` | string | No | Subscription ID override |

---

## STATE Fields

### String Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `name` | = != contains startswith | Vault name | `rsv-example-prod` |
| `id` | = != contains startswith | Full ARM resource ID | `/subscriptions/.../vaults/rsv-example` |
| `type` | = != | ARM resource type | `Microsoft.RecoveryServices/vaults` |
| `location` | = != | Azure region | `eastus` |
| `resource_group` | = != contains startswith | Resource group | `rg-example-eastus` |
| `provisioning_state` | = != | ARM provisioning state | `Succeeded` |
| `sku_name` | = != | SKU name | `Standard` |
| `identity_type` | = != | Managed identity type | `None` |
| `public_network_access` | = != | Public network access | `Enabled` |
| `secure_score` | = != | Azure secure score rating | `Minimum` |
| `bcdr_security_level` | = != | BCDR security level | `Fair` |
| `storage_redundancy` | = != | Storage redundancy type | `GeoRedundant` |
| `cross_region_restore` | = != | Cross-region restore state | `Enabled` |
| `soft_delete_state` | = != | Soft delete state | `Enabled` |
| `enhanced_security_state` | = != | Enhanced security state | `Enabled` |
| `immutability_state` | = != | Immutability state | `Unlocked` |
| `multi_user_authorization` | = != | Multi-user authorization | `Disabled` |

### Boolean Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `found` | = != | Whether the vault was found | `true` |

### Integer Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `soft_delete_retention_days` | = != > >= < <= | Soft delete retention in days | `14` |

### RecordData

| Field | Ops | Description |
|-------|-----|-------------|
| `record` | = | Full vault JSON as RecordData (use record_checks for tags/nested) |

---

## NotFound Handling

- `(ResourceNotFound)` with exit code 3 - sets `found=false`
- `(AuthorizationFailed)` scoped to `recoveryservices/vaults/` - treated as not found

---

## JSON Path Mapping

| Field | JSON Path |
|-------|-----------|
| `provisioning_state` | `properties.provisioningState` |
| `public_network_access` | `properties.publicNetworkAccess` |
| `secure_score` | `properties.secureScore` |
| `bcdr_security_level` | `properties.bcdrSecurityLevel` |
| `storage_redundancy` | `properties.redundancySettings.standardTierStorageRedundancy` |
| `cross_region_restore` | `properties.redundancySettings.crossRegionRestore` |
| `soft_delete_state` | `properties.securitySettings.softDeleteSettings.softDeleteState` |
| `soft_delete_retention_days` | `properties.securitySettings.softDeleteSettings.softDeleteRetentionPeriodInDays` |
| `enhanced_security_state` | `properties.securitySettings.softDeleteSettings.enhancedSecurityState` |
| `immutability_state` | `properties.securitySettings.immutabilitySettings.state` |
| `multi_user_authorization` | `properties.securitySettings.multiUserAuthorization` |
| `sku_name` | `sku.name` |
| `identity_type` | `identity.type` |

---

## Example ESP Policy

```esp
OBJECT rsv_example
    name `rsv-example-prod`
    resource_group `rg-example-eastus`
OBJECT_END

STATE st_rsv_secure
    found boolean = true
    provisioning_state string = `Succeeded`
    storage_redundancy string = `GeoRedundant`
    soft_delete_state string = `Enabled`
    soft_delete_retention_days integer >= 14
    enhanced_security_state string = `Enabled`
    immutability_state string = `Locked`
    multi_user_authorization string = `Enabled`
STATE_END

CRI AND
    CTN az_recovery_services_vault
        TEST all all AND
        STATE_REF st_rsv_secure
        OBJECT_REF rsv_example
    CTN_END
CRI_END
```

---

## Notes

- Uses `az backup vault show` (not `az recovery-services vault show`)
- `az backup vault list` returns fewer fields -- always use `show` for full detail
- Properties are deeply nested under `properties.*` unlike most ARM resources
- `encryption: null` means platform-managed keys (no CMK)
- `secure_score` values: `Minimum`, `Adequate`, `Maximum`, `None`
- `immutability_state` values: `Unlocked`, `Locked`, `Disabled`
