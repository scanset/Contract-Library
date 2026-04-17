# az_virtual_machine

## Overview

**Read-only, control-plane-only.** This CTN validates an Azure Virtual
Machine's configuration surface via a single Azure CLI call --
`az vm show --name <name> --resource-group <rg> [--subscription <id>]
--output json`. Returns compliance scalars for VM size, OS type, storage
profile (OS disk size, storage tier, CMK encryption, data disk count),
security profile (Trusted Launch, Secure Boot, vTPM, encryption at host),
managed identity, boot diagnostics, VM extensions (MDE detection),
patching mode, image reference, availability zones, and priority, plus
the full VM document as RecordData for tag-based and nested record_checks.

The CTN never modifies any resource, never calls data-plane APIs (no
guest OS access, no serial console, no run commands), and never requires
any Azure permission above `Reader`. See "Non-Goals" at the bottom for
the full list of things this CTN will never do.

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

`az_virtual_machine` inherits this env surface unchanged - no per-CTN
overrides, no per-collector env. If `az_resource_group` can authenticate
successfully, so can `az_virtual_machine`.

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
| `name`           | string | **Yes**  | VM name                                   | `vm-prooflayer-demo`                    |
| `resource_group` | string | **Yes**  | Resource group that owns the VM           | `rg-prooflayer-demo-eastus`             |
| `subscription`   | string | opt      | Subscription ID override                  | `00000000-0000-0000-0000-000000000000`  |

Both `name` and `resource_group` are required -- VM names are only unique
within an RG, and `az vm show` demands `-g`. Azure performs no client-side
validation of the name: malformed inputs return `ResourceNotFound` at
runtime.

---

## Commands Executed

```
az vm show --name vm-prooflayer-demo \
    --resource-group rg-prooflayer-demo-eastus \
    --subscription 00000000-0000-0000-0000-000000000000 \
    --output json
```

One call per VM object. Returns hardware profile, storage profile (OS disk,
data disks, image reference), OS profile (admin user, patch settings,
password auth), diagnostics, identity, security profile, extensions, tags,
and zones inline.

**Sample response (abbreviated):**

```json
{
  "diagnosticsProfile": {
    "bootDiagnostics": { "enabled": true }
  },
  "hardwareProfile": { "vmSize": "Standard_D2s_v6" },
  "id": "/subscriptions/.../virtualMachines/vm-prooflayer-demo",
  "identity": {
    "type": "UserAssigned",
    "userAssignedIdentities": {
      ".../id-prooflayer-demo-vm": {
        "clientId": "cccccccc-...",
        "principalId": "dddddddd-..."
      }
    }
  },
  "location": "eastus",
  "name": "vm-prooflayer-demo",
  "networkProfile": {
    "networkInterfaces": [
      { "id": ".../nic-prooflayer-demo-vm", "primary": true }
    ]
  },
  "osProfile": {
    "adminUsername": "azureuser",
    "allowExtensionOperations": true,
    "computerName": "vm-prooflayer-demo",
    "linuxConfiguration": {
      "disablePasswordAuthentication": true,
      "patchSettings": {
        "assessmentMode": "ImageDefault",
        "patchMode": "ImageDefault"
      },
      "provisionVMAgent": true
    }
  },
  "plan": {
    "name": "9-base",
    "product": "rockylinux-x86_64",
    "publisher": "resf"
  },
  "priority": "Regular",
  "provisioningState": "Succeeded",
  "resourceGroup": "rg-prooflayer-demo-eastus",
  "resources": [
    {
      "autoUpgradeMinorVersion": true,
      "name": "MDE.Linux",
      "provisioningState": "Succeeded",
      "publisher": "Microsoft.Azure.AzureDefenderForServers",
      "typeHandlerVersion": "1.0",
      "typePropertiesType": "MDE.Linux"
    }
  ],
  "storageProfile": {
    "dataDisks": [
      {
        "caching": "ReadWrite",
        "diskSizeGB": 50,
        "lun": 0,
        "managedDisk": {
          "diskEncryptionSet": { "id": ".../des-prooflayer-demo" },
          "storageAccountType": "Premium_LRS"
        },
        "name": "disk-prooflayer-demo-vm-data"
      }
    ],
    "diskControllerType": "NVMe",
    "imageReference": {
      "exactVersion": "9.6.20250531",
      "offer": "rockylinux-x86_64",
      "publisher": "resf",
      "sku": "9-base",
      "version": "latest"
    },
    "osDisk": {
      "caching": "ReadWrite",
      "diskSizeGB": 10,
      "managedDisk": {
        "diskEncryptionSet": { "id": ".../des-prooflayer-demo" },
        "storageAccountType": "Premium_LRS"
      },
      "name": "disk-prooflayer-demo-vm-os",
      "osType": "Linux"
    }
  },
  "tags": {
    "Environment": "demo",
    "FedRAMPImpactLevel": "moderate"
  },
  "timeCreated": "2026-04-14T15:58:40.9910866+00:00",
  "type": "Microsoft.Compute/virtualMachines",
  "vmId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "zones": ["1"]
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
| `vm_id`                     | string  | When found     | `vmId`                                                    |
| `priority`                  | string  | When found     | `priority` (`Regular` or `Spot`)                          |
| `time_created`              | string  | When found     | `timeCreated`                                             |
| `vm_size`                   | string  | When found     | `hardwareProfile.vmSize`                                  |
| `os_type`                   | string  | When found     | `storageProfile.osDisk.osType` (`Linux` or `Windows`)     |
| `availability_zone`         | string  | When zonal     | First entry from `zones[]`                                |
| `os_disk_storage_type`      | string  | When found     | `storageProfile.osDisk.managedDisk.storageAccountType`    |
| `disk_controller_type`      | string  | When present   | `storageProfile.diskControllerType`                       |
| `image_publisher`           | string  | When found     | `storageProfile.imageReference.publisher`                 |
| `image_offer`               | string  | When found     | `storageProfile.imageReference.offer`                     |
| `image_sku`                 | string  | When found     | `storageProfile.imageReference.sku`                       |
| `image_version`             | string  | When found     | `storageProfile.imageReference.exactVersion`              |
| `admin_username`            | string  | When found     | `osProfile.adminUsername`                                 |
| `patch_mode`                | string  | When present   | `osProfile.linuxConfiguration.patchSettings.patchMode` or `osProfile.windowsConfiguration.patchSettings.patchMode` |
| `identity_type`             | string  | When identity present | `identity.type` (`SystemAssigned`, `UserAssigned`, `SystemAssigned, UserAssigned`) |
| `security_type`             | string  | When securityProfile present | `securityProfile.securityType` (`TrustedLaunch`, `ConfidentialVM`) |

### Boolean Fields

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `boot_diagnostics_enabled`  | boolean | When found     | `diagnosticsProfile.bootDiagnostics.enabled`              |
| `has_managed_identity`      | boolean | When found     | Derived: true when `identity` block is present            |
| `password_auth_disabled`    | boolean | When Linux     | `osProfile.linuxConfiguration.disablePasswordAuthentication` |
| `vm_agent_provisioned`      | boolean | When found     | `osProfile.{linux,windows}Configuration.provisionVMAgent` |
| `allow_extension_operations`| boolean | When found     | `osProfile.allowExtensionOperations`                      |
| `os_disk_encrypted_with_cmk`| boolean | When found     | Derived: true when `osDisk.managedDisk.diskEncryptionSet.id` is present |
| `has_availability_zone`     | boolean | When found     | Derived: `zones[]` is non-empty                           |
| `secure_boot_enabled`       | boolean | When found     | `securityProfile.uefiSettings.secureBootEnabled` (defaults false if absent) |
| `vtpm_enabled`              | boolean | When found     | `securityProfile.uefiSettings.vTpmEnabled` (defaults false if absent) |
| `encryption_at_host`        | boolean | When found     | `securityProfile.encryptionAtHost` (defaults false if absent) |
| `mde_extension_installed`   | boolean | When found     | Derived: true when `resources[]` contains extension with name starting with `MDE.` |

### Integer Fields

| Field                        | Type    | Always Present | Source                                                    |
| ---------------------------- | ------- | -------------- | --------------------------------------------------------- |
| `os_disk_size_gb`           | integer | When found     | `storageProfile.osDisk.diskSizeGB`                        |
| `data_disk_count`           | integer | When found     | `storageProfile.dataDisks` array length                   |
| `extension_count`           | integer | When found     | `resources` array length                                  |

### RecordData Field

| Field      | Type       | Always Present | Description                                                |
| ---------- | ---------- | -------------- | ---------------------------------------------------------- |
| `resource` | RecordData | Yes            | Full `az vm show` object. Empty `{}` when not found        |

### Derived-field semantics

- **`os_disk_encrypted_with_cmk`** -- true when the OS disk has a
  `diskEncryptionSet.id` reference, meaning customer-managed keys (CMK)
  are used via a Disk Encryption Set (DES). Does not check data disks;
  use record_checks for per-disk assertions.
- **`has_managed_identity`** -- true when the `identity` block is present
  in the response. Covers SystemAssigned, UserAssigned, or both. Check
  `identity_type` for the specific mode.
- **`mde_extension_installed`** -- true when any extension in `resources[]`
  has a name starting with `MDE.` (covers `MDE.Linux` and `MDE.Windows`).
  Does not verify the extension is healthy; check the extension's
  `provisioningState` via record_checks if needed.
- **`password_auth_disabled`** -- only present for Linux VMs. For Windows
  VMs, this field is absent (password auth is the norm). True means
  SSH-key-only authentication.
- **`secure_boot_enabled`** / **`vtpm_enabled`** / **`encryption_at_host`** --
  all default to `false` when `securityProfile` is absent from the response.
  The security profile is only present on VMs created with Trusted Launch
  or Confidential VM security type.

---

## RecordData Structure

```
name                                              -> "vm-prooflayer-demo"
id                                                -> "/subscriptions/.../virtualMachines/..."
type                                              -> "Microsoft.Compute/virtualMachines"
location                                          -> "eastus"
resourceGroup                                     -> "rg-prooflayer-demo-eastus"
provisioningState                                 -> "Succeeded"
vmId                                              -> "bbbbbbbb-..."
priority                                          -> "Regular" | "Spot"
timeCreated                                       -> "2026-04-14T15:58:40..."
zones[]                                           -> ["1"] | []
hardwareProfile.vmSize                            -> "Standard_D2s_v6"
storageProfile.osDisk.osType                      -> "Linux" | "Windows"
storageProfile.osDisk.diskSizeGB                  -> 10
storageProfile.osDisk.managedDisk.storageAccountType -> "Premium_LRS"
storageProfile.osDisk.managedDisk.diskEncryptionSet.id -> "/sub/.../des-demo" | null
storageProfile.dataDisks[].name                   -> "disk-prooflayer-demo-vm-data"
storageProfile.dataDisks[].diskSizeGB             -> 50
storageProfile.dataDisks[].managedDisk.diskEncryptionSet.id -> "/sub/.../des-demo"
storageProfile.diskControllerType                 -> "NVMe" | "SCSI"
storageProfile.imageReference.publisher           -> "resf"
storageProfile.imageReference.offer               -> "rockylinux-x86_64"
storageProfile.imageReference.sku                 -> "9-base"
storageProfile.imageReference.exactVersion        -> "9.6.20250531"
osProfile.adminUsername                           -> "azureuser"
osProfile.allowExtensionOperations                -> true | false
osProfile.linuxConfiguration.disablePasswordAuthentication -> true | false
osProfile.linuxConfiguration.patchSettings.patchMode -> "ImageDefault" | "AutomaticByPlatform"
osProfile.linuxConfiguration.provisionVMAgent     -> true | false
diagnosticsProfile.bootDiagnostics.enabled        -> true | false
identity.type                                     -> "UserAssigned" | "SystemAssigned" | ...
identity.userAssignedIdentities.<id>.clientId     -> "cccccccc-..."
identity.userAssignedIdentities.<id>.principalId  -> "dddddddd-..."
plan.name                                         -> "9-base"
plan.product                                      -> "rockylinux-x86_64"
plan.publisher                                    -> "resf"
resources[].name                                  -> "MDE.Linux"
resources[].publisher                             -> "Microsoft.Azure.AzureDefenderForServers"
resources[].provisioningState                     -> "Succeeded"
securityProfile.securityType                      -> "TrustedLaunch" (when present)
securityProfile.uefiSettings.secureBootEnabled    -> true | false (when present)
securityProfile.uefiSettings.vTpmEnabled          -> true | false (when present)
securityProfile.encryptionAtHost                  -> true | false (when present)
tags.<Key>                                        -> "<Value>"
```

Use `field <path> <type> = \`<value>\`` in `record_checks` to enforce
nested properties. Example:
`field storageProfile.osDisk.managedDisk.storageAccountType string = \`Premium_LRS\``.

---

## State Fields

| State Field                    | Type       | Allowed Operations                           | Maps To Collected Field            |
| ------------------------------ | ---------- | -------------------------------------------- | ---------------------------------- |
| `found`                       | boolean    | `=`, `!=`                                    | `found`                            |
| `name`                        | string     | `=`, `!=`, `contains`, `starts`              | `name`                             |
| `id`                          | string     | `=`, `!=`, `contains`, `starts`              | `id`                               |
| `type`                        | string     | `=`, `!=`                                    | `type`                             |
| `location`                    | string     | `=`, `!=`                                    | `location`                         |
| `resource_group`              | string     | `=`, `!=`, `contains`, `starts`              | `resource_group`                   |
| `provisioning_state`          | string     | `=`, `!=`                                    | `provisioning_state`               |
| `vm_id`                       | string     | `=`, `!=`, `contains`, `starts`              | `vm_id`                            |
| `vm_size`                     | string     | `=`, `!=`                                    | `vm_size`                          |
| `os_type`                     | string     | `=`, `!=`                                    | `os_type`                          |
| `priority`                    | string     | `=`, `!=`                                    | `priority`                         |
| `availability_zone`           | string     | `=`, `!=`                                    | `availability_zone`                |
| `os_disk_storage_type`        | string     | `=`, `!=`                                    | `os_disk_storage_type`             |
| `disk_controller_type`        | string     | `=`, `!=`                                    | `disk_controller_type`             |
| `image_publisher`             | string     | `=`, `!=`, `contains`, `starts`              | `image_publisher`                  |
| `image_offer`                 | string     | `=`, `!=`, `contains`, `starts`              | `image_offer`                      |
| `image_sku`                   | string     | `=`, `!=`, `contains`, `starts`              | `image_sku`                        |
| `image_version`               | string     | `=`, `!=`, `contains`, `starts`              | `image_version`                    |
| `admin_username`              | string     | `=`, `!=`                                    | `admin_username`                   |
| `patch_mode`                  | string     | `=`, `!=`                                    | `patch_mode`                       |
| `identity_type`               | string     | `=`, `!=`                                    | `identity_type`                    |
| `security_type`               | string     | `=`, `!=`                                    | `security_type`                    |
| `time_created`                | string     | `=`, `!=`, `contains`, `starts`              | `time_created`                     |
| `boot_diagnostics_enabled`   | boolean    | `=`, `!=`                                    | `boot_diagnostics_enabled`         |
| `has_managed_identity`        | boolean    | `=`, `!=`                                    | `has_managed_identity`             |
| `password_auth_disabled`      | boolean    | `=`, `!=`                                    | `password_auth_disabled`           |
| `vm_agent_provisioned`        | boolean    | `=`, `!=`                                    | `vm_agent_provisioned`             |
| `allow_extension_operations`  | boolean    | `=`, `!=`                                    | `allow_extension_operations`       |
| `os_disk_encrypted_with_cmk`  | boolean    | `=`, `!=`                                    | `os_disk_encrypted_with_cmk`       |
| `has_availability_zone`       | boolean    | `=`, `!=`                                    | `has_availability_zone`            |
| `secure_boot_enabled`         | boolean    | `=`, `!=`                                    | `secure_boot_enabled`              |
| `vtpm_enabled`                | boolean    | `=`, `!=`                                    | `vtpm_enabled`                     |
| `encryption_at_host`          | boolean    | `=`, `!=`                                    | `encryption_at_host`               |
| `mde_extension_installed`     | boolean    | `=`, `!=`                                    | `mde_extension_installed`          |
| `os_disk_size_gb`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `os_disk_size_gb`                  |
| `data_disk_count`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `data_disk_count`                  |
| `extension_count`             | integer    | `=`, `!=`, `>`, `>=`, `<`, `<=`              | `extension_count`                  |
| `record`                      | RecordData | (record checks)                              | `resource`                         |

---

## Collection Strategy

| Property                 | Value                                |
| ------------------------ | ------------------------------------ |
| Collector ID             | `az-virtual-machine-collector`       |
| Collector Type           | `az_virtual_machine`                 |
| Collection Mode          | Metadata                             |
| Required Capabilities    | `az_cli`, `reader`                   |
| Expected Collection Time | ~3000ms                              |
| Memory Usage             | ~4MB                                 |
| Batch Collection         | No                                   |
| Per-call Timeout         | 30s                                  |
| API Calls                | 1                                    |

---

## Required Azure Permissions

`Reader` role at subscription, RG, or VM scope. That's all.
`az vm show` is a pure ARM GET; the CTN never accesses the guest OS,
never executes run commands, never reads serial console output, and
never interacts with the data plane in any way.

---

## ESP Policy Examples

### Baseline -- VM exists with expected size, OS, and encryption

```esp
META
    esp_id `example-vm-baseline-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `azure`
    criticality `high`
    control_mapping `KSI:KSI-CMT-RMV`
    title `VM baseline - size, OS, encryption, identity`
META_END

DEF
    OBJECT vm_prod
        name `vm-prooflayer-demo`
        resource_group `rg-prooflayer-demo-eastus`
    OBJECT_END

    STATE vm_baseline
        found boolean = true
        provisioning_state string = `Succeeded`
        os_type string = `Linux`
        vm_size string = `Standard_D2s_v6`
        os_disk_encrypted_with_cmk boolean = true
        has_managed_identity boolean = true
        boot_diagnostics_enabled boolean = true
    STATE_END

    CRI AND
        CTN az_virtual_machine
            TEST all all AND
            STATE_REF vm_baseline
            OBJECT_REF vm_prod
        CTN_END
    CRI_END
DEF_END
```

### Security hardening -- SSH only, MDE, no Spot

```esp
STATE vm_hardened
    found boolean = true
    password_auth_disabled boolean = true
    mde_extension_installed boolean = true
    priority string = `Regular`
    vm_agent_provisioned boolean = true
STATE_END
```

### Trusted Launch -- Secure Boot + vTPM required

```esp
STATE vm_trusted_launch
    found boolean = true
    secure_boot_enabled boolean = true
    vtpm_enabled boolean = true
    security_type string = `TrustedLaunch`
STATE_END
```

### Encryption at host + CMK disk encryption

```esp
STATE vm_encrypted
    found boolean = true
    encryption_at_host boolean = true
    os_disk_encrypted_with_cmk boolean = true
    os_disk_storage_type string = `Premium_LRS`
STATE_END
```

### Availability zone required

```esp
STATE vm_zonal
    found boolean = true
    has_availability_zone boolean = true
STATE_END
```

### Image pinning -- approved publisher and SKU

```esp
STATE vm_approved_image
    found boolean = true
    image_publisher string = `resf`
    image_offer string = `rockylinux-x86_64`
    image_sku string = `9-base`
STATE_END
```

### Data disk count check

```esp
STATE vm_storage
    found boolean = true
    data_disk_count int >= 1
    os_disk_size_gb int >= 10
STATE_END
```

### Tag compliance via record_checks

```esp
STATE vm_tagged
    found boolean = true
    record
        field tags.Environment string = `demo`
        field tags.FedRAMPImpactLevel string = `moderate`
    record_end
STATE_END
```

### Per-extension assertion via record_checks

```esp
STATE vm_mde_healthy
    found boolean = true
    record
        field resources[0].name string = `MDE.Linux`
        field resources[0].provisioningState string = `Succeeded`
        field resources[0].autoUpgradeMinorVersion boolean = true
    record_end
STATE_END
```

### NotFound path -- VM must not exist

```esp
STATE vm_absent
    found boolean = false
STATE_END
```

---

## Error Conditions

| Condition                                             | Collector behavior                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| VM does not exist (real RG + missing/malformed name)  | `found=false`, `resource={}` - stderr matches `(ResourceNotFound)`  |
| RG does not exist / caller has no access              | `found=false` - stderr matches `(AuthorizationFailed)` scoped to `/virtualMachines/` |
| `name` missing from OBJECT                            | `InvalidObjectConfiguration` - Error                               |
| `resource_group` missing from OBJECT                  | `InvalidObjectConfiguration` - Error                               |
| `az` binary missing / not authenticated               | `CollectionError::CollectionFailed` - bubbles up                    |
| Unexpected non-zero exit with non-NotFound stderr     | `CollectionError::CollectionFailed`                                 |
| Malformed JSON in stdout on success                   | `CollectionError::CollectionFailed`                                 |

### NotFound detection logic

The collector treats a non-zero `az` exit as `found=false` when stderr
matches either:

1. `(ResourceNotFound)` / `Code: ResourceNotFound` - covers real RG with
   missing or malformed VM name (exit code 3).
2. `(AuthorizationFailed)` **and** the scope string contains
   `/virtualMachines/` (case-insensitive) - covers fake or inaccessible
   RG (exit code 1). An `AuthorizationFailed` that does NOT mention
   `/virtualMachines/` is treated as a real error, not a NotFound.

---

## Non-Goals

These are **never** in scope for this CTN:

1. **No mutation.** The CTN will never call `az vm create`, `update`,
   `delete`, `start`, `stop`, `deallocate`, `restart`, or `redeploy`.
   All inspection is via `show` only.
2. **No guest OS access.** The CTN never executes `az vm run-command`,
   never reads serial console output, never accesses the guest OS via
   SSH/RDP or any other channel.
3. **No instance view.** The CTN reads the ARM model only (`az vm show`),
   not the instance view (`az vm get-instance-view`). Power state,
   VM agent status, and extension health details require the instance
   view -- a future behavior modifier could add this.
4. **No NIC/IP resolution.** Network interface details (private IP,
   public IP, NSG) require separate `az network nic show` calls. Use
   `az_nsg` for NSG validation.
5. **No disk-level detail.** Per-disk encryption settings, IOPS, and
   throughput require `az disk show` calls. Use a future `az_managed_disk`
   CTN for individual disk validation.

---

## Related CTN Types

| CTN Type                          | Relationship                                                    |
| --------------------------------- | --------------------------------------------------------------- |
| `az_resource_group`               | Parent RG housing the VM                                        |
| `az_virtual_network`              | VNet containing the subnet the VM's NIC is attached to          |
| `az_nsg`                          | NSG attached to the VM's NIC or subnet                          |
| `az_key_vault`                    | Key Vault holding CMK keys referenced by the DES                |
| `az_log_analytics_workspace`      | LAW receiving diagnostic logs and MDE telemetry                 |
| `az_diagnostic_setting`           | Diagnostic settings on the VM resource                          |
| `az_storage_account`              | Storage account for boot diagnostics (if custom URI)            |
