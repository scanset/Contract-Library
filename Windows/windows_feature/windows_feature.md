# windows_feature

## Overview

Validates a single Windows feature by name using either
`Get-WindowsOptionalFeature` (DISM, default, Client+Server) or
`Get-WindowsFeature` (ServerManager, Server-only). The two namespaces
overlap partially - pick the backend matching the STIG control's vocabulary.

**Platform:** Windows Server 2022 (and Win10/Win11 for `optionalfeature`)
**Use Case:** STIG checks asserting SMBv1/Telnet removal, required role/feature presence, and payload-removed status for deprecated components.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                             | Example                                      |
| ------ | ------ | -------- | --------------------------------------- | -------------------------------------------- |
| `name` | string | Yes      | Feature name; syntax varies by backend. | `SMB1Protocol`, `TelnetClient`, `Web-Server`, `RSAT-AD-Tools`, `Windows-Defender` |

Case-insensitive. Allowed chars: alphanumerics, hyphen, underscore, dot.

---

## Collected Data Fields (Output)

| Field          | Type    | Required | Description                                                       |
| -------------- | ------- | -------- | ----------------------------------------------------------------- |
| `exists`       | boolean | Yes      | Feature name resolved on the active backend                       |
| `enabled`      | boolean | No       | Fully enabled/installed (payload-removed counts as not enabled)   |
| `state`        | string  | No       | Raw backend state string                                          |
| `display_name` | string  | No       | Human-readable name (windowsfeature backend only)                 |
| `feature_type` | string  | No       | `Role`, `RoleService`, `Feature` (windowsfeature) or `OptionalFeature` |

---

## State Fields (Validation)

| Field          | Type    | Operations                                                                             | Description               |
| -------------- | ------- | -------------------------------------------------------------------------------------- | ------------------------- |
| `exists`       | boolean | `=`, `!=`                                                                              | Feature resolves          |
| `enabled`      | boolean | `=`, `!=`                                                                              | Fully installed/enabled   |
| `state`        | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Raw state string          |
| `display_name` | string  | same as state                                                                          | Human-readable name       |
| `feature_type` | string  | same as state                                                                          | Category                  |

### Valid `state` values

- optionalfeature: `Enabled`, `Disabled`, `EnableWithPayloadRemoved`, `DisabledWithPayloadRemoved`
- windowsfeature: `Installed`, `Available`, `Removed`

### Valid `feature_type` values

`Role`, `RoleService`, `Feature`, `OptionalFeature`

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector Type               | `windows_feature`    |
| Collection Mode              | Metadata             |
| Required Capabilities        | `powershell_exec`    |
| Expected Collection Time     | ~2000ms              |
| Memory Usage                 | ~2MB                 |
| Requires Elevated Privileges | No                   |

### Behaviors

| Behavior          | Form      | Values                              | Default           | Description                               |
| ----------------- | --------- | ----------------------------------- | ----------------- | ----------------------------------------- |
| `executor`        | Parameter | `optionalfeature`, `windowsfeature` | `optionalfeature` | Select feature-query backend              |
| `windowsfeature`  | Flag      | (presence)                          | off               | Flag form of `behavior executor windowsfeature`  |
| `optionalfeature` | Flag      | (presence)                          | off               | Flag form of `behavior executor optionalfeature` |

**Parser quirk:** `behavior executor windowsfeature` is tokenized by the ESP
behavior parser as flags `["executor","windowsfeature"]`, not as
parameter `executor="windowsfeature"`. The contract therefore registers
both `windowsfeature` and `optionalfeature` as flag behaviors so
validation accepts the tokenization; the collector checks
`has_flag("windowsfeature")` / `has_flag("optionalfeature")` first and
falls back to `get_parameter("executor")` for callers that supply an
unambiguous parameter form.

---

## Command Execution

### Default (`optionalfeature`)

```
Get-WindowsOptionalFeature -Online -FeatureName '<name>' | Select FeatureName, State | ConvertTo-Json
```

### `windowsfeature` backend (Server)

```
Get-WindowsFeature -Name '<name>' | Select Name, DisplayName, InstallState, FeatureType | ConvertTo-Json
```

`Get-WindowsFeature` walks the ServerManager catalog and is noticeably slower than the DISM variant.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### SMBv1 is disabled

```esp
OBJECT smb1
    name `SMB1Protocol`
OBJECT_END

STATE smb1_off
    exists boolean = true
    enabled boolean = false
    state string = `Disabled`
STATE_END

CTN windows_feature
    TEST at_least_one all AND
    STATE_REF smb1_off
    OBJECT_REF smb1
CTN_END
```

### Telnet Client payload removed

```esp
OBJECT telnet
    name `TelnetClient`
OBJECT_END

STATE telnet_removed
    exists boolean = true
    enabled boolean = false
    state string = `DisabledWithPayloadRemoved`
STATE_END

CTN windows_feature
    TEST at_least_one all AND
    STATE_REF telnet_removed
    OBJECT_REF telnet
CTN_END
```

### IIS Web-Server role is installed (windowsfeature backend)

```esp
OBJECT web_server
    name `Web-Server`
    behavior executor windowsfeature
OBJECT_END

STATE installed
    exists boolean = true
    enabled boolean = true
    state string = `Installed`
    feature_type string = `Role`
STATE_END

CTN windows_feature
    TEST at_least_one all AND
    STATE_REF installed
    OBJECT_REF web_server
CTN_END
```

### STIG-style "feature must not be installed" (windowsfeature backend)

This is the canonical shape used by `generate_cc.py` for STIG WN22-00-000320..410
(Fax, Web-Ftp-Service, PNRP, Simple-TCPIP, Telnet-Client, TFTP-Client, FS-SMB1,
PowerShell-v2). The backend is `windowsfeature` (Server), asserting the feature
is not enabled. `Removed` and `Available` both satisfy `enabled = false`.

```esp
OBJECT target
    name `Telnet-Client`
    behavior executor windowsfeature
OBJECT_END

STATE compliant
    enabled boolean = false
STATE_END

CRI AND
    CTN windows_feature
        TEST all all AND
        STATE_REF compliant
        OBJECT_REF target
    CTN_END
CRI_END
```

---

## Error Conditions

| Condition                         | Symptom                                       | Effect on TEST          |
| --------------------------------- | --------------------------------------------- | ----------------------- |
| Feature name not recognised       | Backend returns no record                     | `exists` = false        |
| Wrong backend for vocabulary      | `optionalfeature` returns empty for a role    | `exists` = false        |
| `Get-WindowsFeature` on client SKU| Cmdlet unavailable                            | `CollectionFailed`      |
| Invalid character in name         | Caller-side validator rejects                 | `ValidationError`       |

---

## Platform Notes

### Windows Server 2022 (primary)

- Both backends present; `windowsfeature` adds `DisplayName` + `FeatureType`.
- DISM features and ServerManager features partially overlap (e.g. `SMB1Protocol` vs `FS-SMB1`). Pick the vocabulary the STIG cites.

### Caveats

- No automatic fallback between backends. If the name doesn't resolve with the chosen backend, `exists` is false; switch backend via `behavior executor`.
- Payload-removed state is treated as "not enabled" - distinguish via the raw `state` field.

---

## Security Considerations

- Read-only query; no elevation required.
- Feature enumeration can leak host role (DC, file server, IIS). Treat collected evidence as sensitive.
- Feature names are constrained to a safe ASCII subset before invocation, preventing PS injection.

---

## Related CTN Types

| CTN Type                    | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `windows_service`           | Services installed as part of a feature payload            |
| `windows_firewall_rule`     | Rules published by feature installers                      |
| `windows_file_acl`          | ACLs on feature payload directories                        |
| `windows_registry_acl`      | Registry ACLs on feature-specific configuration keys       |
| `windows_hotfix`            | Updates that change feature payloads                       |
| `registry`                  | Feature backing keys under `HKLM\SOFTWARE`                 |
