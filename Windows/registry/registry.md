# registry

## Overview

Queries a single Windows registry value (hive + key + name) and exposes
its existence, type, and parsed value for STIG-style comparison.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** UAC, telemetry, SMB signing, crypto, and other policy-keyed registry settings

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                | Example                                      |
| ------ | ------ | -------- | ------------------------------------------ | -------------------------------------------- |
| `hive` | string | Yes      | Registry hive (short or long form)         | `HKLM`, `HKEY_LOCAL_MACHINE`                 |
| `key`  | string | Yes      | Key path (backslash-separated, no prefix)  | `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` |
| `name` | string | Yes      | Value name                                 | `EnableLUA`, `AllowTelemetry`                |

### Notes

- Valid hives: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG` and their short aliases `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`.
- Use backslashes in `key`. Do not include the hive prefix in `key`.

---

## Collected Data Fields (Output)

| Field    | Type    | Required | Description                                                          |
| -------- | ------- | -------- | -------------------------------------------------------------------- |
| `exists` | boolean | Yes      | Whether the value was found                                          |
| `value`  | string  | Yes      | Value as string (DWORD/QWORD normalized from hex to decimal)         |
| `type`   | string  | No       | Registry type (`reg_sz`, `reg_dword`, `reg_qword`, ...) - `reg` executor only |

---

## State Fields (Validation)

| Field           | Type    | Operations                                              | Maps To | Description                                        |
| --------------- | ------- | ------------------------------------------------------- | ------- | -------------------------------------------------- |
| `exists`        | boolean | `=`, `!=`                                               | exists  | Whether the value exists                           |
| `type`          | string  | `=`, `!=`, `ieq`                                        | type    | Registry type, lowercase                           |
| `value`         | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match`, `ieq`, `ine` | value | Value as string |
| `value_int`     | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                         | value   | Value parsed as integer (DWORD/QWORD)              |
| `value_version` | version | `=`, `!=`, `>`, `<`, `>=`, `<=`                         | value   | Value parsed as semver                             |

### Valid Type Values

`reg_sz`, `reg_expand_sz`, `reg_binary`, `reg_dword`, `reg_dword_big_endian`, `reg_link`, `reg_multi_sz`, `reg_resource_list`, `reg_full_resource_descriptor`, `reg_resource_requirements_list`, `reg_qword`, `reg_none`

---

## Collection Strategy

| Property                     | Value               |
| ---------------------------- | ------------------- |
| Collector Type               | `windows_registry`  |
| Collection Mode              | Metadata            |
| Required Capabilities        | `registry_read`     |
| Expected Collection Time     | ~100ms              |
| Memory Usage                 | ~1MB                |
| Requires Elevated Privileges | No                  |

---

## Command Execution

### Default (reg.exe)

```
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
```

Output:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```

The collector normalizes hex DWORD/QWORD to decimal (`0x1` -> `1`) and
lowercases the type (`REG_DWORD` -> `reg_dword`).

### PowerShell (`behavior executor powershell`)

```
powershell -NoProfile -NonInteractive -Command "Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\...' -Name 'EnableLUA'"
```

PowerShell executor returns the raw value only - `type` is not populated.

### Whitelisted Commands

| Command   | Path                          |
| --------- | ----------------------------- |
| `reg.exe` | `C:\Windows\System32\reg.exe` |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

### Behaviors

| Behavior   | Values             | Default | Description                               |
| ---------- | ------------------ | ------- | ----------------------------------------- |
| `executor` | `reg`, `powershell`| `reg`   | Registry collection backend               |

---

## ESP Examples

### UAC is enabled

```esp
OBJECT uac_enablelua
    hive `HKLM`
    key `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    name `EnableLUA`
OBJECT_END

STATE uac_on
    exists boolean = true
    value_int int = 1
STATE_END

CTN registry
    TEST at_least_one all AND
    STATE_REF uac_on
    OBJECT_REF uac_enablelua
CTN_END
```

### SMB signing required on the server side

```esp
OBJECT smb_server_signing
    hive `HKLM`
    key `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
    name `RequireSecuritySignature`
OBJECT_END

STATE signing_required
    exists boolean = true
    value_int int = 1
STATE_END

CTN registry
    TEST at_least_one all AND
    STATE_REF signing_required
    OBJECT_REF smb_server_signing
CTN_END
```

### Telemetry level at or below Security

```esp
OBJECT telemetry_level
    hive `HKLM`
    key `SOFTWARE\Policies\Microsoft\Windows\DataCollection`
    name `AllowTelemetry`
OBJECT_END

STATE telemetry_min
    exists boolean = true
    value_int int <= 1
STATE_END

CTN registry
    TEST at_least_one all AND
    STATE_REF telemetry_min
    OBJECT_REF telemetry_level
CTN_END
```

---

## Error Conditions

| Condition                       | Error Type         | Effect on TEST                               |
| ------------------------------- | ------------------ | -------------------------------------------- |
| Key or value missing            | N/A                | `exists` = false, `value` = ""               |
| Access denied on hive/key       | `AccessDenied`     | Error state                                  |
| reg.exe timeout (>30s)          | `CollectionFailed` | Error state                                  |
| reg.exe not found               | `CollectionFailed` | Error state                                  |
| PowerShell executor: key exists but value name missing | N/A | `exists` = false                    |

---

## Platform Notes

### Windows Server 2022 (primary target)

- Both `reg.exe` and Windows PowerShell 5.1 are present by default.
- `reg.exe` is faster and returns type information; `powershell` executor is a fallback when `reg` is locked down.

### Windows 10 / Windows 11

- Same interface; policy keys under `HKLM\SOFTWARE\Policies\...` match the Win2022 layout.

### Caveats

- `reg query` returns exit code 1 when the value does not exist - the collector maps this to `exists=false` rather than a failure.
- DWORD values are always normalized to decimal regardless of executor.

---

## Security Considerations

- No elevated privileges required for most policy-relevant hives.
- Some hives (`HKLM\SECURITY`, encrypted SAM entries) require SYSTEM; expect `AccessDenied` if the agent is not running as SYSTEM.
- `reg.exe` is a signed Microsoft binary and whitelisted via its absolute path.

---

## Related CTN Types

| CTN Type           | Relationship                                                  |
| ------------------ | ------------------------------------------------------------- |
| `registry_subkeys` | Enumerate subkeys under a parent key (e.g. smart-card readers) |
| `windows_security_policy` | Overlapping STIG controls expressed via secedit rather than registry |
| `windows_audit_policy`    | Advanced audit settings (registry keys alone are insufficient) |
