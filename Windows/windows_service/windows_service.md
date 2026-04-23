# windows_service

## Overview

Validates a Windows service by name - runtime state, start type, display
name, binary path, and service type. Data via `sc.exe` (default) or
`Get-Service` / `Get-CimInstance Win32_Service` (powershell).

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks on unnecessary/forbidden services, required
services enabled at boot, binary-path tamper detection.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                     | Example     |
| ------ | ------ | -------- | ------------------------------- | ----------- |
| `name` | string | Yes      | Service short name (NOT DisplayName) | `W32Time`, `Spooler`, `TermService`, `RemoteRegistry` |

Use the short name (`W32Time`) not the display name (`Windows Time`).

---

## Collected Data Fields (Output)

| Field          | Type    | Required | Description                          |
| -------------- | ------- | -------- | ------------------------------------ |
| `exists`       | boolean | Yes      | Service is installed                 |
| `state`        | string  | Yes      | Runtime state                        |
| `start_type`   | string  | Yes      | Boot start configuration             |
| `display_name` | string  | No       | Human-readable name                  |
| `path`         | string  | No       | Binary path (`ImagePath`)            |
| `service_type` | string  | No       | Process classification               |

---

## State Fields (Validation)

| Field          | Type    | Operations                                                                                              | Description                  |
| -------------- | ------- | ------------------------------------------------------------------------------------------------------- | ---------------------------- |
| `exists`       | boolean | `=`, `!=`                                                                                               | Service installed            |
| `state`        | string  | `=`, `!=`, `ieq`                                                                                        | Runtime state                |
| `start_type`   | string  | `=`, `!=`, `ieq`                                                                                        | Boot start type              |
| `display_name` | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match`, `ieq`, `ine`                  | Display name                 |
| `path`         | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match`, `ieq`, `ine`                  | Binary path                  |
| `service_type` | string  | `=`, `!=`, `ieq`                                                                                        | Process type                 |

### Valid `state` values

`running`, `stopped`, `paused`, `start_pending`, `stop_pending`, `continue_pending`, `pause_pending`, `unknown`

### Valid `start_type` values

`auto`, `auto_delayed`, `manual`, `disabled`, `boot`, `system`, `unknown`

### Valid `service_type` values

`own_process`, `own_process_interactive`, `share_process`, `kernel_driver`, `file_system_driver`, `win32`, `unknown`

---

## Collection Strategy

| Property                     | Value              |
| ---------------------------- | ------------------ |
| Collector Type               | `windows_service`  |
| Collection Mode              | Status             |
| Required Capabilities        | `service_query`    |
| Expected Collection Time     | ~200ms             |
| Memory Usage                 | ~1MB               |
| Requires Elevated Privileges | No                 |

### Behaviors

| Behavior   | Values              | Default | Description                 |
| ---------- | ------------------- | ------- | --------------------------- |
| `executor` | `sc`, `powershell`  | `sc`    | Service query backend       |

---

## Command Execution

### Default (sc.exe)

Two calls per service:

```
sc.exe query W32Time
sc.exe qc W32Time
```

`query` yields state + service type; `qc` yields start type, binary path,
and display name. The collector normalizes Microsoft constants to
lowercase snake_case (`AUTO_START` -> `auto`, `WIN32_OWN_PROCESS` -> `own_process`).

### PowerShell

```
powershell -NoProfile -NonInteractive -Command "Get-Service -Name W32Time | Select ..."
```

### Whitelisted Commands

| Command   | Path                           |
| --------- | ------------------------------ |
| `sc.exe`  | `C:\Windows\System32\sc.exe`   |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

---

## ESP Examples

### Windows Time service is running and starts automatically

```esp
OBJECT w32time
    name `W32Time`
OBJECT_END

STATE running_auto
    exists boolean = true
    state string = `running`
    start_type string = `auto`
STATE_END

CTN windows_service
    TEST at_least_one all AND
    STATE_REF running_auto
    OBJECT_REF w32time
CTN_END
```

### Remote Registry is disabled

```esp
OBJECT remote_reg
    name `RemoteRegistry`
OBJECT_END

STATE disabled
    start_type string = `disabled`
STATE_END

CTN windows_service
    TEST at_least_one all AND
    STATE_REF disabled
    OBJECT_REF remote_reg
CTN_END
```

### Print Spooler is stopped on domain controllers

```esp
OBJECT spooler
    name `Spooler`
OBJECT_END

STATE stopped_disabled
    state string = `stopped`
    start_type string = `disabled`
STATE_END

CTN windows_service
    TEST at_least_one all AND
    STATE_REF stopped_disabled
    OBJECT_REF spooler
CTN_END
```

---

## Error Conditions

| Condition                      | sc.exe code / symptom                 | Effect on TEST                   |
| ------------------------------ | ------------------------------------- | -------------------------------- |
| Service not installed          | `FAILED 1060:` / "does not exist"     | `exists` = false                 |
| Access denied                  | `FAILED 5:` / "Access is denied"      | `AccessDenied` error             |
| sc.exe timeout (>30s)          | -                                     | `CollectionFailed`               |
| PowerShell: service not found  | Non-zero exit + ServiceNotFoundException | `exists` = false              |

---

## Platform Notes

### Windows Server 2022 (primary)

- Both `sc.exe` and `Get-Service` present by default.
- `sc.exe qc` includes `DELAYED AUTO_START`; collector maps this to `auto_delayed`.

### Caveats

- `DisplayName` is locale-dependent; prefer `name` for the OBJECT field and use `display_name` only for informational state checks.
- Drivers appear as services with `service_type` = `kernel_driver` or `file_system_driver`.

---

## Security Considerations

- Read-only queries via `sc.exe` / `Get-Service` require no elevation for service enumeration.
- `BINARY_PATH_NAME` can expose credentials if a service is misconfigured with arguments in the command line - treat collected `path` fields as sensitive.

---

## Related CTN Types

| CTN Type                  | Relationship                                            |
| ------------------------- | ------------------------------------------------------- |
| `registry`                | Service configuration backing keys under `HKLM\SYSTEM\CurrentControlSet\Services` |
| `windows_security_policy` | User-rights assignments governing service account logon |
| `windows_audit_policy`    | Auditing of service install / state-change events       |
