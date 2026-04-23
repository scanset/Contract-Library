# windows_file_metadata

## Overview

Covers basic filesystem metadata on a single file or directory via
PowerShell `Get-Item` (plus `Get-Acl` for owner SID resolution).
Complements `windows_file_acl`, which covers the full ACL / SDDL.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG controls asserting ownership (`owner_id`), size bounds
(security event log), attribute flags (Hidden/System on pagefile/BCD/SAM),
and basic reachability (`readable`/`writable`).

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                                                  | Example                                       |
| ------ | ------ | -------- | ---------------------------------------------------------------------------- | --------------------------------------------- |
| `path` | string | Yes      | Filesystem path (file or directory). Drive-letter, UNC, and admin shares OK. | `C:\Windows\System32\cmd.exe`, `\\srv\share$` |

Do not use PowerShell-provider paths (e.g. `HKLM:\...`) - registry
metadata belongs on `windows_registry_acl` / `registry`. Path is passed
to `Get-Item` verbatim after safety validation; quotes, backticks,
semicolons, and subexpression syntax are rejected.

---

## Collected Data Fields (Output)

| Field          | Type    | Required | Description                                                           |
| -------------- | ------- | -------- | --------------------------------------------------------------------- |
| `exists`       | boolean | Yes      | Path resolves on this host                                            |
| `readable`     | boolean | No       | Current principal can open for reading (File.OpenRead / first child)  |
| `writable`     | boolean | No       | ReadOnly attribute clear (NOT an ACL-based check)                     |
| `is_hidden`    | boolean | No       | Hidden attribute bit set                                              |
| `is_system`    | boolean | No       | System attribute bit set                                              |
| `is_directory` | boolean | No       | `PSIsContainer` - true for directories                                |
| `is_readonly`  | boolean | No       | ReadOnly attribute bit set                                            |
| `is_archive`   | boolean | No       | Archive attribute bit set                                             |
| `size`         | int     | No       | File size in bytes (0 for directories)                                |
| `owner`        | string  | No       | Owner friendly name (e.g. `BUILTIN\Administrators`)                   |
| `owner_id`     | string  | No       | Owner SID string (e.g. `S-1-5-18`)                                    |
| `owner_error`  | string  | No       | Get-Acl failure message; present iff owner/owner_id are absent        |
| `attributes`   | string  | No       | Comma-joined .NET FileAttributes enum string                          |

`owner_id` resolves via `NTAccount.Translate(SecurityIdentifier)` and
falls back to the `O:` segment of the SDDL when translation fails.
`owner_error` lets policies distinguish "ACL unreadable under current
auth context" from "file genuinely has no owner."

---

## State Fields (Validation)

| Field          | Type    | Operations                                                                             | Description                   |
| -------------- | ------- | -------------------------------------------------------------------------------------- | ----------------------------- |
| `exists`       | boolean | `=`, `!=`                                                                              | Path resolves (required)      |
| `readable`     | boolean | `=`, `!=`                                                                              | Readable by current principal |
| `writable`     | boolean | `=`, `!=`                                                                              | ReadOnly attribute clear      |
| `is_hidden`    | boolean | `=`, `!=`                                                                              | Hidden attribute              |
| `is_system`    | boolean | `=`, `!=`                                                                              | System attribute              |
| `is_directory` | boolean | `=`, `!=`                                                                              | Is a directory                |
| `is_readonly`  | boolean | `=`, `!=`                                                                              | ReadOnly attribute            |
| `is_archive`   | boolean | `=`, `!=`                                                                              | Archive attribute             |
| `size`         | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                                                        | Byte size                     |
| `owner`        | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Owner friendly name           |
| `owner_id`     | string  | same as owner                                                                          | Owner SID                     |
| `owner_error`  | string  | same as owner                                                                          | Get-Acl error message         |
| `attributes`   | string  | same as owner                                                                          | FileAttributes enum string    |

---

## Collection Strategy

| Property                     | Value                   |
| ---------------------------- | ----------------------- |
| Collector Type               | `windows_file_metadata` |
| Collection Mode              | Metadata                |
| Required Capabilities        | `powershell_exec`       |
| Expected Collection Time     | ~400ms                  |
| Memory Usage                 | ~1MB                    |
| Requires Elevated Privileges | No                      |

### Behaviors

None in v1. Single backend (PowerShell + Get-Acl for owner resolution).

---

## Command Execution

```
Get-Item -LiteralPath '<path>' | Select-Object ...  # attributes, size, PSIsContainer
Get-Acl  -LiteralPath '<path>' | Select-Object Owner, Sddl
```

Results are combined and emitted as a single JSON document. Owner SID
is resolved via `NTAccount.Translate(SecurityIdentifier)`; on failure
the collector parses the `O:` segment of the SDDL as a fallback.

### Whitelisted Commands

| Command          | Path                                                        |
| ---------------- | ----------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |

---

## ESP Examples

### cmd.exe is owned by TrustedInstaller

```esp
OBJECT cmd_exe
    path `C:\Windows\System32\cmd.exe`
OBJECT_END

STATE owned_by_ti
    exists boolean = true
    owner string contains `TrustedInstaller`
STATE_END

CRI AND
    CTN windows_file_metadata
        TEST all all AND
        STATE_REF owned_by_ti
        OBJECT_REF cmd_exe
    CTN_END
CRI_END
```

### Security event log is at least 1 GB

```esp
OBJECT sec_evtx
    path `C:\Windows\System32\winevt\Logs\Security.evtx`
OBJECT_END

STATE large_enough
    exists boolean = true
    size int >= 1073741824
STATE_END

CRI AND
    CTN windows_file_metadata
        TEST all all AND
        STATE_REF large_enough
        OBJECT_REF sec_evtx
    CTN_END
CRI_END
```

### pagefile.sys owner SID is SYSTEM

```esp
OBJECT pagefile
    path `C:\pagefile.sys`
OBJECT_END

STATE system_owned
    exists boolean = true
    owner_id string = `S-1-5-18`
STATE_END

CRI AND
    CTN windows_file_metadata
        TEST all all AND
        STATE_REF system_owned
        OBJECT_REF pagefile
    CTN_END
CRI_END
```

---

## Error Conditions

| Condition                | Symptom                                   | Effect on TEST     |
| ------------------------ | ----------------------------------------- | ------------------ |
| Path not found           | Get-Item returns nothing                  | `exists` = false   |
| Get-Acl access denied    | Caught; owner/owner_id absent             | `owner_error` set  |
| Invalid path characters  | Caller-side validator rejects             | `ValidationError`  |
| PowerShell not available | Whitelisted path missing                  | `CollectionFailed` |
| Malformed JSON output    | Parser error                              | `CollectionFailed` |

---

## Platform Notes

### Windows Server 2022 (primary)

- All fields populated for reachable paths under standard agent service account.
- Protected paths (SAM, SECURITY hive files) may return `owner_error` unless the scan identity has `SeSecurityPrivilege`.

### Caveats

- `writable` is an attribute heuristic only. True ACL writability belongs on `windows_file_acl`.
- UNC paths depend on network authentication; failures surface as `exists = false` or `CollectionFailed` depending on the remote response.
- Size is 0 for directories; use recursive enumeration CTNs if directory size matters.

---

## Security Considerations

- Read-only; no elevation required for typical policy-relevant paths.
- Path validator rejects quote/backtick/subexpression/semicolon chars before any invocation, preventing PowerShell injection.
- Owner SIDs and friendly names may leak domain structure; treat collected evidence as sensitive.

---

## Related CTN Types

| CTN Type               | Relationship                                           |
| ---------------------- | ------------------------------------------------------ |
| `windows_file_acl`     | Full SDDL / per-ACE inspection on the same path        |
| `windows_registry_acl` | Same ACL shape, applied to registry keys               |
| `registry`             | Value-level checks on registry-backed file paths       |
| `windows_service`      | Services whose ImagePath refers to a file on disk      |
| `windows_feature`      | Feature payloads that install the files this CTN reads |
