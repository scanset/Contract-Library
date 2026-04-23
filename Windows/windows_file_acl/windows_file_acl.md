# windows_file_acl

## Overview

Validates the NTFS ACL on a single file or directory via PowerShell `Get-Acl`.
Exposes owner, SDDL, inheritance flag, and a denormalised per-ACE string so
STIG policies can use plain `contains`/`not_contains`/`pattern_match`
operators without walking nested structures.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks on owner identity, Everyone/Users ACE absence, inheritance blocking, and golden-SDDL comparisons for sensitive binaries and config directories.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                 | Example                              |
| ------ | ------ | -------- | ------------------------------------------- | ------------------------------------ |
| `path` | string | Yes      | Filesystem path (file or directory); drive-letter, UNC, or admin share. | `C:\Windows\System32\cmd.exe`, `\\server\share\sensitive` |

Do not pass PowerShell-provider paths (`HKLM:\...`); use `windows_registry_acl` for registry.

---

## Collected Data Fields (Output)

| Field                    | Type    | Required | Description                                                  |
| ------------------------ | ------- | -------- | ------------------------------------------------------------ |
| `exists`                 | boolean | Yes      | Path resolves on this host                                   |
| `inheritance_protected`  | boolean | No       | `AreAccessRulesProtected` (inheritance blocked)              |
| `owner`                  | string  | No       | Owner identity (friendly name or SID)                        |
| `group`                  | string  | No       | Primary group                                                |
| `sddl`                   | string  | No       | Full ACL in SDDL form                                        |
| `ace_count`              | int     | No       | Number of ACEs                                               |
| `aces`                   | string  | No       | Newline-joined `IDENTITY|TYPE|RIGHTS[|inherited]` per ACE    |
| `allow_identities`       | string  | No       | Comma-joined identities with any Allow ACE                   |
| `deny_identities`        | string  | No       | Comma-joined identities with any Deny ACE                    |

---

## State Fields (Validation)

| Field                   | Type    | Operations                                                                             | Description              |
| ----------------------- | ------- | -------------------------------------------------------------------------------------- | ------------------------ |
| `exists`                | boolean | `=`, `!=`                                                                              | Path resolves            |
| `inheritance_protected` | boolean | `=`, `!=`                                                                              | Inheritance blocked      |
| `owner`                 | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Owner identity           |
| `group`                 | string  | same as owner                                                                          | Primary group            |
| `sddl`                  | string  | same as owner                                                                          | SDDL golden comparison   |
| `ace_count`             | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | Number of ACEs           |
| `aces`                  | string  | same as owner                                                                          | Per-ACE records          |
| `allow_identities`      | string  | same as owner                                                                          | Allow ACE identities     |
| `deny_identities`       | string  | same as owner                                                                          | Deny ACE identities      |

---

## Collection Strategy

| Property                     | Value                  |
| ---------------------------- | ---------------------- |
| Collector Type               | `windows_file_acl`     |
| Collection Mode              | Metadata               |
| Required Capabilities        | `powershell_exec`      |
| Expected Collection Time     | ~500ms                 |
| Memory Usage                 | ~1MB                   |
| Requires Elevated Privileges | No                     |

### Behaviors

| Behavior                | Values           | Default | Description                                           |
| ----------------------- | ---------------- | ------- | ----------------------------------------------------- |
| `decode_generic_flags`  | `true`, `false`  | `true`  | Translate Win32 `GENERIC_*` bits to `FILE_GENERIC_*`  |

When `false`, generic bits appear as `GenericRead`/`GenericWrite`/`GenericExecute`/`GenericAll` labels - match what `icacls.exe` reports.

---

## Command Execution

Single PowerShell call:

```
Get-Acl -Path '<path>' | Select Owner, Group, Sddl, AreAccessRulesProtected, Access | ConvertTo-Json
```

`IdentityReference` is flattened via `.Value`; `AccessControlType` is int (0=Allow, 1=Deny); `FileSystemRights` is returned as the raw int bitmask and decoded Rust-side so generic-bit translation is version-controlled.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### cmd.exe owner is TrustedInstaller and no Everyone Allow ACE

```esp
OBJECT cmd_exe
    path `C:\Windows\System32\cmd.exe`
OBJECT_END

STATE locked_down
    exists boolean = true
    owner string contains `TrustedInstaller`
    aces string not_contains `Everyone|Allow`
STATE_END

CTN windows_file_acl
    TEST at_least_one all AND
    STATE_REF locked_down
    OBJECT_REF cmd_exe
CTN_END
```

### drivers\etc has inheritance blocked

```esp
OBJECT drivers_etc
    path `C:\Windows\System32\drivers\etc`
OBJECT_END

STATE inheritance_blocked
    exists boolean = true
    inheritance_protected boolean = true
STATE_END

CTN windows_file_acl
    TEST at_least_one all AND
    STATE_REF inheritance_blocked
    OBJECT_REF drivers_etc
CTN_END
```

### Program Files has no Deny ACEs

```esp
OBJECT program_files
    path `C:\Program Files`
OBJECT_END

STATE no_deny
    exists boolean = true
    deny_identities string = ``
STATE_END

CTN windows_file_acl
    TEST at_least_one all AND
    STATE_REF no_deny
    OBJECT_REF program_files
CTN_END
```

---

## Error Conditions

| Condition                | Symptom                                              | Effect on TEST           |
| ------------------------ | ---------------------------------------------------- | ------------------------ |
| Path not found           | `ItemNotFoundException` caught, emits `{}`           | `exists` = false         |
| PS injection in path     | Caller-side `is_safe_path` rejects                   | `ValidationError`        |
| Access denied            | Non-zero exit / Get-Acl error                        | `CollectionFailed`       |
| Malformed JSON           | Parser error                                         | `CollectionFailed`       |

---

## Platform Notes

### Windows Server 2022

- `Get-Acl` is built-in; no module import required.
- `FileSystemRights` serializes as an int bitmask, including negative i32 values for top-nibble generic bits (e.g. -1610612736 for `GenericRead|GenericExecute`). The collector normalises via `(mask as u32) as i64`.
- Inherited ACEs on real Win2022 hosts (e.g. `BUILTIN\Users` on `drivers\etc`) carry generic bits - leave `decode_generic_flags` at default to get readable rights strings.

### Caveats

- Path must not contain `'`, `` ` ``, `"`, `;`, `|`, `&`, newline, `$(`, or `${` - rejected before invocation.
- SDDL equality is position-sensitive; prefer per-ACE `contains` checks unless you maintain a golden SDDL fixture.

---

## Security Considerations

- Read-only query; requires no elevation for most paths a user can list.
- ACE identity strings can leak domain SID structure; treat collected `aces` as sensitive evidence.
- SDDL and owner SIDs for app-package principals may appear as raw SIDs when name resolution is unavailable.
- Injection-proof path validator rejects quote/backtick/subexpression syntax up front.

---

## Related CTN Types

| CTN Type                    | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `windows_registry_acl`      | Same ACL shape applied to registry keys                    |
| `windows_service`           | Service binary paths whose ACLs this CTN inspects          |
| `windows_feature`           | Features whose payload directories may need ACL checks     |
| `windows_security_policy`   | User-rights assignments that complement file ACL checks    |
| `windows_audit_policy`      | Audit events emitted on ACL changes                        |
| `registry`                  | Registry values that may store ACL-related configuration   |
