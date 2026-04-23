# windows_registry_acl

## Overview

Validates the security descriptor on a single registry key via PowerShell
`Get-Acl -LiteralPath`. Exposes owner, SDDL, inheritance flag, and a
denormalised per-ACE string so STIG policies can assert on identity-right
combinations without walking nested objects.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks on policy-key ownership, absence of Users write ACEs, inheritance blocking, and golden-SDDL comparisons for security-sensitive hives.

---

## Object Fields (Input)

| Field      | Type   | Required | Description                             | Example                                                     |
| ---------- | ------ | -------- | --------------------------------------- | ----------------------------------------------------------- |
| `key_path` | string | Yes      | Registry key path (PS-provider form or `HKEY_*` form). | `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Defender` |

Passed to `Get-Acl -LiteralPath` verbatim after safety validation.

---

## Collected Data Fields (Output)

| Field                    | Type    | Required | Description                                                  |
| ------------------------ | ------- | -------- | ------------------------------------------------------------ |
| `exists`                 | boolean | Yes      | Key resolves on this host                                    |
| `inheritance_protected`  | boolean | No       | `AreAccessRulesProtected`                                    |
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
| `exists`                | boolean | `=`, `!=`                                                                              | Key resolves             |
| `inheritance_protected` | boolean | `=`, `!=`                                                                              | Inheritance blocked      |
| `owner`                 | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Owner identity           |
| `group`                 | string  | same as owner                                                                          | Primary group            |
| `sddl`                  | string  | same as owner                                                                          | SDDL golden comparison   |
| `ace_count`             | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | ACE count                |
| `aces`                  | string  | same as owner                                                                          | Per-ACE records          |
| `allow_identities`      | string  | same as owner                                                                          | Allow ACE identities     |
| `deny_identities`       | string  | same as owner                                                                          | Deny ACE identities      |

RIGHTS values in the `aces` field are decoded `RegistryRights` strings such as `FullControl`, `ReadKey`, or `SetValue, CreateSubKey`.

---

## Collection Strategy

| Property                     | Value                    |
| ---------------------------- | ------------------------ |
| Collector Type               | `windows_registry_acl`   |
| Collection Mode              | Metadata                 |
| Required Capabilities        | `powershell_exec`        |
| Expected Collection Time     | ~500ms                   |
| Memory Usage                 | ~1MB                     |
| Requires Elevated Privileges | No                       |

### Behaviors

| Behavior                | Values           | Default | Description                                          |
| ----------------------- | ---------------- | ------- | ---------------------------------------------------- |
| `decode_generic_flags`  | `true`, `false`  | `true`  | Translate Win32 `GENERIC_*` bits to `KEY_*`          |

---

## Command Execution

Single PowerShell call:

```
Get-Acl -LiteralPath '<key_path>' | Select Owner, Group, Sddl, AreAccessRulesProtected, Access | ConvertTo-Json
```

`RegistryRights` is returned as an int mask and decoded Rust-side. `HKEY_*` form is auto-converted to the PS-provider form before invocation.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### LanmanServer parameters key is owned by SYSTEM and has no Users Allow ACE

```esp
OBJECT lanman_params
    key_path `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
OBJECT_END

STATE locked_down
    exists boolean = true
    owner string contains `SYSTEM`
    aces string not_contains `BUILTIN\Users|Allow`
STATE_END

CTN windows_registry_acl
    TEST at_least_one all AND
    STATE_REF locked_down
    OBJECT_REF lanman_params
CTN_END
```

### HKLM:\SECURITY has inheritance blocked

```esp
OBJECT security_hive
    key_path `HKLM:\SECURITY`
OBJECT_END

STATE inheritance_blocked
    exists boolean = true
    inheritance_protected boolean = true
STATE_END

CTN windows_registry_acl
    TEST at_least_one all AND
    STATE_REF inheritance_blocked
    OBJECT_REF security_hive
CTN_END
```

### Winlogon key SDDL matches golden

```esp
OBJECT winlogon
    key_path `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
OBJECT_END

STATE golden_sddl
    exists boolean = true
    sddl string starts `O:BAG:SY`
    deny_identities string = ``
STATE_END

CTN windows_registry_acl
    TEST at_least_one all AND
    STATE_REF golden_sddl
    OBJECT_REF winlogon
CTN_END
```

---

## Error Conditions

| Condition                | Symptom                                              | Effect on TEST           |
| ------------------------ | ---------------------------------------------------- | ------------------------ |
| Key not found            | `ItemNotFoundException` caught, emits `{}`           | `exists` = false         |
| Injection characters     | Caller-side validator rejects                        | `ValidationError`        |
| Access denied            | Non-zero exit / Get-Acl error                        | `CollectionFailed`       |
| Malformed JSON           | Parser error                                         | `CollectionFailed`       |

---

## Platform Notes

### Windows Server 2022

- `Get-Acl -LiteralPath` accepts both `HKLM:\...` and `HKEY_LOCAL_MACHINE\...`.
- `RegistryRights` bitmask differs from `FileSystemRights`; decoder is registry-aware.
- Access to `HKLM:\SECURITY` requires SYSTEM; without elevation the owner field may be blank even if the key exists.

### Caveats

- SDDL string is deterministic but sensitive to ACE order; prefer per-ACE `contains` checks for robustness.
- HKU hive is per-user; only loaded hives are accessible.

---

## Security Considerations

- Read-only query; elevation required only for restricted hives.
- SDDL and SIDs may leak domain structure; treat collected evidence as sensitive.
- Injection-proof path validator rejects quote/backtick/subexpression syntax.
- Generic-bit translation is version-controlled in Rust, not PS - prevents drift between hosts.

---

## Related CTN Types

| CTN Type                    | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `registry`                  | Value-level checks on the same keys                        |
| `registry_subkeys`          | Enumeration of child keys whose ACLs this CTN inspects     |
| `windows_file_acl`          | Same ACL shape on filesystem objects                       |
| `windows_service`           | Services whose backing keys live under `HKLM\SYSTEM\CCS\Services` |
| `windows_security_policy`   | User-rights assignments that complement registry ACL checks|
| `windows_audit_policy`      | Audit of registry-ACL-change events                        |
