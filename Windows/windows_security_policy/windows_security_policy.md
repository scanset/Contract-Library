# windows_security_policy

## Overview

Validates Security Options (`[System Access]`) and User Rights Assignment
(`[Privilege Rights]`) entries from a `secedit /export` INF. One object
per policy name; state fields cover existence, raw value, integer value,
and member count.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** Password policy, lockout, guest account, user-rights SID
assignments required by STIGs / CIS benchmarks.

---

## Object Fields (Input)

| Field         | Type   | Required | Description                                           | Example                   |
| ------------- | ------ | -------- | ----------------------------------------------------- | ------------------------- |
| `policy_name` | string | Yes      | INF key name as emitted by `secedit /export`          | `MinimumPasswordLength`, `EnableGuestAccount`, `SeNetworkLogonRight` |

- Security Options: use the `[System Access]` key (`EnableGuestAccount`, `LockoutBadCount`, `MinimumPasswordAge`, ...).
- User Rights Assignment: use the `Se...Privilege` / `Se...Right` constant (`SeTrustedCredManAccessPrivilege`, `SeNetworkLogonRight`, ...).

---

## Collected Data Fields (Output)

| Field    | Type    | Required | Description                                                             |
| -------- | ------- | -------- | ----------------------------------------------------------------------- |
| `exists` | boolean | Yes      | Whether the policy appears in the export                                |
| `value`  | string  | Yes      | Raw RHS string. For User Rights: comma-separated `*SID` list (e.g. `*S-1-5-32-544,*S-1-5-19`) |

---

## State Fields (Validation)

| Field          | Type    | Operations                                                                                 | Maps To | Description                                           |
| -------------- | ------- | ------------------------------------------------------------------------------------------ | ------- | ----------------------------------------------------- |
| `exists`       | boolean | `=`, `!=`                                                                                  | `exists`| Policy present in export                              |
| `value`        | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `pattern_match`, `ieq`, `ine`     | `value` | Raw value; use `contains`/`not_contains` for SID lists|
| `value_int`    | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                                                            | `value` | Numeric Security Options (fails on non-numeric value) |
| `member_count` | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                                                            | `value` | Count of comma-separated entries (User Rights)        |

---

## Collection Strategy

| Property                     | Value                       |
| ---------------------------- | --------------------------- |
| Collector Type               | `windows_security_policy`   |
| Collection Mode              | Metadata                    |
| Required Capabilities        | `secedit_export`            |
| Expected Collection Time     | ~1500ms                     |
| Memory Usage                 | ~2MB                        |
| Requires Elevated Privileges | **Yes** (local Administrator) |

---

## Command Execution

`secedit` can only export to a file, so the collector wraps it in a
PowerShell one-liner. Invoked via the PowerShell executor (no separate
secedit allowlist):

```
$tmp = "$env:TEMP\esp-secedit-<guid>.inf"
secedit /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet
Get-Content -LiteralPath $tmp -Raw -Encoding Unicode
Remove-Item -LiteralPath $tmp -Force
```

### Output (INF excerpt)

```
[System Access]
MinimumPasswordAge = 1
EnableGuestAccount = 0
LockoutBadCount = 3

[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
```

The parser is BOM-tolerant and ignores `;` comment lines and
non-targeted sections (`[Unicode]`, `[Version]`, etc.).

---

## ESP Examples

### Minimum password length is at least 14

```esp
OBJECT min_pwlen
    policy_name `MinimumPasswordLength`
OBJECT_END

STATE len_ge_14
    exists boolean = true
    value_int int >= 14
STATE_END

CTN windows_security_policy
    TEST at_least_one all AND
    STATE_REF len_ge_14
    OBJECT_REF min_pwlen
CTN_END
```

### Account lockout threshold is enabled (non-zero, <= 3)

```esp
OBJECT lockout_threshold
    policy_name `LockoutBadCount`
OBJECT_END

STATE lockout_enforced
    exists boolean = true
    value_int int > 0
    value_int int <= 3
STATE_END

CTN windows_security_policy
    TEST at_least_one all AND
    STATE_REF lockout_enforced
    OBJECT_REF lockout_threshold
CTN_END
```

### Only Administrators can access the computer from the network

```esp
OBJECT network_logon_right
    policy_name `SeNetworkLogonRight`
OBJECT_END

STATE admins_only
    exists boolean = true
    value string contains `*S-1-5-32-544`
    value string not_contains `*S-1-5-32-545`
STATE_END

CTN windows_security_policy
    TEST at_least_one all AND
    STATE_REF admins_only
    OBJECT_REF network_logon_right
CTN_END
```

### No accounts granted "Act as part of the operating system"

```esp
OBJECT act_as_os
    policy_name `SeTcbPrivilege`
OBJECT_END

STATE empty_right
    exists boolean = true
    member_count int = 0
STATE_END

CTN windows_security_policy
    TEST at_least_one all AND
    STATE_REF empty_right
    OBJECT_REF act_as_os
CTN_END
```

---

## Error Conditions

| Condition                           | Error Type         | Effect                                    |
| ----------------------------------- | ------------------ | ----------------------------------------- |
| Agent not running as Administrator  | `AccessDenied`     | `secedit /export` fails; Error state      |
| Temp dir not writable               | `CollectionFailed` | Error state                               |
| Policy not present in export        | N/A                | `exists` = false                          |
| `value_int` requested on non-numeric RHS | Comparison fails | `false` for all operations                |

---

## Platform Notes

### Windows Server 2022 (primary)

- `secedit.exe` is present by default; export is supported with the SECURITYPOLICY + USER_RIGHTS areas.
- INF output is UTF-16 LE with BOM; `Get-Content -Encoding Unicode` decodes it and the parser strips the leading BOM.

### Caveats

- `secedit /export` requires local Administrator - without it the command returns non-zero and an empty INF.
- A User Rights entry with an empty RHS (`SeTrustedCredManAccessPrivilege =`) means "no accounts granted" - `value` will be `""`, `member_count` will be `0`.
- SIDs appear with a leading `*` prefix in the INF (e.g. `*S-1-5-32-544`). Include the `*` when using `value contains`.

---

## Security Considerations

- Requires local Administrator (privileged capability `secedit_export`).
- Exports a large set of sensitive settings; the temp INF is deleted even on non-zero exit.
- Read-only - no policy mutation.

---

## Related CTN Types

| CTN Type                 | Relationship                                                   |
| ------------------------ | -------------------------------------------------------------- |
| `windows_audit_policy`   | Advanced audit subcategories (not covered by secedit export)   |
| `registry`               | Security Options have registry backing; secedit is the policy-layer view |
| `windows_local_user`     | Per-account enforcement of the policy settings (e.g. Guest disabled) |
| `windows_local_group`    | Resolving SID lists from User Rights to real group members     |
