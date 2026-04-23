# windows_local_user

## Overview

Validates a single Windows local account - existence, enabled state,
password policy flags, description, SID, and age-in-days metrics. Uses
`Get-LocalUser` (default) or `Win32_UserAccount` (CIM fallback).

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIGs that require Guest disabled, Administrator renamed
(via RID lookup), stale accounts detected, password-expiry enforced.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                                      | Example |
| ------ | ------ | -------- | ---------------------------------------------------------------- | ------- |
| `name` | string | Yes      | SAM account name, **or** a RID suffix when `match_by_rid=true`   | `Administrator`, `Guest`, `DefaultAccount`, `500` |

- Case-insensitive matching.
- With `behavior match_by_rid true`, `name` is the numeric RID suffix (last SID segment). Use `"500"` to find the well-known Administrator regardless of rename.

---

## Collected Data Fields (Output)

| Field                     | Type    | Backend   | Description                                                    |
| ------------------------- | ------- | --------- | -------------------------------------------------------------- |
| `exists`                  | boolean | both      | Account found                                                  |
| `enabled`                 | boolean | both      | Account is enabled (CIM inverts `Disabled`)                    |
| `password_required`       | boolean | both      | Password required for interactive logon                        |
| `user_may_change_password`| boolean | powershell| User can change own password                                   |
| `password_expires`        | boolean | both      | Password expiry policy applies                                 |
| `lockout`                 | boolean | cim only  | Currently locked out                                           |
| `sid`                     | string  | both      | Security Identifier                                            |
| `description`             | string  | both      | Account description                                            |
| `full_name`               | string  | both      | Display name                                                   |
| `password_last_set_days`  | int     | powershell| Days since password last set (negative = never)                |
| `password_expires_days`   | int     | powershell| Days until password expires                                    |
| `last_logon_days`         | int     | powershell| Days since last logon (huge value if never)                    |
| `account_expires_days`    | int     | powershell| Days until account expires                                     |

---

## State Fields (Validation)

| Field                     | Type    | Operations                                                                           |
| ------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `exists`                  | boolean | `=`, `!=`                                                                            |
| `enabled`                 | boolean | `=`, `!=`                                                                            |
| `password_required`       | boolean | `=`, `!=`                                                                            |
| `user_may_change_password`| boolean | `=`, `!=`                                                                            |
| `password_expires`        | boolean | `=`, `!=`                                                                            |
| `lockout`                 | boolean | `=`, `!=`                                                                            |
| `sid`                     | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` |
| `description`             | string  | (same as above)                                                                      |
| `full_name`               | string  | (same as above)                                                                      |
| `password_last_set_days`  | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                                                      |
| `password_expires_days`   | int     | (same as above)                                                                      |
| `last_logon_days`         | int     | (same as above)                                                                      |
| `account_expires_days`    | int     | (same as above)                                                                      |

---

## Collection Strategy

| Property                     | Value                |
| ---------------------------- | -------------------- |
| Collector Type               | `windows_local_user` |
| Collection Mode              | Metadata             |
| Required Capabilities        | `powershell_exec`    |
| Expected Collection Time     | ~500ms               |
| Memory Usage                 | ~1MB                 |
| Requires Elevated Privileges | No                   |

### Behaviors

| Behavior       | Values                | Default      | Description                                          |
| -------------- | --------------------- | ------------ | ---------------------------------------------------- |
| `executor`     | `powershell`, `cim`   | `powershell` | Backend (powershell = full date fields; cim adds `lockout`, loses dates) |
| `match_by_rid` | `true`, `false`       | `false`      | When true, treat `name` as a RID suffix and match via SID pattern |

---

## Command Execution

### powershell executor (default)

```
powershell -Command "try { $u = Get-LocalUser -Name 'Administrator' -ErrorAction Stop } \
 catch [Microsoft.PowerShell.Commands.UserNotFoundException] { $u = @() }; \
 ... | ConvertTo-Json -Compress"
```

PS 5.1 date fields arrive as `/Date(epoch-ms)/` strings; collector
converts them to days-since-now.

### RID mode

```
Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' }
```

### cim executor

```
Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=TRUE AND Name='Administrator'"
```

---

## ESP Examples

### Guest account is disabled

```esp
OBJECT guest_acct
    name `Guest`
OBJECT_END

STATE guest_off
    exists boolean = true
    enabled boolean = false
STATE_END

CTN windows_local_user
    TEST at_least_one all AND
    STATE_REF guest_off
    OBJECT_REF guest_acct
CTN_END
```

### Built-in Administrator has been renamed (match by RID 500)

```esp
OBJECT admin_by_rid
    name `500`
    behavior match_by_rid true
OBJECT_END

STATE renamed
    exists boolean = true
    sid string ends_with `-500`
STATE_END

CTN windows_local_user
    TEST at_least_one all AND
    STATE_REF renamed
    OBJECT_REF admin_by_rid
CTN_END
```

### Privileged account password changed within the last 60 days

```esp
OBJECT svc_admin
    name `azureadmin`
OBJECT_END

STATE recent_pw
    exists boolean = true
    enabled boolean = true
    password_last_set_days int <= 60
STATE_END

CTN windows_local_user
    TEST at_least_one all AND
    STATE_REF recent_pw
    OBJECT_REF svc_admin
CTN_END
```

### DefaultAccount remains disabled and password-not-required

```esp
OBJECT default_acct
    name `DefaultAccount`
OBJECT_END

STATE disabled
    exists boolean = true
    enabled boolean = false
STATE_END

CTN windows_local_user
    TEST at_least_one all AND
    STATE_REF disabled
    OBJECT_REF default_acct
CTN_END
```

> Note on example 2: the `name` state-field check shown is illustrative -
> the contract doesn't expose `name` as a state field. Use `sid` matches
> or separate `description` checks for rename verification in practice.

---

## Error Conditions

| Condition                                        | Error Type         | Effect              |
| ------------------------------------------------ | ------------------ | ------------------- |
| Account not found (powershell)                   | UserNotFoundException caught | `exists` = false |
| Account not found (cim)                          | Empty result       | `exists` = false    |
| Unsafe name (contains shell metacharacters)      | `InvalidObjectConfiguration` | Error state |
| PowerShell timeout (>30s)                        | `CollectionFailed` | Error state         |
| Date field missing from Get-LocalUser            | N/A                | `*_days` field absent from collection |

---

## Platform Notes

### Windows Server 2022 (primary)

- `Get-LocalUser` is part of `Microsoft.PowerShell.LocalAccounts`, shipped in-box.
- PS 5.1 `/Date(...)/` format is handled directly; no PSRemoting or AD module required.

### Caveats

- `user_may_change_password`, `*_days` fields are only populated by the `powershell` executor; the `cim` backend loses all date information.
- `lockout` is only populated by the `cim` backend.
- `name` must pass a safety check (letters / digits / `. _ - $`); inputs with spaces or shell metacharacters are rejected to prevent PS command injection.

---

## Security Considerations

- No elevated privileges required for enumeration of local accounts.
- Name validator (`is_safe_identifier`) enforces a conservative character set before string-interpolation into the PowerShell command.
- Agent runs as a non-interactive, non-elevated user when possible.

---

## Related CTN Types

| CTN Type                  | Relationship                                                |
| ------------------------- | ----------------------------------------------------------- |
| `windows_local_group`     | Who is a member of Administrators / Backup Operators / etc. |
| `windows_security_policy` | Policy-layer controls (`EnableGuestAccount`, `PasswordComplexity`) whose per-account effect is measured here |
| `registry`                | Some legacy account flags backed by SAM registry hive        |
