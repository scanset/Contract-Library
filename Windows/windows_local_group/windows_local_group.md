# windows_local_group

## Overview

Validates a single Windows local group and its direct members - member
count, comma-joined member-name / SID / object-class / principal-source
lists. Uses `Get-LocalGroup` + `Get-LocalGroupMember` (default) or
`Win32_Group` + `Win32_GroupUser` (CIM fallback). Supports localized
group names via `match_by_sid`.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIGs that constrain Administrators / Backup Operators /
Remote Desktop Users membership, detect AzureAD / foreign principals,
enforce empty sensitive groups.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                         | Example                    |
| ------ | ------ | -------- | --------------------------------------------------- | -------------------------- |
| `name` | string | Yes      | Group name, **or** full SID when `match_by_sid=true`| `Administrators`, `Backup Operators`, `S-1-5-32-544` |

- Case-insensitive match on name.
- With `behavior match_by_sid true`, `name` must be a full well-known SID (e.g. `S-1-5-32-544`) - survives localized group names and renames.

---

## Collected Data Fields (Output)

| Field                   | Type    | Backend   | Description                                                       |
| ----------------------- | ------- | --------- | ----------------------------------------------------------------- |
| `exists`                | boolean | both      | Group found                                                       |
| `sid`                   | string  | both      | Group SID                                                         |
| `description`           | string  | both      | Group description                                                 |
| `member_count`          | int     | both      | Count of direct members (no recursive expansion)                  |
| `members`               | string  | both      | Comma-joined `DOMAIN\Name` per member                             |
| `member_sids`           | string  | both      | Comma-joined SIDs per member                                      |
| `member_object_classes` | string  | both      | Comma-joined ObjectClass per member (`User`, `Group`, ...)        |
| `member_sources`        | string  | powershell| Comma-joined PrincipalSource per member (`Local`, `ActiveDirectory`, `AzureAD`, `MicrosoftAccount`, `Unknown`). Empty on CIM. |

---

## State Fields (Validation)

| Field                   | Type    | Operations                                                                           |
| ----------------------- | ------- | ------------------------------------------------------------------------------------ |
| `exists`                | boolean | `=`, `!=`                                                                            |
| `sid`                   | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` |
| `description`           | string  | (same as above)                                                                      |
| `member_count`          | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`                                                      |
| `members`               | string  | (same string ops)                                                                    |
| `member_sids`           | string  | (same string ops)                                                                    |
| `member_object_classes` | string  | (same string ops)                                                                    |
| `member_sources`        | string  | (same string ops)                                                                    |

---

## Collection Strategy

| Property                     | Value                 |
| ---------------------------- | --------------------- |
| Collector Type               | `windows_local_group` |
| Collection Mode              | Metadata              |
| Required Capabilities        | `powershell_exec`     |
| Expected Collection Time     | ~600ms                |
| Memory Usage                 | ~1MB                  |
| Requires Elevated Privileges | No                    |

### Behaviors

| Behavior       | Values                | Default      | Description                                                     |
| -------------- | --------------------- | ------------ | --------------------------------------------------------------- |
| `executor`     | `powershell`, `cim`   | `powershell` | Backend (powershell exposes PrincipalSource; cim does not)      |
| `match_by_sid` | `true`, `false`       | `false`      | When true, treat `name` as a full SID and resolve via SID match |

---

## Command Execution

### powershell executor (default)

```
try { $g = Get-LocalGroup -Name 'Administrators' -ErrorAction Stop } \
 catch [Microsoft.PowerShell.Commands.GroupNotFoundException] { $g = $null }
# members = @(Get-LocalGroupMember -Group $g.Name | Select Name,SID,ObjectClass,PrincipalSource)
# emit flattened JSON: { Name, SID, MemberCount, Members, MemberSids, MemberClasses, MemberSources }
```

Avoids two PS 5.1 quirks that can raise `PipelineStoppedException`:
`| Select-Object -First N` and the `,@(...)` force-array prefix on
`Get-LocalGroupMember`.

### SID mode

```
Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } | Select-Object -First 1
```

### cim executor

```
Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=TRUE AND Name='Administrators'"
# members via Win32_GroupUser association, SIDType mapped to User/Group/Alias/WellKnown
```

---

## ESP Examples

### Administrators has at most 3 members and no AzureAD principals

```esp
OBJECT admins
    name `Administrators`
OBJECT_END

STATE admin_constraints
    exists boolean = true
    member_count int <= 3
    member_sources string not_contains `AzureAD`
STATE_END

CTN windows_local_group
    TEST at_least_one all AND
    STATE_REF admin_constraints
    OBJECT_REF admins
CTN_END
```

### Backup Operators group is empty

```esp
OBJECT backup_ops
    name `Backup Operators`
OBJECT_END

STATE empty_group
    exists boolean = true
    member_count int = 0
STATE_END

CTN windows_local_group
    TEST at_least_one all AND
    STATE_REF empty_group
    OBJECT_REF backup_ops
CTN_END
```

### Administrators (by SID, survives localized names) contains the expected SID and no nested groups

```esp
OBJECT admins_by_sid
    name `S-1-5-32-544`
    behavior match_by_sid true
OBJECT_END

STATE no_nested
    exists boolean = true
    member_object_classes string not_contains `Group`
    member_sids string contains `S-1-5-21-`
STATE_END

CTN windows_local_group
    TEST at_least_one all AND
    STATE_REF no_nested
    OBJECT_REF admins_by_sid
CTN_END
```

### Remote Desktop Users does not include Authenticated Users

```esp
OBJECT rdp_users
    name `Remote Desktop Users`
OBJECT_END

STATE no_authenticated
    exists boolean = true
    member_sids string not_contains `S-1-5-11`
STATE_END

CTN windows_local_group
    TEST at_least_one all AND
    STATE_REF no_authenticated
    OBJECT_REF rdp_users
CTN_END
```

---

## Error Conditions

| Condition                                    | Error Type         | Effect                        |
| -------------------------------------------- | ------------------ | ----------------------------- |
| Group not found (powershell)                 | GroupNotFoundException caught | `exists` = false       |
| Group not found (cim)                        | Empty result       | `exists` = false              |
| Unsafe name (metacharacters) or bad SID form | `InvalidObjectConfiguration` | Error state           |
| PowerShell timeout (>30s)                    | `CollectionFailed` | Error state                   |
| `Get-LocalGroupMember` raises on exotic principals | caught, `$members = @()` | `member_count` = 0    |

---

## Platform Notes

### Windows Server 2022 (primary)

- `Get-LocalGroup` / `Get-LocalGroupMember` ship in-box via `Microsoft.PowerShell.LocalAccounts`.
- SAM account names cannot legally contain commas, so the comma-joined strings in `members`, `member_sids`, etc. are safe to split downstream.

### Caveats

- Only **direct** members are enumerated; nested group membership is not expanded. This matches STIG semantics and `Get-LocalGroupMember` behaviour.
- `member_sources` is empty under the `cim` executor - don't rely on AzureAD detection when forced to fall back.
- Localized Windows installs rename well-known groups (`Administratoren`, `Administradores`). Use `match_by_sid true` for rename-resilient checks.

---

## Security Considerations

- No elevated privileges required for membership enumeration.
- Name / SID validators enforce a conservative character set before PS interpolation.
- Read-only queries.

---

## Related CTN Types

| CTN Type                  | Relationship                                                |
| ------------------------- | ----------------------------------------------------------- |
| `windows_local_user`      | Individual account properties for the members listed here   |
| `windows_security_policy` | User Rights Assignment SIDs resolve to the groups queried here |
| `registry`                | Legacy group-policy registry keys (rarely authoritative)    |
