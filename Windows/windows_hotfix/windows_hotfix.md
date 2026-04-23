# windows_hotfix

## Overview

Validates a single installed Windows Update / hotfix by KB id via
`Get-HotFix -Id <KB>`. Exposes installation presence, description,
day-granularity install-age, and installer identity.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks that a specific KB is installed, that recent patches are applied within a compliance window, and that hotfix installer identity matches expected auto-update principals.

---

## Object Fields (Input)

| Field   | Type   | Required | Description                                              | Example                 |
| ------- | ------ | -------- | -------------------------------------------------------- | ----------------------- |
| `kb_id` | string | Yes      | KB article id; regex `^KB\d+$`, max 16 chars.            | `KB5036893`, `KB890830` |

Passed to `Get-HotFix -Id` verbatim.

---

## Collected Data Fields (Output)

| Field                | Type    | Required | Description                                                |
| -------------------- | ------- | -------- | ---------------------------------------------------------- |
| `exists`             | boolean | Yes      | Hotfix is installed                                        |
| `description`        | string  | No       | Description from Get-HotFix (e.g. `Security Update`)       |
| `installed_on_days`  | int     | No       | Days since `InstalledOn` timestamp                         |
| `installed_by`       | string  | No       | Identity that installed the hotfix                         |

---

## State Fields (Validation)

| Field                | Type    | Operations                                                                             | Description              |
| -------------------- | ------- | -------------------------------------------------------------------------------------- | ------------------------ |
| `exists`             | boolean | `=`, `!=`                                                                              | Hotfix installed         |
| `description`        | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Update description       |
| `installed_on_days`  | int     | `=`, `!=`, `<`, `>`, `<=`, `>=`                                                        | Days since install       |
| `installed_by`       | string  | same as description                                                                    | Installer identity       |

### Typical `description` values

`Security Update`, `Update`, `Hotfix`

---

## Collection Strategy

| Property                     | Value              |
| ---------------------------- | ------------------ |
| Collector Type               | `windows_hotfix`   |
| Collection Mode              | Metadata           |
| Required Capabilities        | `powershell_exec`  |
| Expected Collection Time     | ~1000ms            |
| Memory Usage                 | ~1MB               |
| Requires Elevated Privileges | No                 |

### Behaviors

None.

---

## Command Execution

Single PowerShell call:

```
Get-HotFix -Id '<KB>' -ErrorAction SilentlyContinue | Select HotFixID, Description, InstalledOn, InstalledBy | ConvertTo-Json
```

When no matching hotfix exists, the cmdlet emits no output and the collector returns `{ "exists": false }`. `InstalledOn` is normalised Rust-side to a whole-day delta against the moment of collection.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### KB5036893 installed within the last 90 days

```esp
OBJECT apr2024_cu
    kb_id `KB5036893`
OBJECT_END

STATE recent_install
    exists boolean = true
    installed_on_days int < 90
STATE_END

CTN windows_hotfix
    TEST at_least_one all AND
    STATE_REF recent_install
    OBJECT_REF apr2024_cu
CTN_END
```

### Critical servicing stack update is present

```esp
OBJECT ssu
    kb_id `KB5034123`
OBJECT_END

STATE ssu_present
    exists boolean = true
    description string contains `Security Update`
STATE_END

CTN windows_hotfix
    TEST at_least_one all AND
    STATE_REF ssu_present
    OBJECT_REF ssu
CTN_END
```

### KB890830 was installed automatically by SYSTEM

```esp
OBJECT mrt
    kb_id `KB890830`
OBJECT_END

STATE system_installed
    exists boolean = true
    installed_by string contains `NT AUTHORITY\SYSTEM`
STATE_END

CTN windows_hotfix
    TEST at_least_one all AND
    STATE_REF system_installed
    OBJECT_REF mrt
CTN_END
```

---

## Error Conditions

| Condition              | Symptom                                                 | Effect on TEST       |
| ---------------------- | ------------------------------------------------------- | -------------------- |
| KB not installed       | Empty cmdlet output                                     | `exists` = false     |
| Malformed KB id        | Caller-side validator rejects (regex `^KB\d+$`)         | `ValidationError`    |
| Get-HotFix slow on WMI | `Win32_QuickFixEngineering` provider delay              | Collection timeout   |
| WMI repository corrupt | Cmdlet error                                            | `CollectionFailed`   |

---

## Platform Notes

### Windows Server 2022

- `Get-HotFix` queries `Win32_QuickFixEngineering` under the hood; it reports only updates tracked by CBS, not all Store or driver updates.
- `InstalledOn` is a `DateTime` in local time; day deltas use the host clock.
- Some feature updates do not appear in `Get-HotFix` output - use `windows_feature` or registry-based checks for those.

### Caveats

- A missing hotfix does not definitively mean the patch is uninstalled; it may be superseded by a later cumulative update that subsumes the KB. Cross-check with vendor guidance.
- `installed_by` is often blank for hotfixes applied by offline servicing.

---

## Security Considerations

- Read-only query; no elevation required.
- Hotfix enumeration reveals patch cadence and may expose vulnerability windows; treat collected evidence as sensitive.
- KB id validator rejects any non `^KB\d+$` input, preventing PS injection via the `-Id` parameter.

---

## Related CTN Types

| CTN Type                    | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `windows_feature`           | Feature-update state complementary to KB enumeration       |
| `windows_service`           | `wuauserv` / `TrustedInstaller` servicing components       |
| `registry`                  | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` |
| `windows_registry_acl`      | ACLs on servicing registry keys                            |
| `windows_file_acl`          | ACLs on `%windir%\SoftwareDistribution` and servicing dirs |
| `windows_audit_policy`      | Audit of patch installation events                         |
