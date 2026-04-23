# windows_firewall_rule

## Overview

Validates a single Windows Firewall rule via `Get-NetFirewallRule`. Exposes
enabled state, direction, action, profile scope, display metadata, and
primary status. Lookup attribute is selectable via `behavior match_by`.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks that a named rule is enabled, blocks traffic in a specific direction, or that a display-group has at least one active rule.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                                                 | Example                                              |
| ------ | ------ | -------- | --------------------------------------------------------------------------- | ---------------------------------------------------- |
| `name` | string | Yes      | Rule lookup value; meaning determined by `behavior match_by`.               | `RemoteDesktop-UserMode-In-TCP`, `Remote Desktop - User Mode (TCP-In)`, `Remote Desktop` |

Up to 512 chars; rejects quote, backtick, pipe, semicolon, ampersand, subexpression, and newline characters.

---

## Collected Data Fields (Output)

| Field            | Type    | Required | Description                                       |
| ---------------- | ------- | -------- | ------------------------------------------------- |
| `exists`         | boolean | Yes      | At least one rule matched the lookup              |
| `enabled`        | boolean | No       | Rule is enabled                                   |
| `direction`      | string  | No       | `Inbound` or `Outbound`                           |
| `action`         | string  | No       | `Allow`, `Block`, or `NotConfigured`              |
| `profile`        | string  | No       | Sorted, comma-joined profile list                 |
| `display_name`   | string  | No       | User-facing name                                  |
| `description`    | string  | No       | Long-form description                             |
| `display_group`  | string  | No       | Group shown in firewall UI                        |
| `primary_status` | string  | No       | `OK`, `Degraded`, `Error`, or `Unknown`           |

---

## State Fields (Validation)

| Field            | Type    | Operations                                                                             | Description                |
| ---------------- | ------- | -------------------------------------------------------------------------------------- | -------------------------- |
| `exists`         | boolean | `=`, `!=`                                                                              | Rule exists                |
| `enabled`        | boolean | `=`, `!=`                                                                              | Rule enabled               |
| `direction`      | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Traffic direction          |
| `action`         | string  | same as direction                                                                      | Allow/Block/NotConfigured  |
| `profile`        | string  | same as direction                                                                      | Applicable profiles        |
| `display_name`   | string  | same as direction                                                                      | UI display name            |
| `description`    | string  | same as direction                                                                      | Long description           |
| `display_group`  | string  | same as direction                                                                      | Group name                 |
| `primary_status` | string  | same as direction                                                                      | Rule status                |

### Valid `direction` values

`Inbound`, `Outbound`

### Valid `action` values

`Allow`, `Block`, `NotConfigured`

### Valid `profile` values

`Any`, `Domain`, `Private`, `Public`, or comma-joined combinations (e.g. `Domain, Private, Public`)

---

## Collection Strategy

| Property                     | Value                     |
| ---------------------------- | ------------------------- |
| Collector Type               | `windows_firewall_rule`   |
| Collection Mode              | Metadata                  |
| Required Capabilities        | `powershell_exec`         |
| Expected Collection Time     | ~1500ms                   |
| Memory Usage                 | ~2MB                      |
| Requires Elevated Privileges | No                        |

### Behaviors

| Behavior   | Values                                   | Default | Description                                            |
| ---------- | ---------------------------------------- | ------- | ------------------------------------------------------ |
| `match_by` | `name`, `display_name`, `display_group`  | `name`  | Which `Get-NetFirewallRule` parameter to use           |

`display_group` returns the first matching rule in the group.

---

## Command Execution

Default (`match_by name`):

```
Get-NetFirewallRule -Name '<name>' | Select Name, Enabled, Direction, Action, Profile, DisplayName, Description, DisplayGroup, PrimaryStatus | ConvertTo-Json
```

`match_by display_name` swaps `-Name` for `-DisplayName`; `match_by display_group` uses `-DisplayGroup` and takes the first result. `Profile` bitmask is decoded into the sorted comma-joined label form.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### RDP user-mode TCP rule is enabled and allows inbound

```esp
OBJECT rdp_rule
    name `Remote Desktop - User Mode (TCP-In)`
OBJECT_END

STATE rdp_allowed
    behavior match_by display_name
    exists boolean = true
    enabled boolean = true
    direction string = `Inbound`
    action string = `Allow`
STATE_END

CTN windows_firewall_rule
    TEST at_least_one all AND
    STATE_REF rdp_allowed
    OBJECT_REF rdp_rule
CTN_END
```

### File and Printer Sharing group is disabled

```esp
OBJECT file_print_share
    name `File and Printer Sharing`
OBJECT_END

STATE group_disabled
    behavior match_by display_group
    exists boolean = true
    enabled boolean = false
STATE_END

CTN windows_firewall_rule
    TEST at_least_one all AND
    STATE_REF group_disabled
    OBJECT_REF file_print_share
CTN_END
```

### Custom outbound block rule exists and is active

```esp
OBJECT block_rule
    name `Block-Outbound-LegacySMB`
OBJECT_END

STATE outbound_blocked
    exists boolean = true
    enabled boolean = true
    direction string = `Outbound`
    action string = `Block`
    profile string contains `Domain`
STATE_END

CTN windows_firewall_rule
    TEST at_least_one all AND
    STATE_REF outbound_blocked
    OBJECT_REF block_rule
CTN_END
```

---

## Error Conditions

| Condition                   | Symptom                                       | Effect on TEST          |
| --------------------------- | --------------------------------------------- | ----------------------- |
| Rule not found              | Cmdlet emits empty; collector returns `{}`    | `exists` = false        |
| Injection characters        | Caller-side validator rejects                 | `ValidationError`       |
| NetSecurity module missing  | Cmdlet not found                              | `CollectionFailed`      |
| Ambiguous display_group     | First matching rule used                      | Non-deterministic match |

---

## Platform Notes

### Windows Server 2022

- `Get-NetFirewallRule` canonicalises `Name` to a rule ID; `DisplayName` is locale-dependent on multilingual hosts.
- `DisplayGroup` is not set on all rules; custom rules often have empty group.
- `Profile` value `Any` corresponds to mask 0 (applies to all profiles).

### Caveats

- When using `match_by display_name` with a non-English locale, the display name may be translated. Prefer `match_by name` for locale-independent checks.
- `display_group` match returns only the first rule in the group - multiple rules in a group require separate CTN instances or use of `registry_subkeys` style enumeration (not supported here).

---

## Security Considerations

- Read-only query; no elevation required.
- Rule enumeration exposes security posture (open ports, allowed applications); treat as sensitive evidence.
- Rule name validator blocks PS injection via quote/subexpression/pipe characters.

---

## Related CTN Types

| CTN Type                     | Relationship                                               |
| ---------------------------- | ---------------------------------------------------------- |
| `windows_firewall_profile`   | Profile defaults that complement per-rule checks           |
| `windows_service`            | `MpsSvc` service must be running for rules to enforce      |
| `tcp_listener`               | Process-level listener check; pairs with firewall rule check |
| `windows_audit_policy`       | Audit of firewall rule changes                             |
| `registry`                   | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` |
| `windows_security_policy`    | Security policy interactions with firewall posture         |
