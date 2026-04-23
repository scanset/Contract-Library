# windows_firewall_profile

## Overview

Validates one of the three Windows Firewall profiles (Domain, Private, Public)
via `Get-NetFirewallProfile`. Exposes enabled state, default inbound/outbound
action, logging settings, and the listen-notification flag.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks that each profile is enabled, blocks inbound by default, logs dropped/allowed packets, and notifies on new listeners.

---

## Object Fields (Input)

| Field  | Type   | Required | Description                            | Example                         |
| ------ | ------ | -------- | -------------------------------------- | ------------------------------- |
| `name` | string | Yes      | Profile name: `Domain`, `Private`, or `Public` (case-insensitive). | `Domain`, `Private`, `Public` |

Normalised to title case before being passed to `Get-NetFirewallProfile`.

---

## Collected Data Fields (Output)

| Field                      | Type    | Required | Description                                                |
| -------------------------- | ------- | -------- | ---------------------------------------------------------- |
| `exists`                   | boolean | Yes      | Profile resolved                                           |
| `enabled`                  | boolean | No       | Profile is enabled (firewall active)                       |
| `default_inbound_action`   | string  | No       | `Allow`, `Block`, or `NotConfigured`                       |
| `default_outbound_action`  | string  | No       | `Allow`, `Block`, or `NotConfigured`                       |
| `log_allowed`              | boolean | No       | Connection-allowed events written to log                   |
| `log_blocked`              | boolean | No       | Connection-blocked events written to log                   |
| `log_file_name`            | string  | No       | Path to the profile firewall log                           |
| `notify_on_listen`         | boolean | No       | User notified when a program starts listening              |

---

## State Fields (Validation)

| Field                     | Type    | Operations                                                                             | Description                    |
| ------------------------- | ------- | -------------------------------------------------------------------------------------- | ------------------------------ |
| `exists`                  | boolean | `=`, `!=`                                                                              | Profile resolved               |
| `enabled`                 | boolean | `=`, `!=`                                                                              | Profile enabled                |
| `default_inbound_action`  | string  | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends`, `ieq`, `ine`, `pattern_match` | Default inbound action         |
| `default_outbound_action` | string  | same as inbound                                                                        | Default outbound action        |
| `log_allowed`             | boolean | `=`, `!=`                                                                              | Log allowed connections        |
| `log_blocked`             | boolean | `=`, `!=`                                                                              | Log blocked connections        |
| `log_file_name`           | string  | same as inbound                                                                        | Log file path                  |
| `notify_on_listen`        | boolean | `=`, `!=`                                                                              | Listen notification enabled    |

### Valid `default_inbound_action` / `default_outbound_action` values

`Allow`, `Block`, `NotConfigured`

---

## Collection Strategy

| Property                     | Value                        |
| ---------------------------- | ---------------------------- |
| Collector Type               | `windows_firewall_profile`   |
| Collection Mode              | Metadata                     |
| Required Capabilities        | `powershell_exec`            |
| Expected Collection Time     | ~800ms                       |
| Memory Usage                 | ~1MB                         |
| Requires Elevated Privileges | No                           |

### Behaviors

None.

---

## Command Execution

Single PowerShell call:

```
Get-NetFirewallProfile -Name <Domain|Private|Public> | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName, NotifyOnListen | ConvertTo-Json
```

The `NetSecurity` module is auto-loaded. Enum values (`Allow`/`Block`/`NotConfigured`) are emitted as strings by `ConvertTo-Json`.

### Whitelisted Commands

| Command          | Path                                                          |
| ---------------- | ------------------------------------------------------------- |
| `powershell.exe` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`   |

---

## ESP Examples

### Domain profile is enabled and blocks inbound by default

```esp
OBJECT domain_profile
    name `Domain`
OBJECT_END

STATE domain_locked
    exists boolean = true
    enabled boolean = true
    default_inbound_action string = `Block`
STATE_END

CTN windows_firewall_profile
    TEST at_least_one all AND
    STATE_REF domain_locked
    OBJECT_REF domain_profile
CTN_END
```

### Private profile logs dropped packets

```esp
OBJECT private_profile
    name `Private`
OBJECT_END

STATE private_logs_drops
    exists boolean = true
    enabled boolean = true
    log_blocked boolean = true
STATE_END

CTN windows_firewall_profile
    TEST at_least_one all AND
    STATE_REF private_logs_drops
    OBJECT_REF private_profile
CTN_END
```

### Public profile does not notify on listen

```esp
OBJECT public_profile
    name `Public`
OBJECT_END

STATE public_silent
    exists boolean = true
    enabled boolean = true
    notify_on_listen boolean = false
    default_inbound_action string = `Block`
STATE_END

CTN windows_firewall_profile
    TEST at_least_one all AND
    STATE_REF public_silent
    OBJECT_REF public_profile
CTN_END
```

---

## Error Conditions

| Condition                      | Symptom                                      | Effect on TEST        |
| ------------------------------ | -------------------------------------------- | --------------------- |
| Profile name not recognised    | Caller rejects non `Domain|Private|Public`   | `ValidationError`     |
| NetSecurity module unavailable | Cmdlet not found                             | `exists` = false      |
| Access denied (service off)    | `Get-NetFirewallProfile` fails               | `CollectionFailed`    |
| Malformed JSON output          | Parser error                                 | `CollectionFailed`    |

---

## Platform Notes

### Windows Server 2022

- All three profiles always present, even on workgroup hosts (Domain profile inactive but queryable).
- `LogFileName` typically expands to `%systemroot%\system32\LogFiles\Firewall\pfirewall.log`; compare with `contains` rather than equality because env-var expansion may vary.

### Caveats

- `NotConfigured` for inbound action means the active GPO has not set a value; treat as "insecure" unless an overriding GPO is verified separately.
- `enabled=false` on any profile means the firewall service is off for that network category.

---

## Security Considerations

- Read-only query; no elevation required.
- Log file paths may point to attacker-observable locations; ensure ACLs on the log directory are validated separately via `windows_file_acl`.
- Profile name is constrained to the three reserved values - no injection surface.

---

## Related CTN Types

| CTN Type                    | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `windows_firewall_rule`     | Per-rule checks that complement profile-level defaults     |
| `windows_service`           | `MpsSvc` firewall service must be running                  |
| `windows_audit_policy`      | Auditing of firewall configuration changes                 |
| `windows_file_acl`          | ACLs on the firewall log file                              |
| `registry`                  | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` backing keys |
| `windows_security_policy`   | Policies that reference firewall behaviour                 |
