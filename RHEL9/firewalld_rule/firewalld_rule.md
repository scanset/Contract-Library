# firewalld_rule

## Overview

Validates firewalld configuration via `firewall-cmd` subcommands. Checks the
daemon state, panic mode, and zone-specific settings (target, services, ports,
masquerade, interfaces, rich rules).

**Pattern:** A (System binary - firewall-cmd)
**Executor:** Simple (boolean + string)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `zone` | string | No | Firewall zone (defaults to `public`) |

## Commands Executed

```
firewall-cmd --state
firewall-cmd --query-panic
firewall-cmd --list-all --zone=<zone>
```

**Sample `--list-all` output:**
```
public (active)
  target: default
  interfaces: enp0s3 enp0s8
  services: cockpit dhcpv6-client ssh
  ports:
  masquerade: no
  rich rules:
```

**Parsing:** Each line is split on the first `:` into key/value pairs.
Keys are normalized with hyphens replaced by underscores.
`masquerade: yes/no` is converted to a boolean.

## Collected Data Fields

| Field | Type | Description |
|-------|------|-------------|
| `found` | boolean | Zone was inspected successfully |
| `running` | boolean | firewalld daemon is active |
| `panic_mode` | boolean | Panic mode is on |
| `target` | string | Zone target (default, DROP, REJECT, ACCEPT) |
| `services` | string | Allowed services (space-separated) |
| `ports` | string | Open ports (space-separated) |
| `masquerade` | boolean | NAT masquerading enabled |
| `interfaces` | string | Bound interfaces |
| `rich_rules` | string | Rich rules configured |

## State Fields

All STATE fields use the same names as collected data fields.

## ESP Examples

### Verify firewalld is running and not in panic mode

```
OBJECT fw
    zone `public`
OBJECT_END

STATE fw_operational
    found boolean = true
    running boolean = true
    panic_mode boolean = false
STATE_END
```

### Verify only approved services are allowed

```
OBJECT fw_public
    zone `public`
OBJECT_END

STATE only_ssh
    services string = `ssh`
STATE_END
```

### Verify SSH is in the services list (contains check)

```
OBJECT fw_public
    zone `public`
OBJECT_END

STATE ssh_allowed
    services string contains `ssh`
STATE_END
```

## RHEL9 STIG Coverage

Covers 3 firewalld-related controls from RHEL-09-251xxx series.

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| firewall-cmd not in PATH | CollectionFailed error |
| firewalld not running | found=false, running=false, panic_mode=false |
| Invalid zone name | found=false |

## Related CTN Types

- `systemd_service` - check firewalld.service enabled/active
- `rpm_package` - verify firewalld package installed
