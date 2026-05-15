# sysctl_parameter

## Overview

Validates Linux kernel parameters via `sysctl -n`. Returns the parameter value as a string for comparison.

**Platform:** Linux
**Use Case:** Kernel hardening and network security validation

---

## Object Fields (Input)

| Field       | Type   | Required | Description                             | Example                                            |
| ----------- | ------ | -------- | --------------------------------------- | -------------------------------------------------- |
| `parameter` | string | Yes      | Sysctl parameter name (dotted notation) | `net.ipv4.ip_forward`, `kernel.randomize_va_space` |

### Notes

- Use standard dotted sysctl notation
- Supports VAR resolution in parameter names

---

## Collected Data Fields (Output)

| Field   | Type    | Required | Description                                |
| ------- | ------- | -------- | ------------------------------------------ |
| `found` | boolean | Yes      | Whether the parameter exists in the kernel |
| `value` | string  | No       | Raw parameter value as string              |

**Notes:**

- Multi-value parameters (e.g., tab-separated) are returned as a single string
- Boolean-like parameters return `0` or `1` as strings
- Only populated when `found` is `true`

---

## State Fields (Validation)

| Field   | Type    | Operations            | Maps To | Description              |
| ------- | ------- | --------------------- | ------- | ------------------------ |
| `found` | boolean | `=`, `!=`             | `found` | Whether parameter exists |
| `value` | string  | `=`, `!=`, `contains` | `value` | Parameter value          |

---

## Collection Strategy

| Property                     | Value              |
| ---------------------------- | ------------------ |
| Collector Type               | `sysctl_parameter` |
| Collection Mode              | Metadata           |
| Required Capabilities        | `sysctl_access`    |
| Expected Collection Time     | ~10ms              |
| Memory Usage                 | ~1MB               |
| Network Intensive            | No                 |
| CPU Intensive                | No                 |
| Requires Elevated Privileges | No                 |

---

## Command Execution

### Command Format

```bash
sysctl -n <parameter>
```

### Output Format

Raw value, one line:

```
0
```

### Whitelisted Commands

| Command            | Path        | Description          |
| ------------------ | ----------- | -------------------- |
| `sysctl`           | PATH lookup | Standard sysctl      |
| `/usr/sbin/sysctl` | Absolute    | Common location      |
| `/sbin/sysctl`     | Absolute    | Alternative location |

---

## ESP Examples

### Check IP forwarding is disabled

```esp
OBJECT ip_forward
    parameter `net.ipv4.ip_forward`
OBJECT_END

STATE forwarding_disabled
    found boolean = true
    value string = `0`
STATE_END

CTN sysctl_parameter
    TEST at_least_one all AND
    STATE_REF forwarding_disabled
    OBJECT_REF ip_forward
CTN_END
```

### Check ASLR is enabled (full randomization)

```esp
OBJECT aslr
    parameter `kernel.randomize_va_space`
OBJECT_END

STATE full_randomization
    found boolean = true
    value string = `2`
STATE_END

CTN sysctl_parameter
    TEST at_least_one all AND
    STATE_REF full_randomization
    OBJECT_REF aslr
CTN_END
```

### Multiple kernel hardening checks

```esp
OBJECT ip_forward
    parameter `net.ipv4.ip_forward`
OBJECT_END

OBJECT icmp_redirects
    parameter `net.ipv4.conf.all.accept_redirects`
OBJECT_END

OBJECT source_routing
    parameter `net.ipv4.conf.all.accept_source_route`
OBJECT_END

OBJECT syn_cookies
    parameter `net.ipv4.tcp_syncookies`
OBJECT_END

STATE must_be_zero
    found boolean = true
    value string = `0`
STATE_END

STATE must_be_one
    found boolean = true
    value string = `1`
STATE_END

CRI AND
    # These should be disabled (0)
    CTN sysctl_parameter
        TEST all all AND
        STATE_REF must_be_zero
        OBJECT_REF ip_forward
        OBJECT_REF icmp_redirects
        OBJECT_REF source_routing
    CTN_END

    # These should be enabled (1)
    CTN sysctl_parameter
        TEST all all AND
        STATE_REF must_be_one
        OBJECT_REF syn_cookies
    CTN_END
CRI_END
```

### Check reverse path filtering

```esp
OBJECT rp_filter
    parameter `net.ipv4.conf.all.rp_filter`
OBJECT_END

STATE strict_rp_filter
    found boolean = true
    value string = `1`
STATE_END

CTN sysctl_parameter
    TEST at_least_one all AND
    STATE_REF strict_rp_filter
    OBJECT_REF rp_filter
CTN_END
```

### Check core dump restriction

```esp
OBJECT core_pattern
    parameter `kernel.core_pattern`
OBJECT_END

STATE no_core_dumps
    found boolean = true
    value string contains `|/bin/false`
STATE_END

CTN sysctl_parameter
    TEST at_least_one all AND
    STATE_REF no_core_dumps
    OBJECT_REF core_pattern
CTN_END
```

---

## Common Parameters for FedRAMP / STIG Compliance

| Parameter                               | Expected Value | Control                         |
| --------------------------------------- | -------------- | ------------------------------- |
| `net.ipv4.ip_forward`                   | `0`            | SC-7 (disable routing)          |
| `net.ipv4.conf.all.accept_redirects`    | `0`            | SC-7 (no ICMP redirects)        |
| `net.ipv4.conf.all.accept_source_route` | `0`            | SC-7 (no source routing)        |
| `net.ipv4.conf.all.log_martians`        | `1`            | AU-2 (log suspicious packets)   |
| `net.ipv4.tcp_syncookies`               | `1`            | SC-5 (SYN flood protection)     |
| `net.ipv4.conf.all.rp_filter`           | `1`            | SC-7 (reverse path filtering)   |
| `kernel.randomize_va_space`             | `2`            | SI-16 (full ASLR)               |
| `kernel.dmesg_restrict`                 | `1`            | AC-3 (restrict dmesg)           |
| `kernel.kptr_restrict`                  | `1`            | AC-3 (restrict kernel pointers) |
| `fs.suid_dumpable`                      | `0`            | AC-6 (no SUID core dumps)       |

---

## Error Conditions

| Condition            | Error Type         | Effect on TEST  |
| -------------------- | ------------------ | --------------- |
| sysctl not found     | `CollectionFailed` | Error state     |
| sysctl timeout (>5s) | `CollectionFailed` | Error state     |
| Parameter not found  | N/A                | `found` = false |
| Permission denied    | `CollectionFailed` | Error state     |

---

## Platform Notes

### Amazon Linux 2023 / RHEL 9

- `sysctl` at `/usr/sbin/sysctl`
- Parameters set via `/etc/sysctl.conf` and `/etc/sysctl.d/*.conf`
- Runtime values may differ from config file values

### Ubuntu 22.04+

- Same `sysctl` interface
- Parameters in `/etc/sysctl.d/` take precedence

### Important Note

- `sysctl -n` returns the **runtime** value, not the config file value
- A parameter can be set correctly in config but overridden at runtime
- Always validate runtime values for compliance

---

## Security Considerations

- No elevated privileges required to read most parameters
- Some parameters may require root to read (rare)
- Read-only operation, does not modify kernel state

---

## Related CTN Types

| CTN Type          | Relationship                                                          |
| ----------------- | --------------------------------------------------------------------- |
| `file_content`    | Validate `/etc/sysctl.conf` or `/etc/sysctl.d/*.conf` for persistence |
| `systemd_service` | Check `systemd-sysctl.service` is enabled                             |
