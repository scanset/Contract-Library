# fips_mode

## Overview

Validates FIPS 140-3 mode enablement via `fips-mode-setup --check` and the kernel flag at `/proc/sys/crypto/fips_enabled`.

**Platform:** Linux (RHEL 9, Rocky Linux 9, AlmaLinux 9, Amazon Linux 2023)
**Collection Method:** `fips-mode-setup --check` command + `/proc/sys/crypto/fips_enabled` file read

**STIG Coverage:**

- SV-258230 — RHEL 9 must enable FIPS mode

**Note:** `fips-mode-setup` is provided by the `crypto-policies-scripts` package. The collector sets `tool_available = false` when the binary is not found rather than erroring, allowing policies to check for its presence. Enabling FIPS on a VM requires a reboot — this contract checks current state only.

---

## Object Fields

| Field          | Type    | Required | Description                                 | Example |
| -------------- | ------- | -------- | ------------------------------------------- | ------- |
| `check_kernel` | boolean | No       | Also verify `/proc/sys/crypto/fips_enabled` | `true`  |

Default: `true`

---

## Commands Executed

```bash
fips-mode-setup --check
```

**When FIPS is enabled:**

```
FIPS mode is enabled.
```

**When FIPS is not enabled:**

```
FIPS mode is disabled.
```

Also reads:

```
/proc/sys/crypto/fips_enabled   → "1" (enabled) or "0" (disabled)
```

---

## Collected Data Fields

| Field                 | Type    | Always Present | Source                                           |
| --------------------- | ------- | -------------- | ------------------------------------------------ |
| `enabled`             | boolean | Yes            | Derived — output contains "FIPS mode is enabled" |
| `kernel_fips_enabled` | boolean | Yes            | `/proc/sys/crypto/fips_enabled` == `1`           |
| `status_output`       | string  | When available | Raw stdout of `fips-mode-setup --check`          |
| `tool_available`      | boolean | Yes            | Whether `fips-mode-setup` binary was found       |

---

## State Fields

| State Field           | Type    | Allowed Operations    | Maps To Collected Field |
| --------------------- | ------- | --------------------- | ----------------------- |
| `enabled`             | boolean | `=`, `!=`             | `enabled`               |
| `kernel_fips_enabled` | boolean | `=`, `!=`             | `kernel_fips_enabled`   |
| `status_output`       | string  | `=`, `!=`, `contains` | `status_output`         |
| `tool_available`      | boolean | `=`, `!=`             | `tool_available`        |

---

## Collection Strategy

| Property                     | Value               |
| ---------------------------- | ------------------- |
| Collector ID                 | `fips-collector`    |
| Collector Type               | `fips_mode`         |
| Collection Mode              | Metadata            |
| Required Capabilities        | `command_execution` |
| Expected Collection Time     | ~500ms              |
| Memory Usage                 | ~2MB                |
| Requires Elevated Privileges | No                  |
| Batch Collection             | No                  |

### Whitelisted Commands

| Command                    | Path             |
| -------------------------- | ---------------- |
| `fips-mode-setup`          | PATH lookup      |
| `/usr/bin/fips-mode-setup` | Absolute path    |
| `/sbin/fips-mode-setup`    | Alternative path |

---

## ESP Examples

### FIPS mode is enabled (SV-258230)

```esp
OBJECT fips_check
OBJECT_END

STATE fips_enabled
    enabled boolean = true
    kernel_fips_enabled boolean = true
    tool_available boolean = true
STATE_END

CTN fips_mode
    TEST all all AND
    STATE_REF fips_enabled
    OBJECT_REF fips_check
CTN_END
```

---

## Error Conditions

| Condition                       | Error Type              | Outcome                  |
| ------------------------------- | ----------------------- | ------------------------ |
| `fips-mode-setup` not installed | N/A                     | `tool_available = false` |
| Command timeout                 | `CollectionFailed`      | Error                    |
| Incompatible CTN type           | `CtnContractValidation` | Error                    |

---

## Related CTN Types

| CTN Type           | Relationship                                                  |
| ------------------ | ------------------------------------------------------------- |
| `crypto_policy`    | FIPS mode requires crypto policy set to FIPS                  |
| `sysctl_parameter` | Kernel FIPS flag also readable via sysctl crypto.fips_enabled |
