# crypto_policy

## Overview

Validates the system-wide cryptographic policy via `update-crypto-policies --check` and symlink validation under `/etc/crypto-policies/back-ends/`. Confirms the configured policy matches the generated policy with no per-application overrides.

**Platform:** Linux (RHEL 9, Rocky Linux 9, AlmaLinux 9, and any system using the crypto-policies framework)
**Collection Method:** `update-crypto-policies --check` command + symlink inspection + state file read

**STIG Coverage:**

- SV-258236 — RHEL 9 cryptographic policy must not be overridden

**Note:** The check validates two things: (1) the configured policy matches the generated policy (no overrides applied via `update-crypto-policies --set` followed by manual modification), and (2) all backend symlinks point to the correct policy directory. `nss.config` is a regular file, not a symlink — it is skipped in symlink validation.

---

## Object Fields

| Field             | Type   | Required | Description                                               | Example |
| ----------------- | ------ | -------- | --------------------------------------------------------- | ------- |
| `expected_policy` | string | No       | Expected policy name to validate `current_policy` against | `FIPS`  |

---

## Commands / File Access

```bash
update-crypto-policies --check
```

**When policy matches:**

```
The configured policy matches the generated policy
PASS
```

Also reads:

```
/etc/crypto-policies/state/current          → "FIPS"
/etc/crypto-policies/back-ends/*.config     → symlinks validated
```

**Expected symlink targets (FIPS policy):**

```
bind.config       → /usr/share/crypto-policies/FIPS/bind.txt
gnutls.config     → /usr/share/crypto-policies/FIPS/gnutls.txt
openssh.config    → /usr/share/crypto-policies/FIPS/openssh.txt
openssl.config    → /usr/share/crypto-policies/FIPS/openssl.txt
...
```

---

## Collected Data Fields

| Field                      | Type    | Always Present | Source                                                       |
| -------------------------- | ------- | -------------- | ------------------------------------------------------------ |
| `policy_matches`           | boolean | Yes            | Derived — last line of `--check` output is `PASS`            |
| `current_policy`           | string  | When available | Read from `/etc/crypto-policies/state/current`               |
| `backends_point_to_policy` | boolean | When available | Derived — all `.config` symlinks point to current policy dir |
| `tool_available`           | boolean | Yes            | Whether `update-crypto-policies` binary was found            |
| `check_output`             | string  | When available | Raw stdout of `update-crypto-policies --check`               |

---

## State Fields

| State Field                | Type    | Allowed Operations              | Maps To Collected Field    |
| -------------------------- | ------- | ------------------------------- | -------------------------- |
| `policy_matches`           | boolean | `=`, `!=`                       | `policy_matches`           |
| `current_policy`           | string  | `=`, `!=`, `contains`, `starts` | `current_policy`           |
| `backends_point_to_policy` | boolean | `=`, `!=`                       | `backends_point_to_policy` |
| `tool_available`           | boolean | `=`, `!=`                       | `tool_available`           |
| `check_output`             | string  | `=`, `!=`, `contains`           | `check_output`             |

---

## Collection Strategy

| Property                     | Value                     |
| ---------------------------- | ------------------------- |
| Collector ID                 | `crypto-policy-collector` |
| Collector Type               | `crypto_policy`           |
| Collection Mode              | Metadata                  |
| Required Capabilities        | `command_execution`       |
| Expected Collection Time     | ~500ms                    |
| Memory Usage                 | ~2MB                      |
| Requires Elevated Privileges | No                        |
| Batch Collection             | No                        |

### Whitelisted Commands

| Command                            | Path          |
| ---------------------------------- | ------------- |
| `update-crypto-policies`           | PATH lookup   |
| `/usr/bin/update-crypto-policies`  | Absolute path |
| `/usr/sbin/update-crypto-policies` | Alternative   |

---

## ESP Examples

### Crypto policy is FIPS and not overridden (SV-258236)

```esp
OBJECT crypto_check
OBJECT_END

STATE fips_policy_not_overridden
    tool_available boolean = true
    policy_matches boolean = true
    current_policy string = `FIPS`
    backends_point_to_policy boolean = true
STATE_END

CTN crypto_policy
    TEST all all AND
    STATE_REF fips_policy_not_overridden
    OBJECT_REF crypto_check
CTN_END
```

---

## Error Conditions

| Condition                              | Error Type              | Outcome                            |
| -------------------------------------- | ----------------------- | ---------------------------------- |
| `update-crypto-policies` not installed | N/A                     | `tool_available = false`           |
| State file not readable                | N/A                     | `current_policy` absent            |
| Backend dir not readable               | N/A                     | `backends_point_to_policy = false` |
| Command timeout                        | `CollectionFailed`      | Error                              |
| Incompatible CTN type                  | `CtnContractValidation` | Error                              |

---

## Related CTN Types

| CTN Type       | Relationship                                          |
| -------------- | ----------------------------------------------------- |
| `fips_mode`    | FIPS crypto policy pairs with FIPS mode enablement    |
| `file_content` | Read `/etc/crypto-policies/config` for policy setting |
