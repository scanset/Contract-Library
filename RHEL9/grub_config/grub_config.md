# grub_config

## Overview

Validates GRUB2 bootloader configuration by parsing `/etc/grub2.cfg`. Extracts the superuser account name and derives whether it is a common/guessable name.

**Platform:** Linux (GRUB2-based systems)
**Collection Method:** Direct file read — no external commands required
**Requires Elevated Privileges:** Yes — `/etc/grub2.cfg` is typically root-readable only

**STIG Coverage:**

- SV-257789 — RHEL 9 must require a unique superuser name at boot (not root/admin/administrator)

**Note:** Distro-agnostic — works on any GRUB2-based Linux system. Defaults to `/etc/grub2.cfg` but can be overridden to `/boot/grub2/grub.cfg`.

---

## Object Fields

| Field         | Type   | Required | Description              | Example          |
| ------------- | ------ | -------- | ------------------------ | ---------------- |
| `config_path` | string | No       | Path to grub config file | `/etc/grub2.cfg` |

Default: `/etc/grub2.cfg`

---

## File Access

```bash
# File parsed
/etc/grub2.cfg

# Relevant lines extracted
set superusers="grubadmin"
export superusers
password_pbkdf2 grubadmin ${GRUB2_PASSWORD}
```

---

## Collected Data Fields

| Field                      | Type    | Always Present | Source                                                                 |
| -------------------------- | ------- | -------------- | ---------------------------------------------------------------------- |
| `found`                    | boolean | Yes            | Whether the grub config file was readable                              |
| `has_superuser`            | boolean | When found     | Derived — `set superusers=` line is present                            |
| `superuser_name`           | string  | When found     | Extracted from `set superusers="<n>"` line                             |
| `has_password`             | boolean | When found     | Derived — `password_pbkdf2 <n>` line references the superuser          |
| `superuser_is_common_name` | boolean | When found     | Derived — `true` if name is in: root, admin, administrator, grub, boot |

---

## State Fields

| State Field                | Type    | Allowed Operations              | Maps To Collected Field    |
| -------------------------- | ------- | ------------------------------- | -------------------------- |
| `found`                    | boolean | `=`, `!=`                       | `found`                    |
| `has_superuser`            | boolean | `=`, `!=`                       | `has_superuser`            |
| `superuser_name`           | string  | `=`, `!=`, `contains`, `starts` | `superuser_name`           |
| `has_password`             | boolean | `=`, `!=`                       | `has_password`             |
| `superuser_is_common_name` | boolean | `=`, `!=`                       | `superuser_is_common_name` |

---

## Collection Strategy

| Property                     | Value                   |
| ---------------------------- | ----------------------- |
| Collector ID                 | `grub_config_collector` |
| Collector Type               | `grub_config`           |
| Collection Mode              | Metadata                |
| Required Capabilities        | `file_access`           |
| Expected Collection Time     | ~50ms                   |
| Memory Usage                 | ~2MB                    |
| Requires Elevated Privileges | Yes                     |
| Batch Collection             | No                      |

---

## ESP Examples

### Superuser name is not a common name (SV-257789)

```esp
OBJECT grub_cfg
OBJECT_END

STATE secure_superuser
    found boolean = true
    has_superuser boolean = true
    has_password boolean = true
    superuser_is_common_name boolean = false
STATE_END

CTN grub_config
    TEST all all AND
    STATE_REF secure_superuser
    OBJECT_REF grub_cfg
CTN_END
```

---

## Error Conditions

| Condition                        | Error Type              | Outcome         |
| -------------------------------- | ----------------------- | --------------- |
| Config file not found/unreadable | N/A                     | `found = false` |
| Incompatible CTN type            | `CtnContractValidation` | Error           |

---

## Related CTN Types

| CTN Type        | Relationship                          |
| --------------- | ------------------------------------- |
| `file_content`  | Raw content check on grub config      |
| `file_metadata` | Check permissions on `/etc/grub2.cfg` |
