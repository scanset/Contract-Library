# mount_point

## Overview

Validates filesystem mount points and their hardening options via `findmnt -J`.
Checks whether a path is a separate mount and parses the options string into
per-flag booleans for easy policy authoring.

**Pattern:** A (System binary - findmnt)
**Executor:** Simple (boolean + string)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Mount point path to inspect (e.g. `/tmp`, `/var`, `/boot`) |

## Commands Executed

```
findmnt -J <path>
```

**Sample response:**
```json
{
   "filesystems": [
      {
         "target": "/boot",
         "source": "/dev/sda1",
         "fstype": "xfs",
         "options": "rw,nosuid,nodev,noexec,relatime,seclabel,attr2,inode64"
      }
   ]
}
```

**Parsing:** Extracts `source`, `fstype`, `options` from the first filesystem.
Derives per-option booleans (nosuid, nodev, noexec, ro, relatime) by splitting
the options string on commas.

**Exit code != 0:** Path is not a separate mount point. All option flags
default to `false` and `found` is `false`.

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `found` | boolean | Yes | Path is a separate mount point |
| `source` | string | When found | Source device |
| `fstype` | string | When found | Filesystem type |
| `options` | string | When found | Full options string |
| `nosuid` | boolean | Yes | nosuid option present |
| `nodev` | boolean | Yes | nodev option present |
| `noexec` | boolean | Yes | noexec option present |
| `ro` | boolean | Yes | ro option present |
| `relatime` | boolean | Yes | relatime option present |

## State Fields

| Field | Type | Operations |
|-------|------|------------|
| `found` | boolean | =, != |
| `source` | string | =, !=, contains |
| `fstype` | string | =, !=, contains |
| `options` | string | =, !=, contains |
| `nosuid` | boolean | =, != |
| `nodev` | boolean | =, != |
| `noexec` | boolean | =, != |
| `ro` | boolean | =, != |
| `relatime` | boolean | =, != |

## ESP Examples

### /tmp must be a separate mount with nosuid+nodev+noexec

```
OBJECT tmp_mount
    path `/tmp`
OBJECT_END

STATE tmp_hardened
    found boolean = true
    nosuid boolean = true
    nodev boolean = true
    noexec boolean = true
STATE_END
```

### /boot must exist and be nosuid

```
OBJECT boot_mount
    path `/boot`
OBJECT_END

STATE boot_hardened
    found boolean = true
    nosuid boolean = true
STATE_END
```

### /var/log must be a separate filesystem (no specific options required)

```
OBJECT var_log_mount
    path `/var/log`
OBJECT_END

STATE var_log_separate
    found boolean = true
STATE_END
```

## RHEL9 STIG Coverage

Covers approximately 18 mount-related controls:
- /tmp, /var, /var/log, /var/log/audit, /var/tmp, /home, /boot
- nosuid, nodev, noexec hardening on each
- Separate partition requirements

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| findmnt not in PATH | CollectionFailed error |
| Path is not a mount | exit_code != 0, found=false, all flags false |
| Invalid JSON | found=false |

## Related CTN Types

- `file_metadata` - permissions/ownership on mount point directories
- `file_content` - /etc/fstab entries for mount options at boot
