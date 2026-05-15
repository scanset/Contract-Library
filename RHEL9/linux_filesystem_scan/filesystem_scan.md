# filesystem_scan

## Overview

Runs predefined `find` scans across the filesystem to detect policy violations
(world-writable files, SUID/SGID binaries, unowned files, etc.). Uses a
built-in scan library keyed by scan type - arbitrary find arguments are not
accepted.

**Pattern:** A (System binary - find)
**Executor:** Simple (int + string + boolean)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_type` | string | Yes | Predefined scan name from the built-in library |
| `root_path` | string | No | Scan start directory, defaults to `/` |
| `expected` | string | No | Comma-separated list of paths expected to match |

## Scan Library

| scan_type | What It Finds |
|-----------|---------------|
| `world_writable` | Files writable by any user (`-type f -perm -0002`) |
| `suid_sgid` | SUID or SGID binaries (`-perm -4000 -o -perm -2000`) |
| `nouser` | Files with no valid owner (`-nouser`) |
| `nogroup` | Files with no valid group (`-nogroup`) |
| `world_writable_dirs_no_sticky` | World-writable directories without sticky bit |
| `orphaned_files` | Files with no user OR no group |
| `dev_files_outside_dev` | Block/character devices (use with root_path != `/dev`) |

## Commands Executed

```
find <root_path> -xdev <scan-specific args>
```

All scans use `-xdev` to stay on one filesystem by default. Override `root_path`
to scan a specific directory.

## Collected Data Fields

| Field | Type | Description |
|-------|------|-------------|
| `found` | boolean | Whether the scan completed |
| `match_count` | int | Total paths matching the scan criteria |
| `unexpected_count` | int | Matches not in the `expected` list |
| `matches` | string | Newline-separated list of matching paths |

## State Fields

| Field | Type | Operations |
|-------|------|------------|
| `found` | boolean | =, != |
| `match_count` | int | =, !=, >, <, >=, <= |
| `unexpected_count` | int | =, !=, >, <, >=, <= |
| `matches` | string | =, !=, contains |

## ESP Examples

### Assert no world-writable files

```
OBJECT no_world_writable
    scan_type `world_writable`
OBJECT_END

STATE zero_matches
    match_count int = 0
STATE_END
```

### Verify only expected SUID binaries exist

```
OBJECT suid_check
    scan_type `suid_sgid`
    expected `/usr/bin/sudo,/usr/bin/passwd,/usr/bin/su,/usr/bin/chage,/usr/bin/gpasswd,/usr/bin/newgrp,/usr/bin/mount,/usr/bin/umount,/usr/bin/crontab,/usr/bin/write`
OBJECT_END

STATE no_unexpected_suid
    unexpected_count int = 0
STATE_END
```

### Assert no unowned files

```
OBJECT no_orphans
    scan_type `orphaned_files`
OBJECT_END

STATE clean
    match_count int = 0
STATE_END
```

## RHEL9 STIG Coverage

Covers approximately 9 controls using `find`-based filesystem audits:
- No files with no valid owner
- No files with no valid group
- Only authorized SUID/SGID binaries
- No world-writable files outside expected locations
- No world-writable directories without sticky bit

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| find not in PATH | CollectionFailed error |
| Unknown scan_type | InvalidObjectConfiguration error |
| Permission denied on paths | Skipped (find continues), non-zero exit treated as success |
| Scan takes > 120s | Timeout error |

## Related CTN Types

- `file_metadata` - check permissions/ownership on specific known files
- `file_content` - check content of specific config files
