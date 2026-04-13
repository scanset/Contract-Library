# file_metadata

## Overview

Fast metadata collection via `stat()` for file permissions, ownership, group, existence, and size validation.

**Platform:** Linux, macOS, Windows (partial)
**Use Case:** Security compliance validation of file permissions and ownership

---

## Object Fields (Input)

| Field  | Type   | Required | Description                                  | Example                             |
| ------ | ------ | -------- | -------------------------------------------- | ----------------------------------- |
| `path` | string | Yes      | File system path (absolute or relative)      | `/etc/sudoers`, `scanfiles/sudoers` |
| `type` | string | No       | Resource type indicator (informational only) | `file`                              |

### Notes

- Supports VAR resolution in paths
- Both absolute and relative paths accepted

---

## Collected Data Fields (Output)

| Field          | Type    | Description                                          |
| -------------- | ------- | ---------------------------------------------------- |
| `file_mode`    | string  | File permissions in 4-digit octal format (Unix only) |
| `file_owner`   | string  | File owner UID as string (Unix only)                 |
| `file_group`   | string  | File group GID as string (Unix only)                 |
| `exists`       | boolean | Whether file exists                                  |
| `readable`     | boolean | Whether file is readable by current process          |
| `writable`     | boolean | Whether file is writable by current process          |
| `file_size`    | int     | File size in bytes                                   |
| `is_directory` | boolean | Whether path is a directory                          |

**Notes:**

- On non-Unix platforms, `file_mode`, `file_owner`, and `file_group` return empty strings
- If file does not exist, metadata fields return empty/default values

---

## State Fields (Validation)

**CRITICAL: Use the state field names below exactly. They map to collected data fields via the contract.**

| Field          | Type    | Operations                      | Maps To        | Description                      |
| -------------- | ------- | ------------------------------- | -------------- | -------------------------------- |
| `permissions`  | string  | `=`, `!=`                       | `file_mode`    | File permissions in octal format |
| `owner_id`     | string  | `=`, `!=`                       | `file_owner`   | File owner (UID as string)       |
| `group_id`     | string  | `=`, `!=`                       | `file_group`   | File group (GID as string)       |
| `exists`       | boolean | `=`, `!=`                       | `exists`       | Whether file exists              |
| `readable`     | boolean | `=`, `!=`                       | `readable`     | Whether file is readable         |
| `writable`     | boolean | `=`, `!=`                       | `writable`     | Whether file is writable         |
| `size`         | int     | `=`, `!=`, `>`, `<`, `>=`, `<=` | `file_size`    | File size in bytes               |
| `is_directory` | boolean | `=`, `!=`                       | `is_directory` | Whether path is a directory      |

> **Warning:** Do not use `owner` or `group` as state field names. These are not mapped and will silently report "not collected". Use `owner_id` and `group_id`.

---

## Collection Strategy

| Property                     | Value         |
| ---------------------------- | ------------- |
| Collector Type               | `filesystem`  |
| Collection Mode              | Metadata      |
| Required Capabilities        | `file_access` |
| Expected Collection Time     | ~5ms          |
| Memory Usage                 | ~1MB          |
| Network Intensive            | No            |
| CPU Intensive                | No            |
| Requires Elevated Privileges | No            |

---

## ESP Examples

### Basic permissions check

```esp
OBJECT sudoers_file
    path `/etc/sudoers`
OBJECT_END

STATE secure_permissions
    exists boolean = true
    permissions string = `0440`
    owner_id string = `0`
    group_id string = `0`
STATE_END

CTN file_metadata
    TEST all all AND
    STATE_REF secure_permissions
    OBJECT_REF sudoers_file
CTN_END
```

### Check file does NOT exist

```esp
OBJECT shosts_equiv
    path `/etc/shosts.equiv`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN file_metadata
    TEST all all AND
    STATE_REF must_not_exist
    OBJECT_REF shosts_equiv
CTN_END
```

### File size validation

```esp
OBJECT audit_log
    path `/var/log/audit/audit.log`
OBJECT_END

STATE not_empty
    exists boolean = true
    size int > `0`
STATE_END

CTN file_metadata
    TEST all all AND
    STATE_REF not_empty
    OBJECT_REF audit_log
CTN_END
```

### Root ownership check (shadow files)

```esp
OBJECT shadow_file
    path `/etc/shadow`
OBJECT_END

STATE shadow_secure
    exists boolean = true
    permissions string = `0000`
    owner_id string = `0`
    group_id string = `0`
STATE_END

CTN file_metadata
    TEST all all AND
    STATE_REF shadow_secure
    OBJECT_REF shadow_file
CTN_END
```

### Readable by current process

```esp
OBJECT config_file
    path `/etc/myapp/config.yml`
OBJECT_END

STATE must_be_readable
    exists boolean = true
    readable boolean = true
STATE_END

CTN file_metadata
    TEST all all AND
    STATE_REF must_be_readable
    OBJECT_REF config_file
CTN_END
```

---

## Common Permission Values for STIG Compliance

| File                     | permissions | owner_id | group_id |
| ------------------------ | ----------- | -------- | -------- |
| `/etc/shadow`            | `0000`      | `0`      | `0`      |
| `/etc/shadow-`           | `0000`      | `0`      | `0`      |
| `/etc/gshadow`           | `0000`      | `0`      | `0`      |
| `/etc/gshadow-`          | `0000`      | `0`      | `0`      |
| `/etc/passwd`            | `0644`      | `0`      | `0`      |
| `/etc/group`             | `0644`      | `0`      | `0`      |
| `/etc/ssh/sshd_config`   | `0600`      | `0`      | `0`      |
| `/var/log`               | `0755`      | `0`      | `0`      |
| `/var/log/messages`      | `0640`      | `0`      | `0`      |
| `/etc/audit/auditd.conf` | `0640`      | `0`      | `0`      |

---

## Error Conditions

| Condition                | Error Type                   | Effect on TEST                       |
| ------------------------ | ---------------------------- | ------------------------------------ |
| File does not exist      | N/A                          | `exists` = false, other fields empty |
| Permission denied (stat) | `AccessDenied`               | Error state                          |
| Invalid path             | `InvalidObjectConfiguration` | Configuration error                  |
| Path field missing       | `InvalidObjectConfiguration` | Configuration error                  |

---

## Platform Notes

### Linux / macOS (Unix)

- Uses `stat()` system call via `fs::metadata()`
- Permissions returned as 4-digit octal (e.g., `0644`)
- Owner/group returned as numeric UID/GID strings
- Full support for all fields

### Windows

- Limited support
- `file_mode`, `file_owner`, `file_group` return empty strings
- `exists`, `readable`, `file_size` work normally

---

## Security Considerations

- No elevated privileges required for most files
- Files with mode `0000` (e.g., `/etc/shadow`) require root to stat owner/group
- Does not read file content (use `file_content` for that)
- Running the daemon as root is required for full permission/ownership validation

---

## Related CTN Types

| CTN Type       | Relationship                        |
| -------------- | ----------------------------------- |
| `file_content` | Content validation (more expensive) |
| `json_record`  | Structured JSON file validation     |
