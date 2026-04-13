# apache_module

## Overview

Checks whether specific Apache modules are loaded via `httpd -M`. Returns
module presence, type (static/shared), total module count, and the full
module list for detailed inspection.

**Pattern:** A (System binary - httpd)
**Executor:** Simple (boolean + string + int)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `module` | string | Yes | Module name as shown by httpd -M (e.g., `ssl_module`, not `mod_ssl`) |

## Commands Executed

```
httpd -M
```

**Sample response:**
```
Loaded Modules:
 core_module (static)
 ssl_module (shared)
 log_config_module (shared)
 session_module (shared)
```

**Parsing:** Each non-header line is split on `(` to get module name and type.

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `loaded` | boolean | Yes | Module is in the loaded list |
| `module_type` | string | When loaded | `static` or `shared` |
| `module_count` | int | Yes | Total number of loaded modules |
| `modules_list` | string | Yes | Comma-separated list of all module names |

## State Fields

| Field | Type | Operations |
|-------|------|------------|
| `loaded` | boolean | =, != |
| `module_type` | string | =, != |
| `module_count` | int | =, !=, >, <, >=, <= |
| `modules_list` | string | =, !=, contains |

## ESP Examples

### Verify SSL module is loaded

```
OBJECT ssl_check
    module `ssl_module`
OBJECT_END

STATE ssl_loaded
    loaded boolean = true
STATE_END
```

### Verify session module is loaded

```
OBJECT session_check
    module `session_module`
OBJECT_END

STATE session_loaded
    loaded boolean = true
STATE_END
```

### Verify DAV module is NOT loaded (security hardening)

```
OBJECT dav_check
    module `dav_module`
OBJECT_END

STATE dav_not_loaded
    loaded boolean = false
STATE_END
```

## Apache STIG Coverage

Covers approximately 20 controls from the Apache Server and Site STIGs that
check for specific module presence via `httpd -M`.

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| httpd not in PATH | CollectionFailed error |
| Apache not installed | CollectionFailed error |
| Module not loaded | loaded=false, module_type absent |

## Related CTN Types

- `file_content` - check httpd.conf directives
- `file_metadata` - check Apache config/log file permissions
- `rpm_package` - verify httpd package installed
- `systemd_service` - verify httpd.service running
- `tls_probe` - verify TLS from the network side
