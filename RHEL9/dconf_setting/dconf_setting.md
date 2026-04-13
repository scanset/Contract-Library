# dconf_setting

## Overview

Validates GNOME desktop settings via `gsettings get`. Reports `applicable: false`
when GNOME/gsettings is not installed, allowing policies to handle N/A as a pass.

**Pattern:** A (System binary - gsettings)
**Executor:** Simple (boolean + string)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema` | string | Yes | GSettings schema (e.g., `org.gnome.desktop.screensaver`) |
| `key` | string | Yes | Setting key within the schema (e.g., `lock-enabled`) |

## Commands Executed

```
gsettings get <schema> <key>
```

**Sample responses:**
```
true
uint32 300
false
'never'
```

**Parsing:** GVariant type prefixes (`uint32`, `int32`, etc.) are stripped.
Surrounding single quotes are removed. Result is a plain string.

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `applicable` | boolean | Yes | GNOME installed and schema exists |
| `value` | string | When applicable | Setting value with type prefix stripped |

## State Fields

| Field | Type | Operations |
|-------|------|------------|
| `applicable` | boolean | =, != |
| `value` | string | =, !=, contains |

## N/A Handling

When GNOME is not installed (no `gsettings` binary), the collector returns
`applicable: false` without error. Policies should use a CRI OR pattern:

```
CRI OR
    # Either GNOME is not installed (N/A - pass)
    CTN dconf_setting
        TEST all all AND
        STATE_REF gnome_not_installed
        OBJECT_REF setting_check
    CTN_END

    # Or the setting has the required value
    CTN dconf_setting
        TEST all all AND
        STATE_REF setting_correct
        OBJECT_REF setting_check
    CTN_END
CRI_END
```

Or simply check that `applicable = true` AND `value = expected` in a single
STATE, which fails when GNOME is missing (flagging it as a finding if GNOME
is expected to be installed).

## ESP Examples

### Screensaver lock must be enabled

```
OBJECT screensaver_lock
    schema `org.gnome.desktop.screensaver`
    key `lock-enabled`
OBJECT_END

STATE lock_on
    applicable boolean = true
    value string = `true`
STATE_END
```

### Session idle timeout must be 900 seconds or less

```
OBJECT idle_timeout
    schema `org.gnome.desktop.session`
    key `idle-delay`
OBJECT_END

STATE timeout_set
    applicable boolean = true
STATE_END
```

Note: Integer comparison via string is limited. For exact match use
`value string = \`900\``. For range checks, consider using `computed_values`
CTN with the collected value.

### Media automount must be disabled

```
OBJECT no_automount
    schema `org.gnome.desktop.media-handling`
    key `automount`
OBJECT_END

STATE automount_off
    applicable boolean = true
    value string = `false`
STATE_END
```

## RHEL9 STIG Coverage

Covers approximately 22 GNOME/dconf-related controls from the RHEL-09-271xxx
series:
- Screensaver lock-enabled, lock-delay, idle-activation
- Session idle-delay
- Media automount, automount-open
- Privacy camera/microphone disable
- Login banner text
- Thumbnailer disable
- User list disable on login screen

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| gsettings not in PATH | applicable=false (GNOME not installed) |
| Schema not found | applicable=false |
| Key not found | applicable=false |
| Valid setting read | applicable=true, value=parsed |

## Related CTN Types

- `file_content` - for checking dconf database files directly in /etc/dconf/db/
- `rpm_package` - verify gdm/gnome-settings-daemon packages are installed
