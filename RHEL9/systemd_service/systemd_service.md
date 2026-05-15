# systemd_service

## Overview

Validates systemd service unit status via `systemctl show`. Returns scalar fields for active state, enabled state, sub-state, and load state.

**Platform:** Linux (systemd-based)
**Use Case:** Service availability and boot configuration validation

---

## Object Fields (Input)

| Field       | Type   | Required | Description                          | Example                         |
| ----------- | ------ | -------- | ------------------------------------ | ------------------------------- |
| `unit_name` | string | Yes      | Systemd unit name (including suffix) | `sshd.service`, `nginx.service` |

### Notes

- Always include the `.service` suffix
- Supports VAR resolution in unit names

---

## Collected Data Fields (Output)

| Field          | Type    | Required | Description                                                                |
| -------------- | ------- | -------- | -------------------------------------------------------------------------- |
| `found`        | boolean | Yes      | Whether the unit exists on the system                                      |
| `active_state` | string  | No       | Active state: `active`, `inactive`, `failed`, `activating`, `deactivating` |
| `sub_state`    | string  | No       | Sub-state: `running`, `dead`, `exited`, `waiting`, `failed`                |
| `enabled`      | string  | No       | Boot state: `enabled`, `disabled`, `masked`, `static`                      |
| `load_state`   | string  | No       | Load state: `loaded`, `not-found`, `masked`, `error`                       |

**Notes:**

- If `load_state` is `not-found`, `found` is set to `false`
- Optional fields are only populated when the unit exists

---

## State Fields (Validation)

| Field          | Type    | Operations | Maps To        | Description             |
| -------------- | ------- | ---------- | -------------- | ----------------------- |
| `found`        | boolean | `=`, `!=`  | `found`        | Whether the unit exists |
| `active_state` | string  | `=`, `!=`  | `active_state` | Current active state    |
| `sub_state`    | string  | `=`, `!=`  | `sub_state`    | Current sub-state       |
| `enabled`      | string  | `=`, `!=`  | `enabled`      | Boot enable state       |
| `load_state`   | string  | `=`, `!=`  | `load_state`   | Unit load state         |

---

## Collection Strategy

| Property                     | Value              |
| ---------------------------- | ------------------ |
| Collector Type               | `systemd_service`  |
| Collection Mode              | Metadata           |
| Required Capabilities        | `systemctl_access` |
| Expected Collection Time     | ~100ms             |
| Memory Usage                 | ~1MB               |
| Network Intensive            | No                 |
| CPU Intensive                | No                 |
| Requires Elevated Privileges | No                 |

---

## Command Execution

### Command Format

```bash
systemctl show <unit_name> --property=ActiveState,SubState,UnitFileState,LoadState --no-pager
```

### Output Format

Key=value pairs, one per line:

```
ActiveState=active
SubState=running
UnitFileState=enabled
LoadState=loaded
```

### Whitelisted Commands

| Command              | Path        | Description        |
| -------------------- | ----------- | ------------------ |
| `systemctl`          | PATH lookup | Standard systemctl |
| `/usr/bin/systemctl` | Absolute    | Common location    |

---

## ESP Examples

### Check service is running and enabled

```esp
OBJECT sshd_service
    unit_name `sshd.service`
OBJECT_END

STATE running_and_enabled
    found boolean = true
    active_state string = `active`
    sub_state string = `running`
    enabled string = `enabled`
STATE_END

CTN systemd_service
    TEST at_least_one all AND
    STATE_REF running_and_enabled
    OBJECT_REF sshd_service
CTN_END
```

### Check service is NOT running

```esp
OBJECT telnet_service
    unit_name `telnet.socket`
OBJECT_END

STATE not_running
    active_state string = `inactive`
STATE_END

CTN systemd_service
    TEST at_least_one all AND
    STATE_REF not_running
    OBJECT_REF telnet_service
CTN_END
```

### Check service does not exist

```esp
OBJECT legacy_service
    unit_name `rsh.service`
OBJECT_END

STATE must_not_exist
    found boolean = false
STATE_END

CTN systemd_service
    TEST at_least_one all AND
    STATE_REF must_not_exist
    OBJECT_REF legacy_service
CTN_END
```

### Multiple services must be running

```esp
OBJECT sshd
    unit_name `sshd.service`
OBJECT_END

OBJECT nginx
    unit_name `nginx.service`
OBJECT_END

OBJECT node_app
    unit_name `dashboard.service`
OBJECT_END

STATE active_running
    found boolean = true
    active_state string = `active`
    sub_state string = `running`
STATE_END

CTN systemd_service
    TEST all all AND
    STATE_REF active_running
    OBJECT_REF sshd
    OBJECT_REF nginx
    OBJECT_REF node_app
CTN_END
```

### Check service is masked (disabled permanently)

```esp
OBJECT rpcbind
    unit_name `rpcbind.service`
OBJECT_END

STATE is_masked
    enabled string = `masked`
STATE_END

CTN systemd_service
    TEST at_least_one all AND
    STATE_REF is_masked
    OBJECT_REF rpcbind
CTN_END
```

---

## Error Conditions

| Condition                | Error Type         | Effect on TEST                              |
| ------------------------ | ------------------ | ------------------------------------------- |
| systemctl not found      | `CollectionFailed` | Error state                                 |
| systemctl timeout (>10s) | `CollectionFailed` | Error state                                 |
| Unit not found           | N/A                | `found` = false, `load_state` = `not-found` |
| Permission denied        | `CollectionFailed` | Error state                                 |

---

## Platform Notes

### Amazon Linux 2023 / RHEL 9 / Fedora

- `systemctl` at `/usr/bin/systemctl`
- All services managed via systemd
- `UnitFileState` reflects `systemctl enable/disable` status

### Ubuntu 22.04+

- Same `systemctl` interface
- Some services use `.socket` activation

### Non-systemd Systems

- Not supported (e.g., Alpine Linux with OpenRC)
- Collector will fail with `systemctl not found`

---

## Security Considerations

- No elevated privileges required to query service status
- `systemctl show` is read-only
- Does not expose service configuration details, only state

---

## Related CTN Types

| CTN Type        | Relationship                                 |
| --------------- | -------------------------------------------- |
| `tcp_listener`  | Often used together to verify service + port |
| `file_content`  | Validate service configuration files         |
| `file_metadata` | Check unit file permissions                  |
