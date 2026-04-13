# os_release

## Overview

Validates operating system release information by parsing `/etc/os-release`. Returns structured fields for OS name, version, distribution ID, and a derived `supported` boolean for Rocky/RHEL 9 vendor-support validation.

**Platform:** Linux (any distribution providing `/etc/os-release`)
**Collection Method:** Direct file read — no external commands required

**STIG Coverage:** SV-257777 — RHEL 9 must be a vendor-supported release

**Note:** Distro-agnostic — works on Rocky Linux 9, RHEL 9, AlmaLinux 9, and any EL9-family distribution. The `supported` field is derived: `true` when `ID` is `rocky`, `rhel`, or `almalinux` and `VERSION_ID` starts with `9.`.

---

## Object Fields

| Field          | Type   | Required | Description                        | Example           |
| -------------- | ------ | -------- | ---------------------------------- | ----------------- |
| `release_file` | string | No       | Override default release file path | `/etc/os-release` |

Default path is `/etc/os-release` when `release_file` is not specified.

---

## Commands / File Access

```
cat /etc/os-release
```

**Sample /etc/os-release content:**

```
NAME="Rocky Linux"
VERSION="9.5 (Blue Onyx)"
ID=rocky
ID_LIKE="rhel centos fedora"
VERSION_ID=9.5
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.5 (Blue Onyx)"
```

---

## Collected Data Fields

| Field         | Type    | Always Present | Source                                              |
| ------------- | ------- | -------------- | --------------------------------------------------- |
| `id`          | string  | Yes            | `ID` field                                          |
| `name`        | string  | When present   | `NAME` field                                        |
| `version`     | string  | When present   | `VERSION` field                                     |
| `version_id`  | string  | When present   | `VERSION_ID` field                                  |
| `id_like`     | string  | When present   | `ID_LIKE` field                                     |
| `pretty_name` | string  | When present   | `PRETTY_NAME` field                                 |
| `platform_id` | string  | When present   | `PLATFORM_ID` field                                 |
| `supported`   | boolean | Yes            | Derived — `true` when EL9 family and VERSION_ID=9.x |

---

## State Fields

| State Field   | Type    | Allowed Operations              | Maps To Collected Field |
| ------------- | ------- | ------------------------------- | ----------------------- |
| `id`          | string  | `=`, `!=`, `contains`, `starts` | `id`                    |
| `name`        | string  | `=`, `!=`, `contains`, `starts` | `name`                  |
| `version`     | string  | `=`, `!=`, `contains`, `starts` | `version`               |
| `version_id`  | string  | `=`, `!=`, `contains`, `starts` | `version_id`            |
| `id_like`     | string  | `=`, `!=`, `contains`, `starts` | `id_like`               |
| `pretty_name` | string  | `=`, `!=`, `contains`, `starts` | `pretty_name`           |
| `platform_id` | string  | `=`, `!=`, `contains`, `starts` | `platform_id`           |
| `supported`   | boolean | `=`, `!=`                       | `supported`             |

---

## Collection Strategy

| Property                     | Value                  |
| ---------------------------- | ---------------------- |
| Collector ID                 | `os_release_collector` |
| Collector Type               | `os_release`           |
| Collection Mode              | Metadata               |
| Required Capabilities        | `file_access`          |
| Expected Collection Time     | ~10ms                  |
| Memory Usage                 | ~1MB                   |
| Requires Elevated Privileges | No                     |
| Batch Collection             | No                     |

---

## ESP Examples

### Validate vendor-supported Rocky 9 release (SV-257777)

```esp
OBJECT os_info
OBJECT_END

STATE vendor_supported
    id string = `rocky`
    supported boolean = true
    platform_id string = `platform:el9`
STATE_END

CTN os_release
    TEST all all AND
    STATE_REF vendor_supported
    OBJECT_REF os_info
CTN_END
```

### Check for any EL9 family OS

```esp
OBJECT os_info
OBJECT_END

STATE el9_family
    id_like string contains `rhel`
    version_id string starts `9.`
STATE_END

CTN os_release
    TEST all all AND
    STATE_REF el9_family
    OBJECT_REF os_info
CTN_END
```

---

## Error Conditions

| Condition                   | Error Type              | Outcome |
| --------------------------- | ----------------------- | ------- |
| `/etc/os-release` not found | `CollectionFailed`      | Error   |
| File not readable           | `CollectionFailed`      | Error   |
| Incompatible CTN type       | `CtnContractValidation` | Error   |

---

## Related CTN Types

| CTN Type       | Relationship                                     |
| -------------- | ------------------------------------------------ |
| `rpm_package`  | Validate installed packages on the same OS       |
| `file_content` | Read `/etc/redhat-release` for additional detail |
