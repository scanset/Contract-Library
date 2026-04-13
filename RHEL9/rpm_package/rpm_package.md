# rpm_package

## Overview

Validates RPM package installation state via `rpm -q <package_name>`. Returns whether the package is installed and its version string when present.

**Platform:** Linux (RPM-based distributions)
**Collection Method:** `rpm -q` command via whitelisted `SystemCommandExecutor`

**STIG Coverage:**

- SV-257826 — No FTP server (`vsftpd` must not be installed)
- SV-257835 — No TFTP server (`tftp-server` must not be installed)

**Note:** Distro-agnostic — works on Rocky Linux 9, RHEL 9, AlmaLinux 9, Amazon Linux 2/2023, CentOS, and any RPM-based distribution. Use `installed boolean = false` to assert packages must not be present.

---

## Object Fields

| Field          | Type   | Required | Description               | Example  |
| -------------- | ------ | -------- | ------------------------- | -------- |
| `package_name` | string | **Yes**  | RPM package name to query | `vsftpd` |

---

## Commands Executed

```bash
rpm -q vsftpd
```

**When installed:**

```
vsftpd-3.0.5-5.el9.x86_64
```

**When not installed (exit code 1):**

```
package vsftpd is not installed
```

---

## Collected Data Fields

| Field       | Type    | Always Present | Source                                             |
| ----------- | ------- | -------------- | -------------------------------------------------- |
| `installed` | boolean | Yes            | Derived — `true` when `rpm -q` exits with code 0   |
| `version`   | string  | When installed | Parsed from rpm output (`version-release` portion) |
| `full_name` | string  | When installed | Full rpm -q output (`name-version-release.arch`)   |

---

## State Fields

| State Field | Type    | Allowed Operations              | Maps To Collected Field |
| ----------- | ------- | ------------------------------- | ----------------------- |
| `installed` | boolean | `=`, `!=`                       | `installed`             |
| `version`   | string  | `=`, `!=`, `contains`, `starts` | `version`               |
| `full_name` | string  | `=`, `!=`, `contains`, `starts` | `full_name`             |

---

## Collection Strategy

| Property                     | Value           |
| ---------------------------- | --------------- |
| Collector ID                 | `rpm-collector` |
| Collector Type               | `rpm_package`   |
| Collection Mode              | Metadata        |
| Required Capabilities        | `rpm_access`    |
| Expected Collection Time     | ~500ms          |
| Memory Usage                 | ~2MB            |
| Requires Elevated Privileges | No              |
| Batch Collection             | No              |

### Whitelisted Commands

| Command        | Path          |
| -------------- | ------------- |
| `rpm`          | PATH lookup   |
| `/usr/bin/rpm` | Absolute path |

---

## ESP Examples

### FTP server must not be installed (SV-257826)

```esp
OBJECT vsftpd_pkg
    package_name `vsftpd`
OBJECT_END

STATE not_installed
    installed boolean = false
STATE_END

CTN rpm_package
    TEST all all AND
    STATE_REF not_installed
    OBJECT_REF vsftpd_pkg
CTN_END
```

### TFTP server must not be installed (SV-257835)

```esp
OBJECT tftp_pkg
    package_name `tftp-server`
OBJECT_END

STATE not_installed
    installed boolean = false
STATE_END

CTN rpm_package
    TEST all all AND
    STATE_REF not_installed
    OBJECT_REF tftp_pkg
CTN_END
```

### Multiple prohibited packages

```esp
OBJECT vsftpd_pkg
    package_name `vsftpd`
OBJECT_END

OBJECT tftp_pkg
    package_name `tftp-server`
OBJECT_END

OBJECT sendmail_pkg
    package_name `sendmail`
OBJECT_END

STATE not_installed
    installed boolean = false
STATE_END

CRI AND
    CTN rpm_package
        TEST all all AND
        STATE_REF not_installed
        OBJECT_REF vsftpd_pkg
    CTN_END

    CTN rpm_package
        TEST all all AND
        STATE_REF not_installed
        OBJECT_REF tftp_pkg
    CTN_END

    CTN rpm_package
        TEST all all AND
        STATE_REF not_installed
        OBJECT_REF sendmail_pkg
    CTN_END
CRI_END
```

### Required package must be installed

```esp
OBJECT aide_pkg
    package_name `aide`
OBJECT_END

STATE must_be_installed
    installed boolean = true
STATE_END

CTN rpm_package
    TEST all all AND
    STATE_REF must_be_installed
    OBJECT_REF aide_pkg
CTN_END
```

---

## Error Conditions

| Condition              | Error Type                   | Outcome             |
| ---------------------- | ---------------------------- | ------------------- |
| `package_name` missing | `InvalidObjectConfiguration` | Error               |
| `rpm` binary not found | `CollectionFailed`           | Error               |
| Package not installed  | N/A (not an error)           | `installed = false` |
| Incompatible CTN type  | `CtnContractValidation`      | Error               |

---

## Related CTN Types

| CTN Type          | Relationship                                |
| ----------------- | ------------------------------------------- |
| `os_release`      | Validate OS version alongside package state |
| `systemd_service` | Verify service state for installed packages |
