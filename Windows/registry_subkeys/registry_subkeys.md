# registry_subkeys

## Overview

Enumerates child subkeys of a Windows registry key and exposes the
subkey count plus an aggregated subkey-name list for membership checks.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG checks that assert "at least one" or "none" of a class of
drivers, readers, or handlers is installed (e.g. smart-card readers).

---

## Object Fields (Input)

| Field  | Type   | Required | Description                   | Example                                        |
| ------ | ------ | -------- | ----------------------------- | ---------------------------------------------- |
| `hive` | string | Yes      | Registry hive                 | `HKLM`                                         |
| `key`  | string | Yes      | Parent key (subkeys enumerated beneath) | `SOFTWARE\Microsoft\Cryptography\Calais\Readers` |

Valid hives: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG` and their short aliases.

---

## Collected Data Fields (Output)

| Field          | Type    | Required | Description                                              |
| -------------- | ------- | -------- | -------------------------------------------------------- |
| `exists`       | boolean | Yes      | Whether the parent key exists                            |
| `subkey_count` | int     | Yes      | Number of direct child subkeys                           |
| `subkeys`      | string  | No       | Aggregated subkey-name list (one per line / joined)      |

---

## State Fields (Validation)

| Field          | Type    | Operations                                  | Maps To        | Description                            |
| -------------- | ------- | ------------------------------------------- | -------------- | -------------------------------------- |
| `exists`       | boolean | `=`, `!=`                                   | `exists`       | Parent key existence                   |
| `subkey_count` | int     | `=`, `!=`, `>`, `<`, `>=`, `<=`             | `subkey_count` | Threshold checks on subkey count       |
| `subkeys`      | string  | `contains`, `not_contains`, `pattern_match` | `subkeys`      | Check a specific subkey name is listed |

---

## Collection Strategy

| Property                     | Value                      |
| ---------------------------- | -------------------------- |
| Collector Type               | `windows_registry_subkeys` |
| Collection Mode              | Metadata                   |
| Required Capabilities        | `registry_read`            |
| Expected Collection Time     | ~150ms                     |
| Memory Usage                 | ~2MB                       |
| Requires Elevated Privileges | No                         |

### Behaviors

| Behavior   | Values              | Default | Description                 |
| ---------- | ------------------- | ------- | --------------------------- |
| `executor` | `reg`, `powershell` | `reg`   | Subkey enumeration backend  |

---

## Command Execution

### Default (reg.exe)

```
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Calais\Readers"
```

Output lists child subkey paths (one per line). The collector counts
them and joins subkey short names for `subkeys`.

### PowerShell

```
powershell -NoProfile -NonInteractive -Command "Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers' | Select-Object -ExpandProperty PSChildName"
```

---

## ESP Examples

### At least one smart-card reader driver is installed

```esp
OBJECT smartcard_readers
    hive `HKLM`
    key `SOFTWARE\Microsoft\Cryptography\Calais\Readers`
OBJECT_END

STATE one_or_more
    exists boolean = true
    subkey_count int >= 1
STATE_END

CTN registry_subkeys
    TEST at_least_one all AND
    STATE_REF one_or_more
    OBJECT_REF smartcard_readers
CTN_END
```

### No third-party credential providers beyond the Microsoft defaults

```esp
OBJECT cred_providers
    hive `HKLM`
    key `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
OBJECT_END

STATE limited_providers
    exists boolean = true
    subkey_count int <= 10
STATE_END

CTN registry_subkeys
    TEST at_least_one all AND
    STATE_REF limited_providers
    OBJECT_REF cred_providers
CTN_END
```

### A specific USB reader driver is present by name

```esp
OBJECT usbccid_reader
    hive `HKLM`
    key `SOFTWARE\Microsoft\Cryptography\Calais\Readers`
OBJECT_END

STATE has_usbccid
    subkeys string contains `Microsoft Usbccid Smartcard Reader`
STATE_END

CTN registry_subkeys
    TEST at_least_one all AND
    STATE_REF has_usbccid
    OBJECT_REF usbccid_reader
CTN_END
```

---

## Error Conditions

| Condition                   | Error Type         | Effect on TEST                   |
| --------------------------- | ------------------ | -------------------------------- |
| Parent key missing          | N/A                | `exists` = false, `subkey_count` = 0 |
| Access denied               | `AccessDenied`     | Error state                      |
| reg.exe / PowerShell timeout| `CollectionFailed` | Error state                      |

---

## Platform Notes

### Windows Server 2022

- Both executors available. `reg` is faster for deep trees.
- Subkey names containing spaces or backslashes are preserved as-is in the `subkeys` string.

### Caveats

- Only direct children are enumerated; no recursive descent.
- Subkey ordering is not stable between collections; always use `contains` for name checks.

---

## Security Considerations

- Read-only enumeration; no elevated privileges required for policy hives.
- Hives requiring SYSTEM (`HKLM\SECURITY`) will raise `AccessDenied`.

---

## Related CTN Types

| CTN Type   | Relationship                                     |
| ---------- | ------------------------------------------------ |
| `registry` | Query a specific value under one of the enumerated subkeys |
