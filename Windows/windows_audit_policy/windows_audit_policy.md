# windows_audit_policy

## Overview

Validates an Advanced Audit Policy subcategory via
`auditpol /get /category:* /r`. One object per subcategory; state fields
cover existence, raw inclusion string, and booleans for Success / Failure
auditing.

**Platform:** Windows Server 2022 (and Win10/Win11)
**Use Case:** STIG requirements that specific subcategories audit
Success, Failure, or both (Credential Validation, Logon, Sensitive
Privilege Use, ...).

---

## Object Fields (Input)

| Field         | Type   | Required | Description                                       | Example                          |
| ------------- | ------ | -------- | ------------------------------------------------- | -------------------------------- |
| `subcategory` | string | Yes      | Subcategory name as it appears in auditpol output | `Credential Validation`, `Logon`, `Sensitive Privilege Use` |

- Match is case-insensitive.
- Use the human-readable name, not the GUID.

---

## Collected Data Fields (Output)

| Field             | Type    | Required | Description                                   |
| ----------------- | ------- | -------- | --------------------------------------------- |
| `exists`          | boolean | Yes      | Subcategory present in auditpol output        |
| `setting`         | string  | Yes      | Raw inclusion string (`No Auditing`, `Success`, `Failure`, `Success and Failure`) |
| `success_audited` | boolean | Yes      | Convenience: setting includes Success         |
| `failure_audited` | boolean | Yes      | Convenience: setting includes Failure         |

---

## State Fields (Validation)

| Field             | Type    | Operations                                                                 | Description                              |
| ----------------- | ------- | -------------------------------------------------------------------------- | ---------------------------------------- |
| `exists`          | boolean | `=`, `!=`                                                                  | Subcategory present                      |
| `setting`         | string  | `=`, `!=`, `contains`, `not_contains`, `ieq`, `ine`                        | Raw inclusion string                     |
| `success_audited` | boolean | `=`, `!=`                                                                  | Success events are audited               |
| `failure_audited` | boolean | `=`, `!=`                                                                  | Failure events are audited               |

### Valid `setting` values

`No Auditing`, `Success`, `Failure`, `Success and Failure`

---

## Collection Strategy

| Property                     | Value                   |
| ---------------------------- | ----------------------- |
| Collector Type               | `windows_audit_policy`  |
| Collection Mode              | Metadata                |
| Required Capabilities        | `auditpol_query`        |
| Expected Collection Time     | ~500ms                  |
| Memory Usage                 | ~1MB                    |
| Requires Elevated Privileges | **Yes** (local Administrator) |

---

## Command Execution

Single invocation returns CSV for all subcategories:

```
auditpol.exe /get /category:* /r
```

### Output (CSV excerpt)

```
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
WIN-SRV,System,Credential Validation,{0CCE923F-...},Success and Failure,
WIN-SRV,System,Logon,{0CCE9215-...},Success and Failure,
WIN-SRV,System,Sensitive Privilege Use,{0CCE9228-...},Failure,
WIN-SRV,System,Security Group Management,{0CCE9237-...},Success,
```

The parser is BOM-tolerant and handles quoted fields
(e.g. `"Object Access, Detailed"`).

### Whitelisted Commands

| Command       | Path                                |
| ------------- | ----------------------------------- |
| `auditpol.exe`| `C:\Windows\System32\auditpol.exe`  |

---

## ESP Examples

### Credential Validation audits both Success and Failure

```esp
OBJECT cred_validation
    subcategory `Credential Validation`
OBJECT_END

STATE success_and_failure
    exists boolean = true
    success_audited boolean = true
    failure_audited boolean = true
STATE_END

CTN windows_audit_policy
    TEST at_least_one all AND
    STATE_REF success_and_failure
    OBJECT_REF cred_validation
CTN_END
```

### Sensitive Privilege Use audits Failure (Success optional)

```esp
OBJECT sens_priv
    subcategory `Sensitive Privilege Use`
OBJECT_END

STATE failure_required
    exists boolean = true
    failure_audited boolean = true
STATE_END

CTN windows_audit_policy
    TEST at_least_one all AND
    STATE_REF failure_required
    OBJECT_REF sens_priv
CTN_END
```

### Logon audits neither are off

```esp
OBJECT logon_audit
    subcategory `Logon`
OBJECT_END

STATE not_disabled
    exists boolean = true
    setting string not_contains `No Auditing`
STATE_END

CTN windows_audit_policy
    TEST at_least_one all AND
    STATE_REF not_disabled
    OBJECT_REF logon_audit
CTN_END
```

---

## Error Conditions

| Condition                                 | Error Type         | Effect                      |
| ----------------------------------------- | ------------------ | --------------------------- |
| Agent not running as Administrator        | `AccessDenied`     | auditpol returns empty / errors; Error state |
| auditpol.exe missing                      | `CollectionFailed` | Error state                 |
| Subcategory typo / not in output          | N/A                | `exists` = false            |
| auditpol timeout (>30s)                   | `CollectionFailed` | Error state                 |

---

## Platform Notes

### Windows Server 2022 (primary)

- `auditpol.exe` is present by default at `C:\Windows\System32\auditpol.exe`.
- Subcategory names are locale-aware; use the English names unless policies are tested on a localized host.

### Caveats

- Auditpol's CSV can include a "System audit policy" divider row which the parser skips.
- Basic Audit Policy (`AUDITPOL /get /category:*` vs the older `auditpol.msc` Basic Policy) is superseded; always target subcategories.

---

## Security Considerations

- Requires local Administrator (capability `auditpol_query`).
- Read-only - `auditpol /get` does not mutate policy.

---

## Related CTN Types

| CTN Type                  | Relationship                                                 |
| ------------------------- | ------------------------------------------------------------ |
| `windows_security_policy` | User Rights Assignment and Security Options (different secedit areas) |
| `registry`                | Event log size / retention keys that complement audit policy |
