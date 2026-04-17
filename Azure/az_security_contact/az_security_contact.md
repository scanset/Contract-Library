# az_security_contact CTN

## Overview

Validates Azure Security Center contact configuration via `az security contact show`.

**CLI command:** `az security contact show --name <name> [--subscription <id>] --output json`

**Scope:** Subscription-level (no resource group required)

---

## OBJECT Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Security contact name (only 'default' is valid) |
| `subscription` | string | No | Subscription ID override |

---

## STATE Fields

### String Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `name` | = != | Contact name | `default` |
| `id` | = != contains startswith | Full ARM resource ID | `/subscriptions/.../securityContacts/default` |
| `type` | = != | ARM resource type | `Microsoft.Security/securityContacts` |
| `emails` | = != contains startswith | Notification email addresses | `security@example.com` |
| `phone` | = != contains startswith | Phone number | `+15551234567` |
| `alert_notifications_state` | = != | Alert notifications enabled | `On` |
| `alert_notifications_severity` | = != | Minimum alert severity | `High` |
| `notifications_by_role_state` | = != | Role-based notifications enabled | `On` |

### Boolean Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `found` | = != | Whether the security contact was found | `true` |
| `has_email` | = != | Whether notification email is configured | `true` |
| `has_phone` | = != | Whether phone number is configured | `true` |

### Integer Fields

| Field | Ops | Description | Example |
|-------|-----|-------------|---------|
| `notification_role_count` | = != > >= < <= | Number of roles for notifications | `1` |

### RecordData

| Field | Ops | Description |
|-------|-----|-------------|
| `record` | = | Full contact object as RecordData (use record_checks for role array) |

---

## NotFound Handling

- `(BadRequest)` with exit code 1 -- invalid contact name
- `(ResourceNotFound)` -- no contact configured
- Only `default` is a valid contact name

---

## Example ESP Policy

```esp
OBJECT contact_default
    name `default`
OBJECT_END

STATE st_contact_configured
    found boolean = true
    has_email boolean = true
    alert_notifications_state string = `On`
    alert_notifications_severity string = `High`
    notifications_by_role_state string = `On`
STATE_END

CRI AND
    CTN az_security_contact
        TEST all all AND
        STATE_REF st_contact_configured
        OBJECT_REF contact_default
    CTN_END
CRI_END
```

---

## Notes

- Only `default` is a valid security contact name
- CIS Azure 2.1.19: Ensure security contact email is configured
- CIS Azure 2.1.20: Ensure security contact phone is configured
- CIS Azure 2.1.21: Ensure alert notifications are enabled with high severity
- `emails` may contain comma-separated addresses
- `phone` may be empty string (not configured)
