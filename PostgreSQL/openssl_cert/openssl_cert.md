# openssl_cert

## Overview

Inspects X.509 certificates via `openssl x509` and extracts subject, issuer,
validity dates, common name, and a derived self_signed flag.
Platform-agnostic — works on any OS where `openssl` is in PATH.

**Pattern:** A (System binary — openssl)
**Executor:** Simple (boolean + string comparison)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Absolute path to the X.509 certificate file |

## Commands Executed

```
openssl x509 -noout -subject -issuer -dates -in <path>
```

**Sample response:**
```
subject=CN=localhost
issuer=CN=localhost
notBefore=Apr 10 00:44:04 2026 GMT
notAfter=Apr 10 00:44:04 2027 GMT
```

**Parsing:** Split lines on first `=`. Keys: `subject`, `issuer`, `notBefore`, `notAfter`.
CN is extracted from subject by splitting on commas and finding `CN=` prefix.
self_signed is derived: `true` when subject == issuer.

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `found` | boolean | Yes | Whether the cert file exists and is parseable |
| `subject` | string | When found=true | Full subject line |
| `issuer` | string | When found=true | Full issuer line |
| `cn` | string | When found=true and CN present | Common Name from subject |
| `not_before` | string | When found=true | Validity start date |
| `not_after` | string | When found=true | Validity end date |
| `self_signed` | boolean | When found=true | Derived: subject == issuer |

## State Fields

| Field | Type | Operations | Description |
|-------|------|------------|-------------|
| `found` | boolean | =, != | Certificate exists and is valid |
| `subject` | string | =, !=, contains | Full subject line |
| `issuer` | string | =, !=, contains | Full issuer line |
| `cn` | string | =, !=, contains | Common Name for PKI identity matching |
| `not_before` | string | =, != | Validity start date |
| `not_after` | string | =, != | Validity end date |
| `self_signed` | boolean | =, != | Whether cert is self-signed |

## Collection Strategy

- **Mode:** Metadata
- **Capability:** `openssl_access`
- **Expected time:** ~50ms
- **Network:** No
- **Elevated:** No (reads cert file directly)

## ESP Examples

### Verify server certificate exists and is not self-signed

```
OBJECT pg_server_cert
    path `/var/lib/pgsql/16/data/server.crt`
OBJECT_END

STATE cert_valid
    found boolean = true
    self_signed boolean = false
STATE_END
```

### Verify certificate CN matches expected hostname

```
OBJECT pg_server_cert
    path `/var/lib/pgsql/16/data/server.crt`
OBJECT_END

STATE cn_matches
    found boolean = true
    cn string = `db.example.com`
STATE_END
```

## PG16 STIG Coverage

| Control | What It Checks | How This CTN Helps |
|---------|---------------|-------------------|
| V-261895 (CD16-00-004200) | PKI identity maps to DB user | `cn` field compared to expected username |
| V-261929 (CD16-00-008400) | DOD-approved certificates | `issuer` contains expected CA, `self_signed = false` |

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| openssl not in PATH | CollectionFailed error |
| File not found | exit_code != 0, found=false |
| Not a valid certificate | exit_code != 0, found=false |
| No CN in subject | found=true, cn field absent |

## Related CTN Types

- `pg_config_param` — check ssl_cert_file, ssl_key_file, ssl_ca_file paths
- `file_metadata` — check certificate/key file permissions
- `pg_catalog_query` (ssl_settings) — get SSL file paths from pg_settings
