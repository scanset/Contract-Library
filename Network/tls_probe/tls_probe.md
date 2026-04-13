# tls_probe

## Overview

Connects to a host:port via TLS handshake and reports the negotiated protocol
version, cipher suite, certificate details, and verification result. Uses
`openssl s_client` directly. Supports STARTTLS for protocols like PostgreSQL,
SMTP, FTP, and IMAP. Cross-platform.

**Pattern:** A (System binary - openssl)
**Executor:** Simple (boolean + string)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | Yes | Hostname or IP to connect to |
| `port` | string | Yes | Port number |
| `servername` | string | No | SNI server name (defaults to host) |
| `starttls` | string | No | STARTTLS protocol (postgres, smtp, ftp, imap, etc.) |

## Collected Data Fields

| Field | Type | Description |
|-------|------|-------------|
| `connected` | boolean | TLS handshake succeeded |
| `protocol` | string | TLSv1.2, TLSv1.3, etc. |
| `cipher` | string | Negotiated cipher suite |
| `cert_subject` | string | Server certificate subject |
| `cert_issuer` | string | Server certificate issuer |
| `cert_not_after` | string | Certificate expiration date |
| `self_signed` | boolean | Derived: subject == issuer or verify error contains "self-signed" |
| `verify_result` | string | OpenSSL verification result |

## Agent Requirements

- `openssl` in PATH
- Network access to the target host:port
