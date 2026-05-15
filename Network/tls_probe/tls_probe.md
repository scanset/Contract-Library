# tls_probe

## Overview

Connects to a `host:port` via TLS handshake and reports the negotiated protocol version, cipher suite, certificate chain details (subject, issuer, expiry), and connection success/failure. Uses `openssl s_client` under the hood. Platform-agnostic — runs anywhere the assessor host can reach the target. Useful for verifying TLS minimums, certificate validity windows, and cipher-suite compliance.

**Platform:** Cross-platform (requires `openssl` binary)
**Collection Method:** Single `openssl s_client` invocation per object via the system command executor

**Note:** This CTN does not perform a full HTTP request — only the TLS handshake. For HTTP-layer checks (status codes, headers), use `http_probe`. The `port` field is a **string** to allow variable substitution from RUN blocks.

---

## Object Fields

| Field        | Type   | Required | Description                                          | Example                                          |
| ------------ | ------ | -------- | ---------------------------------------------------- | ------------------------------------------------ |
| `host`       | string | **Yes**  | Hostname or IP to connect to                         | `localhost`, `10.0.0.1`, `api.example.com`       |
| `port`       | string | **Yes**  | Port number (string for variable substitution)       | `443`, `6443`, `5432`, `2379`                    |
| `servername` | string | No       | SNI server name. Defaults to `host`                  | `api.example.com`                                |

---

## Commands Executed

### Command 1: openssl s_client

Performs the TLS handshake and dumps connection details.

**Resulting commands:**

```
# Default — uses host as SNI
echo "" | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null

# Explicit SNI
echo "" | openssl s_client -connect 10.0.0.1:443 -servername api.example.com 2>/dev/null

# Kube API server
echo "" | openssl s_client -connect localhost:6443 -servername localhost 2>/dev/null
```

**Sample response captured:**

```
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = api.example.com
   i:CN = R3, O = Let's Encrypt, C = US
---
SSL handshake has read 5234 bytes and written 320 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
---
notAfter=Apr 10 00:44:04 2027 GMT
```

**Response parsing:**

- `Protocol  : TLSv1.x` → `protocol`
- `Cipher    : ...` → `cipher`
- `s:CN = ...` (first cert) → `cert_subject`
- `i:CN = ...` (first cert) → `cert_issuer`
- `notAfter=...` → `cert_not_after`
- `Verification: ...` → `verify_result`
- `subject == issuer` → `self_signed=true`
- TLS handshake succeeded → `connected=true`. Connection refused / TLS failure → `connected=false`.

---

## Collected Data Fields

### Scalar Fields

| Field            | Type    | Always Present | Source                                |
| ---------------- | ------- | -------------- | ------------------------------------- |
| `connected`      | boolean | Yes            | Derived — `true` if handshake succeeded |
| `protocol`       | string  | When connected | `Protocol  : ...`                     |
| `cipher`         | string  | When connected | `Cipher    : ...`                     |
| `cert_subject`   | string  | When connected | First cert's `s:CN = ...`             |
| `cert_issuer`    | string  | When connected | First cert's `i:CN = ...`             |
| `cert_not_after` | string  | When connected | `notAfter=...`                        |
| `self_signed`    | boolean | When connected | Derived — `cert_subject == cert_issuer` |
| `verify_result`  | string  | When connected | `Verification: ...`                   |

This CTN does not expose a `resource` / RecordData field — all fields are flat scalars.

---

## State Fields

| State Field      | Type    | Allowed Operations              | Maps To Collected Field |
| ---------------- | ------- | ------------------------------- | ----------------------- |
| `connected`      | boolean | `=`, `!=`                       | `connected`             |
| `protocol`       | string  | `=`, `!=`, `contains`           | `protocol`              |
| `cipher`         | string  | `=`, `!=`, `contains`           | `cipher`                |
| `cert_subject`   | string  | `=`, `!=`, `contains`           | `cert_subject`          |
| `cert_issuer`    | string  | `=`, `!=`, `contains`           | `cert_issuer`           |
| `cert_not_after` | string  | `=`, `!=`, `contains`           | `cert_not_after`        |
| `self_signed`    | boolean | `=`, `!=`                       | `self_signed`           |
| `verify_result`  | string  | `=`, `!=`, `contains`           | `verify_result`         |

---

## Collection Strategy

| Property                     | Value                 |
| ---------------------------- | --------------------- |
| Collector ID                 | `tls_probe_collector` |
| Collector Type               | `tls_probe`           |
| Collection Mode              | Metadata              |
| Required Capabilities        | `openssl_access`      |
| Expected Collection Time     | ~2000ms               |
| Memory Usage                 | ~1MB                  |
| Network Intensive            | Yes                   |
| CPU Intensive                | No                    |
| Requires Elevated Privileges | No                    |
| Batch Collection             | No                    |

### Required Permissions

`openssl` binary must be in `PATH`. Network reachability to `host:port` is required.

---

## ESP Examples

### Enforce TLS 1.2 minimum on storage endpoint

```esp
OBJECT storage_account_endpoint
    host `mystorage.blob.core.windows.net`
    port `443`
OBJECT_END

STATE tls_12_minimum
    connected boolean = true
    protocol string contains `TLSv1.`
    self_signed boolean = false
    verify_result string = `ok`
STATE_END

CTN tls_probe
    TEST all all AND
    STATE_REF tls_12_minimum
    OBJECT_REF storage_account_endpoint
CTN_END
```

### Validate kube apiserver uses TLSv1.3

```esp
OBJECT kube_apiserver
    host `localhost`
    port `6443`
OBJECT_END

STATE modern_tls
    connected boolean = true
    protocol string = `TLSv1.3`
    cipher string contains `AES_256_GCM`
STATE_END

CTN tls_probe
    TEST all all AND
    STATE_REF modern_tls
    OBJECT_REF kube_apiserver
CTN_END
```

### Confirm cert is not self-signed and not near expiry

```esp
OBJECT public_endpoint
    host `api.example.com`
    port `443`
    servername `api.example.com`
OBJECT_END

STATE valid_public_cert
    connected boolean = true
    self_signed boolean = false
    verify_result string = `ok`
    cert_issuer string contains `Let's Encrypt`
STATE_END

CTN tls_probe
    TEST all all AND
    STATE_REF valid_public_cert
    OBJECT_REF public_endpoint
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome             |
| ---------------------------------------- | ---------------------------- | ------------------- |
| `host` or `port` missing                 | `InvalidObjectConfiguration` | Error               |
| Connection refused                       | N/A — captured as data       | `connected=false`   |
| TLS handshake failure (e.g. SSL_ERROR)   | N/A — captured as data       | `connected=false`   |
| Cert verification failed                 | N/A — `verify_result` carries reason | `connected=true`, `verify_result` has detail |
| `openssl` binary missing                 | `CollectionFailed`           | Error               |
| Incompatible CTN type                    | `CtnContractValidation`      | Error               |

---

## Related CTN Types

| CTN Type             | Relationship                                                              |
| -------------------- | ------------------------------------------------------------------------- |
| `http_probe`         | HTTP-layer checks (status, headers, body) — sibling for full-stack checks |
| `tcp_listener`       | TCP-layer only — confirms port is open before TLS handshake               |
| `openssl_cert`       | Static cert file inspection — different shape, doesn't connect            |
| `crypto_policy`      | OS-level crypto policy (RHEL) — sibling for system-wide TLS minimums      |
