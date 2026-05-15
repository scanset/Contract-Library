# http_probe

## Overview

Makes an HTTP/HTTPS request to a URL and reports the status code, response headers, protocol version, redirect target, and body snippet (first 4KB). Uses `curl` under the hood. Platform-agnostic — runs on any host with `curl` available. Useful for endpoint health, security-header presence, and content-pattern checks.

**Platform:** Cross-platform (requires `curl` binary)
**Collection Method:** Single `curl` invocation per object via the system command executor

**Note:** Body capture is **truncated to 4KB**. Use `contains` / `not_contains` ops on `body` rather than equality. Only `GET` and `HEAD` methods are considered safe — POST/PUT/DELETE could mutate state and the contract refuses them by convention.

---

## Object Fields

| Field      | Type   | Required | Description                                  | Example                                     |
| ---------- | ------ | -------- | -------------------------------------------- | ------------------------------------------- |
| `url`      | string | **Yes**  | Full URL including scheme                    | `https://localhost:443/`, `http://api/health` |
| `method`   | string | No       | HTTP method (defaults to `GET`)              | `GET`, `HEAD`                               |
| `insecure` | string | No       | Skip TLS cert verification (defaults to `false`) | `true`, `false`                          |

---

## Commands Executed

### Command 1: curl

Performs the HTTP request, captures status / headers / body.

**Resulting commands:**

```
# Default GET with TLS verification
curl -sS -i -o - --max-time 30 https://localhost:443/

# HEAD request
curl -sS -I --max-time 30 https://api.example.com/

# Skip cert verification (self-signed)
curl -sS -i -o - -k --max-time 30 https://localhost:6443/healthz
```

**Sample response captured:**

```
HTTP/2 200
content-type: application/json
strict-transport-security: max-age=31536000
x-content-type-options: nosniff

{"status":"ok"}
```

**Response parsing:**

- Status line (e.g. `HTTP/2 200`) → `protocol` (`HTTP/2`) and `status_code` (`200`)
- All header lines concatenated into a single string → `headers`
- Body bytes (first 4KB) → `body`
- `Location:` header value (if present) → `redirect_url`
- Successful execution → `connected=true`. Any curl error (timeout, DNS, refused) → `connected=false`.

---

## Collected Data Fields

### Scalar Fields

| Field          | Type    | Always Present | Source                             |
| -------------- | ------- | -------------- | ---------------------------------- |
| `connected`    | boolean | Yes            | Derived — `true` if curl returned non-error |
| `status_code`  | string  | When connected | HTTP response status line          |
| `protocol`     | string  | When connected | Negotiated protocol (HTTP/1.1 / HTTP/2) |
| `headers`      | string  | When connected | Raw header block, single string    |
| `body`         | string  | When connected | Response body (first 4KB)          |
| `redirect_url` | string  | When 3xx       | `Location:` header value           |

This CTN does not expose a `resource` / RecordData field — all fields are flat scalars.

---

## State Fields

| State Field    | Type    | Allowed Operations              | Maps To Collected Field |
| -------------- | ------- | ------------------------------- | ----------------------- |
| `connected`    | boolean | `=`, `!=`                       | `connected`             |
| `status_code`  | string  | `=`, `!=`, `contains`           | `status_code`           |
| `protocol`     | string  | `=`, `!=`, `contains`           | `protocol`              |
| `headers`      | string  | `=`, `!=`, `contains`           | `headers`               |
| `body`         | string  | `=`, `!=`, `contains`           | `body`                  |
| `redirect_url` | string  | `=`, `!=`, `contains`           | `redirect_url`          |

---

## Collection Strategy

| Property                     | Value                  |
| ---------------------------- | ---------------------- |
| Collector ID                 | `http_probe_collector` |
| Collector Type               | `http_probe`           |
| Collection Mode              | Metadata               |
| Required Capabilities        | `curl_access`          |
| Expected Collection Time     | ~3000ms (timeout 30s)  |
| Memory Usage                 | ~2MB                   |
| Network Intensive            | Yes                    |
| CPU Intensive                | No                     |
| Requires Elevated Privileges | No                     |
| Batch Collection             | No                     |

### Required Permissions

`curl` must be in `PATH`. The host running the assessor needs network reachability to the probed URL — for cluster API endpoints, that typically means in-cluster execution.

---

## ESP Examples

### Validate HSTS header is set on prod endpoint

```esp
OBJECT prod_https_endpoint
    url `https://api.example.com/`
OBJECT_END

STATE has_hsts
    connected boolean = true
    status_code string = `200`
    headers string contains `strict-transport-security`
STATE_END

CTN http_probe
    TEST all all AND
    STATE_REF has_hsts
    OBJECT_REF prod_https_endpoint
CTN_END
```

### Validate HTTP/2 is negotiated

```esp
OBJECT api_endpoint
    url `https://api.example.com/`
    method `HEAD`
OBJECT_END

STATE http2_active
    connected boolean = true
    protocol string = `HTTP/2`
STATE_END

CTN http_probe
    TEST all all AND
    STATE_REF http2_active
    OBJECT_REF api_endpoint
CTN_END
```

### Validate self-signed kubelet endpoint

```esp
OBJECT kubelet_metrics
    url `https://localhost:10250/metrics`
    insecure `true`
OBJECT_END

STATE kubelet_returns_unauthorized
    connected boolean = true
    status_code string = `401`
STATE_END

CTN http_probe
    TEST all all AND
    STATE_REF kubelet_returns_unauthorized
    OBJECT_REF kubelet_metrics
CTN_END
```

---

## Error Conditions

| Condition                                | Error Type                   | Outcome             |
| ---------------------------------------- | ---------------------------- | ------------------- |
| `url` missing                            | `InvalidObjectConfiguration` | Error               |
| Connection refused / DNS / timeout       | N/A — captured as data       | `connected=false`   |
| TLS verification failure (without `insecure`) | N/A — captured as data  | `connected=false`   |
| Unsafe method (POST/PUT/DELETE)          | (convention-only refusal)    | Use a different CTN |
| `curl` binary missing                    | `CollectionFailed`           | Error               |
| Incompatible CTN type                    | `CtnContractValidation`      | Error               |

---

## Related CTN Types

| CTN Type            | Relationship                                                                    |
| ------------------- | ------------------------------------------------------------------------------- |
| `tls_probe`         | TLS handshake details only — use when you need cipher / cert info, not body     |
| `tcp_listener`      | Local listening port — sibling for "is it accepting connections at all"         |
| `file_content`      | Static config validation — use this for content patterns when not over HTTP    |
