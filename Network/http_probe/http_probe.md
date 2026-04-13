# http_probe

## Overview

Makes HTTP/HTTPS requests to a URL and reports status code, protocol version,
response headers, and redirect information. Uses `curl` directly with
sentinel-based output parsing. Cross-platform.

**Pattern:** A (System binary - curl)
**Executor:** Simple (boolean + string)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Full URL including scheme |
| `method` | string | No | HTTP method (defaults to GET) |
| `insecure` | string | No | Skip TLS verification (true/false, defaults to false) |

## Collected Data Fields

| Field | Type | Description |
|-------|------|-------------|
| `connected` | boolean | HTTP request completed |
| `status_code` | string | HTTP response status code (200, 403, etc.) |
| `protocol` | string | HTTP/2, HTTP/1.1, etc. |
| `headers` | string | Raw response headers |
| `redirect_url` | string | Location header if redirect |

## Agent Requirements

- `curl` in PATH
- Network access to the target URL
