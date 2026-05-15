# pg_catalog_query

## Overview

Runs **predefined queries** against PostgreSQL system catalogs and returns results as RecordData for field-level validation. Queries are identified **by name** from a built-in library — arbitrary SQL is not accepted. Used for compliance checks against role configuration, extensions, password hashing, security-definer functions, and similar catalog-introspectable state.

**Platform:** PostgreSQL (requires `psql` binary, TCP loopback to PostgreSQL)
**Collection Method:** Single `psql` invocation via the shared `create_psql_executor()` from `commands/pg.rs`

**Note:** Connects via **TCP** (`-h 127.0.0.1`), not Unix socket. Peer auth fails when the assessor runs as root because OS user ≠ postgres role. Set the `ESP_PG_PASS` env var for password auth — it's resolved per scan via the `set_env_from` mechanism. The query library lives in code, not config — adding a query requires a Rust change.

---

## Object Fields

| Field      | Type   | Required | Description                                                                                  | Example                                                  |
| ---------- | ------ | -------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `query`    | string | **Yes**  | Predefined query name from the built-in library. Arbitrary SQL refused.                      | `password_hashes`, `installed_extensions`, `role_connection_limits`, `security_definer_functions` |
| `filter`   | string | No       | Optional filter passed to parameterized queries. Usage depends on the query name             | `pgcrypto`, `pgaudit`                                    |
| `database` | string | No       | Target database for db-scoped queries. Defaults to `postgres`. Extensions/schemas are per-db | `postgres`, `my_app_db`                                  |
| `host`     | string | No       | PostgreSQL host. Defaults to `127.0.0.1` (TCP loopback)                                      | `127.0.0.1`                                              |
| `username` | string | No       | PostgreSQL role to connect as. Defaults to `postgres`                                        | `postgres`                                               |

---

## Commands Executed

### Command 1: psql

Looks up the named query in the in-code library, runs it via `psql`, captures rows as JSON.

**Collector call:** `executor.run(query_name, filter, database, host, username)` — the executor is shared with `pg_config_param` (see `commands/pg.rs::create_psql_executor()`).

**Resulting command** (representative):

```
PGPASSWORD=$ESP_PG_PASS psql \
    -h 127.0.0.1 -U postgres -d postgres \
    -A -t -X --no-password \
    -c "<resolved SQL from query library>"
```

The shared executor:
- Whitelisted psql paths (RHEL: `/usr/pgsql-16/bin`, Debian, generic)
- Extended PATH including `/usr/pgsql-16/bin`
- Dynamic env: `ESP_PG_PASS → PGPASSWORD` via `set_env_from`

**Sample response (varies by query):**

For `password_hashes`:
```json
[
  {"role": "postgres", "encrypted": true, "method": "scram-sha-256"},
  {"role": "app_user", "encrypted": true, "method": "scram-sha-256"}
]
```

For `installed_extensions` with `filter=pgcrypto`:
```json
[{"name": "pgcrypto", "version": "1.3", "schema": "public"}]
```

**Response parsing:**

- Rows from psql JSON output → `record` RecordData (array)
- Row count → `row_count`
- Any rows present → `found=true`. Empty / failed query → `found=false`.

---

## Collected Data Fields

### Scalar Fields

| Field       | Type    | Always Present | Source                              |
| ----------- | ------- | -------------- | ----------------------------------- |
| `found`     | boolean | Yes            | Derived — `true` if query returned ≥1 row |
| `row_count` | int     | Yes            | Number of rows                      |

### RecordData Field

| Field    | Type       | Always Present | Description                                                |
| -------- | ---------- | -------------- | ---------------------------------------------------------- |
| `record` | RecordData | Yes            | Query result rows. Path shape depends on the query name    |

---

## RecordData Structure

Path shape depends on the predefined query. Examples:

| Query name                      | RecordData shape                                                    |
| ------------------------------- | ------------------------------------------------------------------- |
| `password_hashes`               | `[{role, encrypted, method}, ...]`                                  |
| `installed_extensions`          | `[{name, version, schema}, ...]`                                    |
| `role_connection_limits`        | `[{role, connection_limit}, ...]`                                   |
| `security_definer_functions`    | `[{schema, function, owner}, ...]`                                  |

Use the query library reference (in `assessor-core/src/contract_kit/commands/pg.rs`) to find the exact column names per query.

---

## State Fields

| State Field | Type       | Allowed Operations              | Maps To Collected Field |
| ----------- | ---------- | ------------------------------- | ----------------------- |
| `found`     | boolean    | `=`, `!=`                       | `found`                 |
| `row_count` | int        | `=`, `!=`, `>`, `>=`, `<`, `<=` | `row_count`             |
| `record`    | RecordData | (record checks)                 | `record`                |

---

## Collection Strategy

| Property                     | Value                          |
| ---------------------------- | ------------------------------ |
| Collector ID                 | `pg_catalog_query_collector`   |
| Collector Type               | `pg_catalog_query`             |
| Collection Mode              | Metadata                       |
| Required Capabilities        | `psql_access`                  |
| Expected Collection Time     | ~100ms                         |
| Memory Usage                 | ~2MB                           |
| Network Intensive            | No (loopback)                  |
| CPU Intensive                | No                             |
| Requires Elevated Privileges | No                             |
| Batch Collection             | No                             |

### Required Permissions

The `username` (default `postgres`) needs `CONNECT` on `database` plus `pg_read_server_files` or equivalent role permissions for the target catalogs. Most predefined queries hit `pg_catalog` tables which are world-readable for connected users.

Set `ESP_PG_PASS` environment variable on the assessor host before scan time. The collector resolves it dynamically per scan.

---

## ESP Examples

### Assert no roles use the deprecated `md5` password method

```esp
OBJECT all_password_hashes
    query `password_hashes`
OBJECT_END

STATE no_md5_passwords
    found boolean = true
    record
        field record.*.method string = `scram-sha-256`
    record_end
STATE_END

CTN pg_catalog_query
    TEST all all AND
    STATE_REF no_md5_passwords
    OBJECT_REF all_password_hashes
CTN_END
```

### Confirm `pgcrypto` extension is installed in app database

```esp
OBJECT pgcrypto_in_app
    query `installed_extensions`
    filter `pgcrypto`
    database `my_app_db`
OBJECT_END

STATE pgcrypto_present
    found boolean = true
    row_count int = `1`
    record
        field record.0.name string = `pgcrypto`
    record_end
STATE_END

CTN pg_catalog_query
    TEST all all AND
    STATE_REF pgcrypto_present
    OBJECT_REF pgcrypto_in_app
CTN_END
```

### Validate no security-definer functions exist outside whitelisted schemas

```esp
OBJECT security_definer_audit
    query `security_definer_functions`
OBJECT_END

STATE no_unauthorized_definers
    row_count int = `0`
STATE_END

CTN pg_catalog_query
    TEST all all AND
    STATE_REF no_unauthorized_definers
    OBJECT_REF security_definer_audit
CTN_END
```

---

## Error Conditions

| Condition                                                  | Error Type                   | Outcome             |
| ---------------------------------------------------------- | ---------------------------- | ------------------- |
| `query` missing or not in library                          | `InvalidObjectConfiguration` | Error               |
| `psql` binary not found                                    | `CollectionFailed`           | Error               |
| Connection refused / network error                         | `CollectionFailed`           | Error               |
| Auth failure (peer auth as root, missing `ESP_PG_PASS`)    | `CollectionFailed`           | Error               |
| Query returns zero rows                                    | N/A — not an error           | `found=false`       |
| `database` doesn't exist                                   | `CollectionFailed`           | Error               |
| Incompatible CTN type                                      | `CtnContractValidation`      | Error               |

---

## Related CTN Types

| CTN Type           | Relationship                                                                          |
| ------------------ | ------------------------------------------------------------------------------------- |
| `pg_config_param`  | SHOW-parameter check — different lookup model (`SHOW`, not catalog query). Sibling.   |
| `tcp_listener`     | Confirm Postgres is listening on the expected port before connecting                  |
| `tls_probe`        | Validate Postgres TLS handshake separately                                            |
| `systemd_service`  | Confirm `postgresql.service` is enabled / active                                      |
