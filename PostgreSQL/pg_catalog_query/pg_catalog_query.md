# pg_catalog_query

## Overview

Runs predefined queries against PostgreSQL system catalogs and returns results
as structured data for field-level validation. Queries are selected by name
from a built-in library — arbitrary SQL is not accepted.

**Pattern:** A (System binary — psql)
**Executor:** Simple + RecordData support
**RECORD:** yes

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | Predefined query name from the built-in library |
| `filter` | string | No | Filter parameter for parameterized queries (e.g., extension name) |
| `database` | string | No | Target database. Defaults to `postgres`. Extensions/schemas are per-database. |
| `host` | string | No | PostgreSQL host. Defaults to `127.0.0.1` |
| `username` | string | No | PostgreSQL role. Defaults to `postgres` |

## Query Library

| Query Name | STIG Controls | What It Checks |
|------------|---------------|----------------|
| `password_hashes` | V-261891 | Weak/missing password hashes in pg_shadow |
| `role_connection_limits` | V-261857 | Per-role connection limits from pg_roles |
| `installed_extensions` | V-261888 | Non-default extensions from pg_extension |
| `extension_available` | V-261901, V-261930, V-261931 | Check if a specific extension exists (use `filter` for name) |
| `security_definer_functions` | V-261916 | Functions with SECURITY DEFINER outside system schemas |
| `role_attributes` | V-261859, V-261862, V-261890, V-261897 | Role privileges (superuser, createdb, login, etc.) |
| `ssl_settings` | V-261893 | SSL-related file paths from pg_settings |

## Authentication

Same model as `pg_config_param`:
- TCP loopback (`-h 127.0.0.1`) by default
- `ESP_PG_PASS` env var -> `PGPASSWORD` via dynamic resolution
- Uses shared `create_psql_executor()` from `commands/pg.rs`

## Commands Executed

```
psql -U <username> -h <host> -d <database> -At -c "<sql from query library>"
```

All queries wrap results in `json_agg(row_to_json(t))` for machine-parseable output.

**Sample response (password_hashes):**
```json
[{"usename":"postgres","hash_type":"scram-sha-256"},{"usename":"app_user","hash_type":"scram-sha-256"}]
```

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `found` | boolean | Yes | Whether query returned any rows |
| `row_count` | int | Yes | Number of rows returned |
| `record` | string (JSON) | When found=true | JSON array of result rows |

## State Fields

| Field | Type | Operations | Description |
|-------|------|------------|-------------|
| `found` | boolean | =, != | Query returned rows |
| `row_count` | int | =, !=, >, <, >=, <= | Row count comparison |
| `record` | RecordData | (record checks) | Field-level validation of results |

## ESP Examples

### Assert no weak password hashes (V-261891)

```
OBJECT pg_weak_passwords
    query `password_hashes`
OBJECT_END

STATE no_weak_hashes
    found boolean = true
    row_count int > 0
STATE_END
```

Note: This checks that the query runs and returns results. To validate
that NO weak hashes exist, use a record check on the hash_type field.

### Check pgcrypto extension is available (V-261901)

```
OBJECT pg_pgcrypto
    query `extension_available`
    filter `pgcrypto`
OBJECT_END

STATE pgcrypto_available
    found boolean = true
STATE_END
```

### Assert no security definer functions in user schemas (V-261916)

```
OBJECT pg_secdef_funcs
    query `security_definer_functions`
OBJECT_END

STATE no_secdef_funcs
    row_count int = 0
STATE_END
```

## PG16 STIG Coverage

This CTN covers **~27 controls** across two categories:

**SELECT-based checks (~13 controls):**
V-261857, V-261888, V-261891, V-261893, V-261901, V-261916, V-261930, V-261931

**Meta-command equivalents (~14 controls):**
V-261859, V-261862, V-261863, V-261878, V-261884, V-261885, V-261888,
V-261890, V-261897, V-261898, V-261902, V-261914, V-261923, V-261924

Meta-commands (\du, \dp, \l, etc.) are replaced by their underlying
catalog queries in the query library.

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| Unknown query name | InvalidObjectConfiguration error |
| psql connection failed | CollectionFailed error |
| Auth failed | exit_code != 0, found=false |
| Query returns no rows | found=false, row_count=0 |
| Query returns null | found=false, row_count=0 |

## Related CTN Types

- `pg_config_param` — for SHOW parameter checks (simpler, scalar values)
- `file_content` — for pg_hba.conf / pg_ident.conf file-level checks
