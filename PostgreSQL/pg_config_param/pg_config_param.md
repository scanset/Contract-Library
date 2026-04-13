# pg_config_param

## Overview

Validates PostgreSQL runtime configuration parameters by querying them via `SHOW`.
Platform-agnostic — works on any OS where `psql` is accessible.

**Pattern:** A (System binary — psql)
**Executor:** Simple (boolean + string comparison)

## Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `parameter` | string | Yes | PostgreSQL parameter name (e.g., `max_connections`, `shared_preload_libraries`) |
| `host` | string | No | PostgreSQL host. Defaults to `127.0.0.1` (TCP loopback) |
| `username` | string | No | PostgreSQL role to connect as. Defaults to `postgres` |
| `connection` | string | No | Connection URI for remote/non-default setups. Do not embed credentials |

## Authentication

The collector connects via TCP (`-h 127.0.0.1`) by default, not via Unix socket.
This avoids peer auth OS user mismatch (agent runs as root, DB role is postgres).

### Environment Variable: `ESP_PG_PASS`

Set `ESP_PG_PASS` in the agent's environment to provide the PostgreSQL password.
The command factory (`create_psql_executor`) uses dynamic env resolution:

    executor.set_env_from("PGPASSWORD", "ESP_PG_PASS");

On EVERY `execute()` call, the executor reads `ESP_PG_PASS` from the agent's
current environment and injects it as `PGPASSWORD` into the spawned psql process.

**Key behaviors:**
- **Credential rotation without restart** — update the env var, next scan uses it
- **Password never in policy files** — policies contain only parameter names
- **Password never in evidence** — command strings show the query, not the password
- **Silently skipped if unset** — if `ESP_PG_PASS` is not set, PGPASSWORD is
  not injected. Useful for peer-auth setups where no password is needed.

**Setup:**

    # Set password for postgres role (one-time)
    sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'your-password';"

    # Export for agent
    export ESP_PG_PASS="your-password"


**For Kubernetes deployments**, inject via Secret -> env var:

    env:
      - name: ESP_PG_PASS
        valueFrom:
          secretKeyRef:
            name: pg-credentials
            key: password

### pg_hba.conf Requirements

The default TCP connection (`-h 127.0.0.1`) requires a host auth rule:

    host   all   postgres   127.0.0.1/32   scram-sha-256

This is the RHEL default for host connections.

### Peer Auth (alternative, no password needed)

If the agent runs as the `postgres` OS user (e.g., via `sudo -u postgres`),
set `host` to empty or override with a Unix socket path. Peer auth avoids
the need for `ESP_PG_PASS` but requires OS user = DB role.

### Security Note

`SystemCommandExecutor` clears ALL inherited environment variables via
`env_clear()`. The spawned psql process gets only:
- `PATH` — restricted system dirs + PostgreSQL bin dirs
- `PGPASSWORD` — only if `ESP_PG_PASS` is set (dynamic resolution)

No other env vars leak into the child process.

## Commands Executed

```
psql -U <username> -h <host> -At [-d <connection>] -c "SHOW <parameter>"
```

**Flags:**
- `-U` — connect as this role (default: `postgres`)
- `-h` — host to connect to (default: `127.0.0.1`)
- `-A` — unaligned output (no padding)
- `-t` — tuples only (no header/footer)

**Sample response:**
```
on
```

**Parsing:** Trim whitespace from stdout. Non-zero exit code = parameter not found.

## Collected Data Fields

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `found` | boolean | Yes | Whether the parameter exists |
| `value` | string | When found=true | Raw string value from SHOW |

## State Fields

| Field | Type | Operations | Description |
|-------|------|------------|-------------|
| `found` | boolean | Equals, NotEqual | Parameter existence |
| `value` | string | Equals, NotEqual, Contains | Parameter value comparison |

## Collection Strategy

- **Mode:** Metadata
- **Capability:** `psql_access`
- **Expected time:** ~50ms
- **Network:** TCP loopback (127.0.0.1:5432)
- **Elevated:** No
- **Auth:** `ESP_PG_PASS` env var -> PGPASSWORD (dynamic, resolved per call)

## ESP Examples

### Scalar check — verify password encryption

```
OBJECT pg_password_enc
    parameter `password_encryption`
OBJECT_END

STATE pg_password_enc_state
    value string = `scram-sha-256`
STATE_END
```

### Scalar check — verify pgaudit is loaded

```
OBJECT pg_preload
    parameter `shared_preload_libraries`
OBJECT_END

STATE pg_preload_state
    value string contains `pgaudit`
STATE_END
```

### Scalar check — verify SSL is enabled

```
OBJECT pg_ssl
    parameter `ssl`
OBJECT_END

STATE pg_ssl_state
    value string = `on`
STATE_END
```

## PG16 STIG Coverage

This CTN covers **43 controls** checking 22 distinct parameters:

| Parameter | STIG Controls |
|-----------|---------------|
| `shared_preload_libraries` | V-261860, V-261861, V-261863, V-261865-V-261869, V-261871, V-261934, V-261939, V-261942-V-261945, V-261947, V-261951-V-261952, V-261956-V-261957, V-261959-V-261960, V-261963 |
| `pgaudit.log` | V-261861, V-261865-V-261869, V-261871 |
| `log_line_prefix` | V-261860, V-261875 |
| `log_connections` | V-261876 |
| `log_disconnections` | V-261877 |
| `log_destination` | V-261879 |
| `log_file_mode` | V-261879 |
| `log_hostname` | V-261889 |
| `log_timezone` | V-261891 |
| `client_min_messages` | V-261899, V-261900 |
| `password_encryption` | V-261908 |
| `ssl` | V-261909, V-261917 |
| `ssl_ca_file` | V-261921, V-261922 |
| `ssl_cert_file` | V-261926 |
| `syslog_facility` | V-261928, V-261929 |
| `port` | V-261932, V-261933 |
| `listen_addresses` | V-261938, V-261940 |
| `statement_timeout` | V-261941 |
| `max_connections` | V-261857 |
| `tcp_keepalives_idle` | V-261946 |
| `tcp_keepalives_interval` | V-261946 |
| `tcp_keepalives_count` | V-261946 |

## Error Conditions

| Condition | Behavior |
|-----------|----------|
| psql not in PATH | CollectionFailed error |
| Connection refused | CollectionFailed error |
| Auth failed (no ESP_PG_PASS) | exit_code != 0, found=false |
| Unrecognized parameter | exit_code != 0, found=false |
| Empty value | found=true, value="" |

## Related CTN Types

- `pg_catalog_query` — for SELECT-based system catalog checks
- `file_content` — for pg_hba.conf / postgresql.conf file-level checks
- `file_metadata` — for PGDATA permission checks
