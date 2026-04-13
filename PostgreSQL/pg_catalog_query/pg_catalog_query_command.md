# Command: Shared with pg_config_param

pg_catalog_query reuses `create_psql_executor()` from `commands/pg.rs`.
No separate command file — see `../pg_config_param/pg_config_param_command.rs`.

The shared executor provides:
- Whitelisted psql paths (RHEL, Debian, generic)
- Extended PATH including /usr/pgsql-16/bin
- Dynamic env: ESP_PG_PASS -> PGPASSWORD via set_env_from
