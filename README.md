# Endpoint State Policy - Contract Library

A library of CTN (Criterion Type Node) contracts for the Endpoint State Policy
(ESP) ecosystem. Each contract defines **what** a CTN type checks, **how** it
collects data, and **how** collected data is validated against state
requirements.

This repo is **contract definitions only**. It does not ship an agent, a
runtime, or a registry. Agents pull these contracts into their own build and
wire them into their strategy registry.

---

## Core Projects

| Project | Description |
|---------|-------------|
| [ESP Core Engine](https://github.com/scanset/Endpoint-State-Policy) | Parses ESP DSL, validates policies, and executes evaluation trees |
| [ESP Agent SDK](https://github.com/scanset/ESP-Agent-SDK) | Agent-side execution, collector/executor registration, result packaging |

---

## Library Layout

Contracts are organized by **platform**. Each contract folder is a
self-contained Rust module plus a reference doc:

```
Contract-Library/
  Apache/          # Apache HTTP Server compliance contracts
  AWS/             # AWS API compliance contracts
  Azure/           # Azure API compliance contracts
  Kubernetes/      # Kubernetes cluster compliance contracts
  Network/         # Network probe contracts (TLS, HTTP)
  PostgreSQL/      # Database compliance contracts
  RHEL9/           # Linux host compliance contracts
```

Each contract directory contains:

```
<contract_name>/
  <contract_name>_contract.rs    # CTN type, object/state fields, field mappings
  <contract_name>_collector.rs   # Data collection implementation
  <contract_name>_executor.rs    # Validation against collected data
  <contract_name>_command.rs     # (optional) Command executor factory
  <contract_name>.md             # Reference doc, ESP examples, STIG coverage
```

The `.md` file is the source of truth for consumers - it documents object
fields, state fields, commands executed, sample output, and ESP usage.

---

## Platform Coverage

### Apache

Contracts for Apache HTTP Server 2.4 compliance scanning, backing the DISA
Apache Server and Site STIGs.

| Contract | Purpose |
|----------|---------|
| `apache_module` | Check loaded Apache modules via `httpd -M` |

Used with `file_content` and `file_metadata` from RHEL9 for config and
permission checks on httpd.conf and related files.

### AWS

Contracts for AWS resource compliance, backing FedRAMP and KSI controls. All
contracts use a dedicated `AwsClient` (Pattern C - API-based collection).

| Category | Contracts |
|----------|-----------|
| Backup & DR | `aws_backup_plan`, `aws_backup_vault` |
| Monitoring & Logging | `aws_cloudtrail`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_log_group`, `aws_cloudwatch_metric_alarm`, `aws_cloudwatch_metric_filter`, `aws_config_recorder`, `aws_config_rule`, `aws_flow_log` |
| Compute & Network | `aws_ec2_instance`, `aws_ebs_volume`, `aws_internet_gateway`, `aws_nat_gateway`, `aws_network_acl`, `aws_route_table`, `aws_security_group`, `aws_subnet`, `aws_vpc`, `aws_vpc_endpoint` |
| Database | `aws_rds_instance` |
| Container | `aws_ecr_repository`, `aws_eks_cluster` |
| Security & Compliance | `aws_guardduty_detector`, `aws_inspector2_account`, `aws_macie2_account`, `aws_securityhub_account` |
| Identity & Access | `aws_iam_role`, `aws_iam_user`, `aws_identitystore_group`, `aws_ssoadmin_permission` |
| Secrets & Keys | `aws_kms_key`, `aws_secretsmanager_secret` |
| Storage | `aws_s3_bucket` |
| Systems Management | `aws_ssm_maintenance_window` |

### Azure

Contracts for Azure resource compliance via the Azure CLI (`AzClient`).

| Contract | Purpose |
|----------|---------|
| `az_entra_application` | Entra ID application registrations |
| `az_entra_group` | Entra security groups |
| `az_entra_service_principal` | Service principals |
| `az_role_assignment` | RBAC role assignments |

### Kubernetes

Contracts for Kubernetes cluster compliance scanning, backing the DISA
Kubernetes STIG. Uses `kubectl get -o json` for API-based resource queries
with RecordData support for field-level validation of pod specs and configs.

| Contract | Purpose |
|----------|---------|
| `k8s_resource` | Query and validate Kubernetes API resources (Pods, Namespaces, Services, Secrets, etc.) via kubectl with record checks on resource specs |

Authentication via `ESP_KUBECONFIG` env var or default `~/.kube/config`.
Supports kind, kubeadm, EKS, AKS, and GKE clusters.

### Network

Cross-platform network probe contracts for validating encryption in transit,
HTTP protocol compliance, and TLS certificate properties. Work against any
TCP service regardless of the underlying application.

| Contract | Purpose |
|----------|---------|
| `tls_probe` | TLS handshake probe via `openssl s_client` - protocol version, cipher suite, certificate inspection, STARTTLS support |
| `http_probe` | HTTP request probe via `curl` - status code, protocol version (HTTP/2), response headers, redirect detection |

These are horizontal contracts that cut across all benchmarks - any STIG with
"encryption in transit" controls can use `tls_probe`, and any web-related
benchmark can use `http_probe`.

### PostgreSQL

Custom contracts for PostgreSQL 16 compliance scanning. Authenticate via
pg_hba.conf peer auth or `ESP_PG_PASS` env var injection.

| Contract | Purpose |
|----------|---------|
| `pg_config_param` | Validate PostgreSQL runtime parameters via `SHOW` |
| `pg_catalog_query` | Query system catalogs (pg_roles, pg_shadow, pg_extension, etc.) via a predefined query library |
| `openssl_cert` | Inspect X.509 certificates (subject, issuer, dates, CN, self-signed detection) |

### RHEL9 / Rocky Linux 9

Linux host compliance contracts backing the DISA RHEL 9 STIG.

| Contract | Purpose |
|----------|---------|
| `sysctl_parameter` | Kernel parameters via `sysctl -n` |
| `systemd_service` | Service state via `systemctl show` |
| `rpm_package` | Package installation and version via `rpm -q` |
| `os_release` | OS identity and version from `/etc/os-release` |
| `fips` | FIPS 140 status via `fips-mode-setup` and `/proc/sys/crypto/fips_enabled` |
| `crypto_policy` | System-wide crypto policy via `update-crypto-policies` |
| `grub_config` | Bootloader configuration parsing |
| `mount_point` | Mount state and hardening options via `findmnt -J` |
| `firewalld_rule` | Firewalld zone configuration via `firewall-cmd` |
| `filesystem_scan` | Filesystem-wide scans (world-writable, SUID/SGID, orphaned files) via `find` |
| `dconf_setting` | GNOME desktop settings via `gsettings get` (N/A-aware for headless servers) |
| `file_system` | File metadata (permissions, ownership) and file content checks |
| `tcp_listener` | TCP listener inspection via `/proc/net/tcp` |
| `json` | Structured JSON file validation via record checks |
| `computed_value` | Derived values for cross-CTN assertions |

---

## Consuming Contracts

Agents consume this library by copying (or vendoring) the contract files into
their own `contract_kit/` module and registering the resulting
collector/executor pairs with a `CtnStrategyRegistry`.

Each contract's `.rs` file begins with a comment block describing the
`mod.rs` additions required to hook it into an agent build. See the
[ESP Agent SDK](https://github.com/scanset/ESP-Agent-SDK) for full wiring
examples and the registered-strategy pattern.

---

## Authoring New Contracts

See the [Contract Development Guide](https://github.com/scanset/ESP-Agent-SDK/blob/main/guides/Contract_Development_Guide.md)
in the ESP Agent SDK for the full workflow, templates, and patterns.

---

## Status

| Component | Status |
|-----------|--------|
| ESP DSL | v1.0.0 |
| Contract model | Stable |
| Apache contracts | Stable |
| AWS contracts | Stable |
| Azure contracts | Stable |
| Kubernetes contracts | Stable |
| Network contracts | Stable |
| PostgreSQL contracts | Stable |
| RHEL9 contracts | Stable |
