# Endpoint State Policy - Contract Library

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A library of CTN (Criterion Type Node) contracts for the Endpoint State Policy
(ESP) ecosystem. Each contract defines **what** a CTN type checks, **how** it
collects data, and **how** collected data is validated against state
requirements.

This repo is **contract definitions only**. It does not ship an agent, a
runtime, or a registry. Agents pull these contracts into their own build and
wire them into their strategy registry.

> **Engine compatibility:** This snapshot targets ESP engine **v2.2.3**.
> Cut a tag of this repo alongside engine releases — the contracts and the
> engine evolve together.

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
  M365/            # Microsoft 365 / Entra ID / Purview / Intune contracts
  Network/         # Network probe contracts (TLS, HTTP)
  PostgreSQL/      # Database compliance contracts
  RHEL9/           # Linux host compliance contracts
  Windows/         # Windows host compliance contracts
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

The `.md` file is the source of truth for consumers — it documents object
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
collectors run against a customer-side AWS CLI / SDK install with the
caller's credentials — there is no remote transport.

| Category | Contracts |
|----------|-----------|
| Backup & DR | `aws_backup_plan`, `aws_backup_vault` |
| Monitoring & Logging | `aws_cloudtrail`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_log_group`, `aws_cloudwatch_metric_alarm`, `aws_cloudwatch_metric_filter`, `aws_config_recorder`, `aws_config_rule`, `aws_flow_log` |
| Compute & Network | `aws_ec2_instance`, `aws_ec2_describe_instances`, `aws_ec2_describe_images`, `aws_ebs_volume`, `aws_internet_gateway`, `aws_nat_gateway`, `aws_network_acl`, `aws_route_table`, `aws_security_group`, `aws_subnet`, `aws_vpc`, `aws_vpc_endpoint` |
| Database | `aws_rds_instance` |
| Container | `aws_ecr_repository`, `aws_eks_cluster` |
| Security & Compliance | `aws_guardduty_detector`, `aws_inspector2_account`, `aws_macie2_account`, `aws_securityhub_account` |
| Identity & Access | `aws_iam_role`, `aws_iam_user`, `aws_identitystore_group`, `aws_ssoadmin_permission` |
| Secrets & Keys | `aws_kms_key`, `aws_secretsmanager_secret` |
| Storage | `aws_s3_bucket` |
| Systems Management | `aws_ssm_maintenance_window` |
| Discovery primitives | `aws_resource_explorer_query` (bulk Search across services), `aws_ec2_describe_images`, `aws_ec2_describe_instances` (per-resource enrichment) |

### Azure

Contracts for Azure resource compliance via the Azure CLI (`az`). All
collectors authenticate with the caller's `az login` context or a
service-principal credential set in environment variables.

| Category | Contracts |
|----------|-----------|
| Identity & directory | `az_entra_application`, `az_entra_group`, `az_entra_service_principal`, `az_role_assignment`, `az_role_assignment_list` |
| Compute & networking | `az_virtual_machine`, `az_virtual_network`, `az_subnet_list`, `az_vnet_peering_list`, `az_nsg`, `az_nsg_rule_list`, `az_load_balancer`, `az_application_gateway`, `az_public_ip`, `az_nat_gateway`, `az_bastion_host` |
| Storage & data | `az_storage_account`, `az_managed_disk`, `az_disk_encryption_set`, `az_recovery_services_vault`, `az_key_vault` |
| Security & governance | `az_defender_pricing`, `az_auto_provisioning`, `az_security_contact`, `az_policy_assignment`, `az_policy_assignment_list`, `az_policy_compliance_state`, `az_diagnostic_setting`, `az_diagnostic_setting_list`, `az_activity_log_alert`, `az_log_analytics_workspace` |
| Discovery primitives | `az_resource_graph_query` (KQL across all resources — preferred), `az_resource_list`, `az_resource_group`, `az_resource_group_list` |

### Kubernetes

Contracts for Kubernetes cluster compliance scanning, backing the DISA
Kubernetes STIG. Uses `kubectl get -o json` for API-based resource queries
with RecordData support for field-level validation of pod specs and configs.

| Contract | Purpose |
|----------|---------|
| `k8s_resource` | Query and validate Kubernetes API resources (Pods, Namespaces, Services, Secrets, etc.) via kubectl with record checks on resource specs |

Authentication via `ESP_KUBECONFIG` env var or default `~/.kube/config`.
Supports kind, kubeadm, EKS, AKS, and GKE clusters.

### M365

Contracts for Microsoft 365 / Entra ID / Purview / Intune compliance,
backing CMMC and FedRAMP M365 controls. Two dispatch shapes:

- **`m365_graph_query`** — single CTN that issues `GET` against an arbitrary
  Microsoft Graph collection path. One CTN covers every Graph resource type;
  the caller's discovery layer adds new resource types as new path entries,
  not as new CTNs.
- **`m365_pwsh_cmdlet`** — wraps `Connect-IPPSSession`-backed PowerShell
  cmdlets (DLP policies, audit log search, mailbox audit, retention) for
  surfaces Graph doesn't expose.

Authentication via Entra ID app registration (client credentials with admin
consent) configured through environment variables.

| Category | Contracts |
|----------|-----------|
| Generic primitives | `m365_graph_query`, `m365_pwsh_cmdlet` |
| Identity & directory | `m365_user`, `m365_group`, `m365_directory_role`, `m365_role_assignment`, `m365_pim_role_eligibility`, `m365_service_principal`, `m365_app_registration` |
| Devices | `m365_device`, `m365_managed_device`, `m365_device_category`, `m365_device_configuration` |
| Conditional access | `m365_conditional_access_policy`, `m365_authentication_context` |
| Compliance & retention | `m365_compliance_policy`, `m365_retention_label`, `m365_retention_event`, `m365_retention_event_type`, `m365_sensitivity_label`, `m365_app_protection_policy`, `m365_audit_log_query`, `m365_ediscovery_case` |
| Collaboration | `m365_team`, `m365_sharepoint_site` |
| Credentials & recovery | `m365_bitlocker_recovery_key`, `m365_laps_credential` |

### Network

Cross-platform network probe contracts for validating encryption in transit,
HTTP protocol compliance, and TLS certificate properties. Work against any
TCP service regardless of the underlying application.

| Contract | Purpose |
|----------|---------|
| `tls_probe` | TLS handshake probe via `openssl s_client` — protocol version, cipher suite, certificate inspection, STARTTLS support |
| `http_probe` | HTTP request probe via `curl` — status code, protocol version (HTTP/2), response headers, redirect detection |

These are horizontal contracts that cut across all benchmarks — any STIG with
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
| `fips_crypto` | FIPS 140 status via `fips-mode-setup` and `/proc/sys/crypto/fips_enabled`, plus the system-wide crypto policy via `update-crypto-policies` |
| `grub_config` | Bootloader configuration parsing |
| `mount_point` | Mount state and hardening options via `findmnt -J` |
| `firewalld_rule` | Firewalld zone configuration via `firewall-cmd` |
| `linux_filesystem` | File metadata (permissions, ownership) and file content checks |
| `linux_filesystem_scan` | Filesystem-wide scans (world-writable, SUID/SGID, orphaned files) via `find` |
| `linux_tcp_listener` | TCP listener inspection via `/proc/net/tcp` |
| `dconf_setting` | GNOME desktop settings via `gsettings get` (N/A-aware for headless servers) |
| `json` | Structured JSON file validation via record checks |
| `computed_value` / `computed_values` | Derived values for cross-CTN assertions (`computed_value` singular = single derived field; `computed_values` plural = composite record) |
| `file_system` | Legacy file-system reference set retained for older agents — new code should use `linux_filesystem` and `linux_filesystem_scan` |

### Windows

Windows Server 2022 host compliance contracts, backing the DISA Windows
Server STIG. Each folder ships the full contract / collector / executor /
command quartet — drop them into a scanner running on a Windows host (or
into any scanner you've given a Windows-capable execution context) and
register the strategies with your `CtnStrategyRegistry`.

The Agent SDK's default `cargo build` produces a Linux-host scanner with a
local-only execution context, so Windows CTNs aren't wired into that
registry by default. To run Windows policies, either build the scanner on
Windows or supply your own Windows-friendly executor environment when you
construct the registry.

| Contract | Purpose |
|----------|---------|
| `registry` | Registry value inspection |
| `registry_subkeys` | Registry subkey enumeration |
| `windows_registry_acl` | Registry key ACLs |
| `windows_audit_policy` | Audit policy via `auditpol` |
| `windows_security_policy` | Security policy via `secedit` |
| `windows_local_user`, `windows_local_group` | Local user/group state |
| `windows_service` | Service state |
| `windows_scheduled_task` | Scheduled task definition / state |
| `windows_firewall_profile`, `windows_firewall_rule` | Firewall configuration |
| `windows_feature` | Windows feature install state |
| `windows_hotfix` | Installed hotfixes |
| `windows_file_metadata`, `windows_file_acl` | File metadata + ACLs |

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
| ESP engine target | v2.2.3 |
| Envelope / canonical output schema | v2.1.1 |
| ESP DSL grammar (`dsl_schema_version`) | v1.0.0 |
| Contract model | Stable |
| Apache contracts | Stable |
| AWS contracts | Stable |
| Azure contracts | Stable |
| Kubernetes contracts | Stable |
| M365 contracts | Stable |
| Network contracts | Stable |
| PostgreSQL contracts | Stable |
| RHEL9 contracts | Stable |
| Windows contracts | Stable (requires Windows-host scanner build) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
