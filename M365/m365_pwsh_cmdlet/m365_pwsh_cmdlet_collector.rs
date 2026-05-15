//! Microsoft compliance PowerShell collector — cert-based app-only auth.
//!
//! Sibling of `m365_graph_query`. Where Graph reaches the bulk of M365
//! via HTTP, the compliance / records-management / DLP surface is
//! gated behind PowerShell (`Connect-IPPSSession` /
//! `Connect-ExchangeOnline`) for app-only callers. This collector
//! shells out to a local `pwsh` runtime to run a cmdlet, authenticated
//! via X.509 certificate that the SPN has uploaded as a keyCredential.
//!
//! ## Auth
//!
//! Reads the following env vars (set by `inventory::resolver::build_env`
//! for any `azure_spn_cert` credential):
//!
//! - `M365_PWSH_TENANT_ID`    — Entra tenant id
//! - `M365_PWSH_CLIENT_ID`    — app registration client id
//! - `M365_PWSH_PFX_PATH`     — absolute path to a PFX bundle holding
//!                              both halves of the cert pair
//! - `M365_PWSH_PFX_PASSWORD` — optional; empty for TF-generated certs
//!
//! ## Inputs (from the OBJECT block)
//!
//! - `cmdlet`       — PowerShell cmdlet name (e.g. `Get-DlpCompliancePolicy`)
//! - `organization` — tenant primary domain (e.g. `scanset.io`)
//! - `filter`       — optional cmdlet `-Filter` argument
//!
//! ## Outputs (in CollectedData) — same shape as m365_graph_query
//!
//! - `found`     — boolean, true on successful cmdlet execution
//! - `row_count` — integer
//! - `rows`      — `RecordData` array of objects from the cmdlet's
//!                 ConvertTo-Json output

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use std::process::Command;
use std::time::Instant;

/// Default cmdlet execution timeout. Connect + cmdlet + Disconnect
/// typically completes in 5-10s; we set 60s to absorb network slow-downs
/// and tenant-side throttling without false-positive timeouts.
const PWSH_TIMEOUT_SECS: u32 = 60;

#[derive(Clone)]
pub struct M365PwshCmdletCollector {
    id: String,
    _executor: SystemCommandExecutor,
}

impl M365PwshCmdletCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            _executor: executor,
        }
    }

    fn extract_string_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    fn auth_from_env() -> Result<(String, String, String, String), String> {
        let tenant_id = std::env::var("M365_PWSH_TENANT_ID")
            .map_err(|_| "M365_PWSH_TENANT_ID not set".to_string())?;
        let client_id = std::env::var("M365_PWSH_CLIENT_ID")
            .map_err(|_| "M365_PWSH_CLIENT_ID not set".to_string())?;
        let pfx_path = std::env::var("M365_PWSH_PFX_PATH")
            .map_err(|_| "M365_PWSH_PFX_PATH not set".to_string())?;
        // Password is optional — TF-generated certs use empty password,
        // operator-supplied certs may set one. Default to empty.
        let pfx_password =
            std::env::var("M365_PWSH_PFX_PASSWORD").unwrap_or_default();

        if tenant_id.is_empty() || client_id.is_empty() || pfx_path.is_empty() {
            return Err(
                "M365_PWSH_TENANT_ID / CLIENT_ID / PFX_PATH must all be non-empty"
                    .to_string(),
            );
        }
        Ok((tenant_id, client_id, pfx_path, pfx_password))
    }

    /// Build the pwsh -Command payload that:
    ///   1. Loads the PFX into an X509Certificate2
    ///   2. Connects to IPPSSession with cert-based app-only auth
    ///   3. Runs the cmdlet (with optional -Filter), forces array shape
    ///   4. Emits the result as JSON on stdout
    ///   5. Disconnects in finally{} so the session is closed even on error
    ///
    /// Quoting: cmdlet name is interpolated as a bareword. The cmdlet
    /// MUST be a Get-* with no positional args; filter is shell-escaped.
    /// We deliberately don't accept arbitrary cmdlet bodies — only a
    /// cmdlet name + optional filter — to prevent OBJECT-field injection
    /// from turning into an RCE primitive.
    fn build_pwsh_script(
        cmdlet: &str,
        organization: &str,
        filter: Option<&str>,
        client_id: &str,
        pfx_path: &str,
        pfx_password: &str,
    ) -> String {
        // Sanity guard: cmdlet name should be alphanumeric + dash only.
        // Caller's responsibility to validate before we get here, but
        // we double-check.
        let cmdlet_safe: String = cmdlet
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();

        // PowerShell-escape single quotes in caller-provided strings.
        // Double-quote interpolation isn't used (no $-expansion needed),
        // so single-quoted strings + doubled-single-quote escape is safe.
        let esc = |s: &str| s.replace('\'', "''");

        let filter_block = match filter {
            Some(f) if !f.is_empty() => format!(" -Filter '{}'", esc(f)),
            _ => String::new(),
        };

        format!(
            r#"
$ErrorActionPreference = 'Stop'
$InformationPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

try {{
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('{pfx_path}', '{pfx_password}')
    Connect-IPPSSession -AppId '{client_id}' -Certificate $cert -Organization '{organization}' -ShowBanner:$false 6>$null

    # Force array via @() — single-row results otherwise come back as
    # a scalar object, which ConvertTo-Json renders as an object (not
    # an array), breaking the downstream "rows[]" expectation.
    $rows = @({cmdlet_safe}{filter_block})

    # ConvertTo-Json on empty array emits `[]`; on single object emits
    # `{{...}}` (not wrapped); on array of >=2 emits `[{{...}}, ...]`.
    # The @() above forces array shape so we always get `[...]`.
    if ($rows.Count -eq 0) {{ '[]' }} else {{ $rows | ConvertTo-Json -Depth 12 -EnumsAsStrings -Compress }}
}} finally {{
    Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore 6>$null | Out-Null
}}
"#,
            pfx_path = esc(pfx_path),
            pfx_password = esc(pfx_password),
            client_id = esc(client_id),
            organization = esc(organization),
            cmdlet_safe = cmdlet_safe,
            filter_block = filter_block,
        )
    }

    fn run_pwsh(&self, script: &str) -> Result<Vec<serde_json::Value>, String> {
        let started = Instant::now();
        let output = Command::new("pwsh")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(script)
            .output()
            .map_err(|e| format!("pwsh spawn failed: {e}"))?;

        let elapsed_ms = started.elapsed().as_millis();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!(
                "pwsh exited {} (elapsed {}ms)\nstderr:\n{}\nstdout (tail):\n{}",
                output.status,
                elapsed_ms,
                stderr.trim(),
                // Truncate stdout to last ~2KB to keep error messages bounded
                stdout
                    .chars()
                    .rev()
                    .take(2048)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        // Empty output → no rows. Defensive fallback if ConvertTo-Json
        // somehow emits whitespace only (shouldn't happen, but…).
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }

        let parsed: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("pwsh stdout is not valid JSON: {e}\nbody:\n{trimmed}"))?;

        match parsed {
            serde_json::Value::Array(rows) => Ok(rows),
            // Defensive: if for any reason a single object snuck through
            // without our @() wrap, accept it as a 1-row result.
            obj @ serde_json::Value::Object(_) => Ok(vec![obj]),
            _ => Err(format!(
                "pwsh output is JSON but not an array/object: {:?}",
                parsed
            )),
        }
    }
}

impl CtnDataCollector for M365PwshCmdletCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let cmdlet = self.extract_string_field(object, "cmdlet").ok_or_else(|| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `cmdlet` (PowerShell cmdlet name)".to_string(),
            }
        })?;
        let organization = self.extract_string_field(object, "organization").ok_or_else(
            || CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `organization` (tenant primary domain)".to_string(),
            },
        )?;
        let filter = self.extract_string_field(object, "filter");

        let (tenant_id, client_id, pfx_path, pfx_password) = Self::auth_from_env().map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: e,
            }
        })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "m365_pwsh_cmdlet".to_string(),
            self.id.clone(),
        );

        let target = format!("pwsh:{}/{}", organization, cmdlet);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::Custom("pwsh".to_string()))
            .description("Microsoft compliance PowerShell cmdlet")
            .target(&target)
            .command(&format!(
                "pwsh -Command \"Connect-IPPSSession + {} + Disconnect\"",
                cmdlet
            ));
        method_builder = method_builder.input("cmdlet", &cmdlet);
        method_builder = method_builder.input("organization", &organization);
        if let Some(ref f) = filter {
            method_builder = method_builder.input("filter", f);
        }
        method_builder = method_builder.input("tenant_id", &tenant_id);
        method_builder = method_builder.input("client_id", &client_id);
        // PFX path is non-secret-but-noisy; tenant + client are the
        // useful provenance values. Skip pfx_path + pfx_password.
        method_builder = method_builder.input("timeout_secs", &PWSH_TIMEOUT_SECS.to_string());
        data.set_method(method_builder.build());

        let script = Self::build_pwsh_script(
            &cmdlet,
            &organization,
            filter.as_deref(),
            &client_id,
            &pfx_path,
            &pfx_password,
        );

        let rows = self.run_pwsh(&script).map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("cmdlet '{}' failed: {}", cmdlet, e),
            }
        })?;

        let row_count = rows.len() as i64;
        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("row_count".to_string(), ResolvedValue::Integer(row_count));
        let rows_record = RecordData::from_json_value(serde_json::Value::Array(rows));
        data.add_field(
            "rows".to_string(),
            ResolvedValue::RecordData(Box::new(rows_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["m365_pwsh_cmdlet".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "m365_pwsh_cmdlet" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "M365PwshCmdletCollector handles only `m365_pwsh_cmdlet`, got `{}`",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }
}
