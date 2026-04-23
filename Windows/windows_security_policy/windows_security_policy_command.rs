// === secedit.rs ===

//! secedit.exe helpers (Windows Security Policy / User Rights export)
//!
//! `secedit` can only export to a file, so we wrap its invocation in a
//! PowerShell one-liner that writes to a temp file, reads it back, and
//! cleans up. The resulting INF is an INI-like format with two sections
//! we care about:
//!
//! ```ini
//! [System Access]
//! MinimumPasswordAge = 1
//! EnableGuestAccount = 0
//!
//! [Privilege Rights]
//! SeTrustedCredManAccessPrivilege =
//! SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
//! ```
//!
//! The collector dispatches this via the already-whitelisted PowerShell
//! executor — no separate `secedit` binary whitelist is required, since
//! `secedit` is only ever invoked inside the PowerShell string.

use std::collections::HashMap;

/// Build the PowerShell `-Command` string that exports SecurityPolicy and
/// User_Rights areas to a temp file, emits the file contents to stdout,
/// then deletes the temp file. Exit code is `secedit`'s own exit code.
pub fn build_secedit_export_command() -> String {
    // One-liner: create temp, export, print, cleanup.
    // `secedit /export` returns 0 on success even when no changes are made.
    // `/quiet` suppresses the "Task is completed successfully" banner.
    "$tmp = \"$env:TEMP\\esp-secedit-$([guid]::NewGuid().ToString('N')).inf\"; \
     $null = secedit /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet; \
     $rc = $LASTEXITCODE; \
     if (Test-Path $tmp) { Get-Content -LiteralPath $tmp -Raw -Encoding Unicode; \
     Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } \
     exit $rc"
        .to_string()
}

/// Parsed output of a `secedit /export` INF file.
///
/// Keys are the policy names (e.g. `EnableGuestAccount`,
/// `SeNetworkLogonRight`); values are the raw right-hand-side string
/// (trimmed). Missing policies are absent from the map.
#[derive(Debug, Default, Clone)]
pub struct SeceditExport {
    pub system_access: HashMap<String, String>,
    pub privilege_rights: HashMap<String, String>,
    pub kerberos_policy: HashMap<String, String>,
}

impl SeceditExport {
    /// Look up a policy value across all sections. Returns `None` if the
    /// policy name isn't present.
    pub fn get(&self, policy_name: &str) -> Option<&str> {
        self.system_access
            .get(policy_name)
            .or_else(|| self.privilege_rights.get(policy_name))
            .or_else(|| self.kerberos_policy.get(policy_name))
            .map(|s| s.as_str())
    }

    /// True if the policy name exists in any section.
    pub fn contains(&self, policy_name: &str) -> bool {
        self.system_access.contains_key(policy_name)
            || self.privilege_rights.contains_key(policy_name)
            || self.kerberos_policy.contains_key(policy_name)
    }
}

/// Parse a secedit INF export into per-section maps.
///
/// Accepts `[System Access]`, `[Privilege Rights]`, and `[Kerberos Policy]`
/// headers. Blank lines, comments (leading `;`), and unrecognized sections
/// are ignored. RHS values are trimmed. Empty RHS (e.g.
/// `SeTrustedCredManAccessPrivilege =`) is preserved as the empty string,
/// which semantically means "no accounts are granted this right".
pub fn parse_secedit_export(text: &str) -> SeceditExport {
    let mut out = SeceditExport::default();
    let mut section: Option<&str> = None;

    // secedit writes UTF-16 LE with BOM; Get-Content -Encoding Unicode
    // returns a decoded String. We may still see a leading BOM char
    // (U+FEFF) on some agents — strip it so the first section header
    // parses cleanly.
    let text = text.trim_start_matches('\u{feff}');

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = match name {
                "System Access" => Some("system_access"),
                "Privilege Rights" => Some("privilege_rights"),
                "Kerberos Policy" => Some("kerberos_policy"),
                _ => None,
            };
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_string();
        let value = value.trim().to_string();

        match section {
            Some("system_access") => {
                out.system_access.insert(key, value);
            }
            Some("privilege_rights") => {
                out.privilege_rights.insert(key, value);
            }
            Some("kerberos_policy") => {
                out.kerberos_policy.insert(key, value);
            }
            _ => {}
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_export() {
        let inf = "\
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
EnableGuestAccount = 0
[Privilege Rights]
SeTrustedCredManAccessPrivilege =
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
[Version]
signature=\"$CHICAGO$\"
";
        let p = parse_secedit_export(inf);
        assert_eq!(p.get("MinimumPasswordAge"), Some("1"));
        assert_eq!(p.get("EnableGuestAccount"), Some("0"));
        assert_eq!(p.get("SeTrustedCredManAccessPrivilege"), Some(""));
        assert_eq!(
            p.get("SeNetworkLogonRight"),
            Some("*S-1-5-32-544,*S-1-5-32-545")
        );
        assert!(p.get("NotInExport").is_none());
    }

    #[test]
    fn parses_kerberos_policy() {
        let inf = "\
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
";
        let p = parse_secedit_export(inf);
        assert_eq!(p.get("MaxTicketAge"), Some("10"));
        assert_eq!(p.get("MaxRenewAge"), Some("7"));
        assert_eq!(p.get("MaxServiceAge"), Some("600"));
        assert_eq!(p.get("MaxClockSkew"), Some("5"));
        assert_eq!(p.get("TicketValidateClient"), Some("1"));
        assert!(p.contains("MaxTicketAge"));
    }

    #[test]
    fn strips_bom_and_comments() {
        let inf = "\u{feff}; header comment\n[System Access]\nLockoutBadCount = 3\n";
        let p = parse_secedit_export(inf);
        assert_eq!(p.get("LockoutBadCount"), Some("3"));
    }
}

// === powershell.rs ===

//! PowerShell command executor (Windows Registry + Service queries)
//!
//! Channel-aware whitelisted executor for `powershell.exe`.

use base64::prelude::*;
use execution_engine::strategies::channel::SharedChannel;
use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for PowerShell execution (30 seconds)
const DEFAULT_POWERSHELL_TIMEOUT_SECS: u64 = 30;

/// Whitelisted PowerShell binary paths (Windows PowerShell 5.1, always present)
pub const POWERSHELL_PATHS: &[&str] = &[
    "powershell",
    "powershell.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
];

/// Create a command executor configured for PowerShell over `channel`.
pub fn create_powershell_executor(channel: SharedChannel) -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::from_channel_with_timeout(
        channel,
        Duration::from_secs(DEFAULT_POWERSHELL_TIMEOUT_SECS),
    );
    executor.allow_commands(POWERSHELL_PATHS);
    executor
}

/// Encode a PowerShell script body for `-EncodedCommand`.
///
/// PowerShell's `-EncodedCommand` takes a Base64-encoded UTF-16LE string.
/// Using this instead of `-Command <raw body>` means cmd.exe (or CreateProcessW)
/// never sees the pipe characters, curly braces, or semicolons in the script —
/// the encoded token is plain alphanumeric + `=` padding with no shell
/// metacharacters.
pub fn encode_ps_command(ps_body: &str) -> String {
    let utf16: Vec<u8> = ps_body
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    BASE64_STANDARD.encode(&utf16)
}

/// Build PowerShell arguments for Get-ItemPropertyValue.
pub fn build_registry_value_args(hive: &str, key: &str, name: &str) -> Vec<String> {
    let ps_hive = normalize_hive_for_powershell(hive);

    let command = format!(
        "Get-ItemPropertyValue -Path '{}:\\{}' -Name '{}'",
        ps_hive, key, name
    );

    vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-EncodedCommand".to_string(),
        encode_ps_command(&command),
    ]
}

/// Normalize registry hive name to PowerShell drive format.
pub fn normalize_hive_for_powershell(hive: &str) -> &'static str {
    match hive.to_uppercase().as_str() {
        "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
        "HKEY_CURRENT_USER" | "HKCU" => "HKCU",
        "HKEY_CLASSES_ROOT" | "HKCR" => "HKCR",
        "HKEY_USERS" | "HKU" => "HKU",
        "HKEY_CURRENT_CONFIG" | "HKCC" => "HKCC",
        _ => "HKLM",
    }
}

/// Parse PowerShell Get-ItemPropertyValue output (just trim).
pub fn parse_powershell_output(output: &str) -> String {
    output.trim().to_string()
}
