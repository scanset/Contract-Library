// === get_local_user.rs ===

//! Get-LocalUser / Win32_UserAccount helpers (Windows local user enumeration)
//!
//! Two executor backends:
//!
//! - **powershell** (default): `Get-LocalUser` via PS 5.1. Full fidelity:
//!   exposes date fields (PasswordLastSet, PasswordExpires, LastLogon,
//!   AccountExpires) as /Date(epoch-ms)/ strings, bool policy flags, SID,
//!   description, full name. Missing user raises
//!   `Microsoft.PowerShell.Commands.UserNotFoundException`, which we
//!   catch to emit `[]` → `exists=false`.
//!
//! - **cim**: `Get-CimInstance Win32_UserAccount`. No date fields at all
//!   (PasswordExpires is a bool policy flag here, not a date). Adds
//!   `Lockout` which Get-LocalUser doesn't expose. Missing user returns
//!   empty set, no exception.
//!
//! RID-matching mode (`match_by_rid=true`) treats the `name` object field
//! as a RID suffix ("500", "501", "503") and matches via SID pattern —
//! handles the renamed-Administrator case.
//!
//! Both commands run through the whitelisted PowerShell executor; no
//! separate binary allowlist is needed.

use serde::Deserialize;

/// Maximum length of a user name we'll embed in a PS command string.
/// Long enough for any real Windows account (MAX_USER_NAME = 20 chars +
/// renames usually stay short), strict enough to reject obviously crafted
/// input.
const MAX_NAME_LEN: usize = 64;

/// Validate a user name or RID suffix before string-interpolation into a
/// PowerShell `-Command` body. Windows SAM account names permit letters,
/// digits, and the printable set `. _ - $`; we also allow unicode word
/// chars for non-ASCII locales. Rejects anything containing characters
/// that have meaning to PowerShell's parser.
pub fn is_safe_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    name.chars().all(|c| {
        c.is_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '$'
    })
}

/// Build the PowerShell `-Command` body for the `powershell` executor.
///
/// When `match_by_rid` is true, `name` is treated as a RID suffix and
/// matched by SID. When false, it's an exact account-name match.
///
/// The output is always a JSON **array** (zero or more users) — we force
/// array wrapping in the PS pipeline so the Rust parser sees a uniform
/// shape.
pub fn build_get_localuser_command(name: &str, match_by_rid: bool) -> String {
    // Caller must have validated `name` with `is_safe_identifier` first.
    let selector = if match_by_rid {
        format!(
            "$u = Get-LocalUser | Where-Object {{ $_.SID.Value -like 'S-1-5-21-*-{}' }}",
            name
        )
    } else {
        format!(
            "try {{ $u = Get-LocalUser -Name '{}' -ErrorAction Stop }} \
             catch [Microsoft.PowerShell.Commands.UserNotFoundException] {{ $u = @() }}",
            name
        )
    };

    // `@($u)` forces a single-element result to an array; `-Compress`
    // keeps the output on one line for easier line-based logging.
    format!(
        "{}; \
         $proj = @($u) | Select-Object Name,Enabled,PasswordRequired,UserMayChangePassword,\
         PasswordLastSet,PasswordExpires,LastLogon,AccountExpires,Description,FullName,\
         @{{N='SID';E={{$_.SID.Value}}}}; \
         if ($proj.Count -eq 0) {{ Write-Output '[]' }} \
         else {{ @($proj) | ConvertTo-Json -Depth 3 -Compress }}",
        selector
    )
}

/// Build the PowerShell `-Command` body for the `cim` executor (fallback
/// path, less fidelity — no date fields).
pub fn build_cim_useraccount_command(name: &str, match_by_rid: bool) -> String {
    let filter = if match_by_rid {
        // CIM -Filter's LIKE syntax is unreliable across providers; fetch
        // all local accounts and filter in PS.
        format!(
            "$u = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=TRUE' | \
             Where-Object {{ $_.SID -like 'S-1-5-21-*-{}' }}",
            name
        )
    } else {
        format!(
            "$u = Get-CimInstance -ClassName Win32_UserAccount \
             -Filter \"LocalAccount=TRUE AND Name='{}'\"",
            name
        )
    };

    format!(
        "{}; \
         $proj = @($u) | Select-Object Name,Disabled,PasswordRequired,PasswordChangeable,\
         PasswordExpires,SID,Description,FullName,Lockout; \
         if ($proj.Count -eq 0) {{ Write-Output '[]' }} \
         else {{ @($proj) | ConvertTo-Json -Depth 3 -Compress }}",
        filter
    )
}

/// Raw Get-LocalUser JSON row. Date fields arrive as `/Date(ms)/` strings
/// or `null`; bools are clean. SID is pre-flattened to a string by the
/// Select-Object projection.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawLocalUser {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "PasswordRequired")]
    pub password_required: Option<bool>,
    #[serde(rename = "UserMayChangePassword")]
    pub user_may_change_password: Option<bool>,
    #[serde(rename = "PasswordLastSet")]
    pub password_last_set: Option<String>,
    #[serde(rename = "PasswordExpires")]
    pub password_expires: Option<String>,
    #[serde(rename = "LastLogon")]
    pub last_logon: Option<String>,
    #[serde(rename = "AccountExpires")]
    pub account_expires: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "FullName")]
    pub full_name: Option<String>,
    #[serde(rename = "SID")]
    pub sid: Option<String>,
}

/// Raw Win32_UserAccount JSON row (CIM fallback).
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawCimUser {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Disabled")]
    pub disabled: Option<bool>,
    #[serde(rename = "PasswordRequired")]
    pub password_required: Option<bool>,
    #[serde(rename = "PasswordChangeable")]
    pub password_changeable: Option<bool>,
    #[serde(rename = "PasswordExpires")]
    pub password_expires: Option<bool>,
    #[serde(rename = "SID")]
    pub sid: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "FullName")]
    pub full_name: Option<String>,
    #[serde(rename = "Lockout")]
    pub lockout: Option<bool>,
}

/// Parse the JSON emitted by `build_get_localuser_command`. Accepts both
/// an object (single user, PS 5.1 unwraps arrays) and an array.
pub fn parse_localuser_json(text: &str) -> Result<Vec<RawLocalUser>, String> {
    parse_json_maybe_array(text)
}

/// Parse the JSON emitted by `build_cim_useraccount_command`.
pub fn parse_cim_json(text: &str) -> Result<Vec<RawCimUser>, String> {
    parse_json_maybe_array(text)
}

fn parse_json_maybe_array<T: for<'de> serde::Deserialize<'de>>(
    text: &str,
) -> Result<Vec<T>, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // Try as array first
    if let Ok(v) = serde_json::from_str::<Vec<T>>(trimmed) {
        return Ok(v);
    }
    // PS 5.1 ConvertTo-Json can wrap array output in an envelope object:
    // `{"value":[...],"Count":N}`. Recognize and unwrap so we don't
    // silently deserialize the envelope as T and get all-None fields.
    #[derive(serde::Deserialize)]
    struct PsArrayEnvelope<T> {
        value: Vec<T>,
    }
    if let Ok(env) = serde_json::from_str::<PsArrayEnvelope<T>>(trimmed) {
        return Ok(env.value);
    }
    // Then as single object
    serde_json::from_str::<T>(trimmed)
        .map(|u| vec![u])
        .map_err(|e| format!("parse_users_json: {}", e))
}

/// Convert a PS 5.1 `/Date(1776750940256)/` string to an epoch-ms i64.
/// Returns None for null, empty, or malformed inputs.
pub fn parse_ps_date(value: &Option<String>) -> Option<i64> {
    let s = value.as_deref()?.trim();
    if s.is_empty() || s == "null" {
        return None;
    }
    // Accept both `/Date(1234)/` and escaped `\/Date(1234)\/` forms.
    let inner = s
        .strip_prefix("\\/Date(")
        .or_else(|| s.strip_prefix("/Date("))?;
    let inner = inner.strip_suffix(")\\/").or_else(|| inner.strip_suffix(")/"))?;
    // Epoch ms may be followed by an offset like `1234+0000` — split.
    let num_part = inner
        .split(|c: char| c == '+' || c == '-')
        .next()
        .unwrap_or(inner);
    num_part.trim().parse::<i64>().ok()
}

/// Days between an epoch-ms instant and `now_ms`, rounding toward zero.
/// Positive = in the past. Negative = in the future.
pub fn days_between(epoch_ms: i64, now_ms: i64) -> i64 {
    const MS_PER_DAY: i64 = 86_400_000;
    (now_ms - epoch_ms) / MS_PER_DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_identifier_accepts_common_names() {
        assert!(is_safe_identifier("azureadmin"));
        assert!(is_safe_identifier("Administrator"));
        assert!(is_safe_identifier("user.name"));
        assert!(is_safe_identifier("svc_account-01"));
        assert!(is_safe_identifier("500")); // RID
        assert!(is_safe_identifier("DOMAIN$")); // machine account
    }

    #[test]
    fn safe_identifier_rejects_injection() {
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier("a'; rm -rf /"));
        assert!(!is_safe_identifier("a`b"));
        assert!(!is_safe_identifier("a;b"));
        assert!(!is_safe_identifier("a$(whoami)"));
        assert!(!is_safe_identifier("a b"));
        assert!(!is_safe_identifier(&"x".repeat(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn parses_default_getlocaluser_json() {
        let json = r#"[
            {"Name":"azureadmin","Enabled":true,"PasswordRequired":true,
             "UserMayChangePassword":true,
             "PasswordLastSet":"\/Date(1776750940256)\/",
             "PasswordExpires":"\/Date(1780379740256)\/",
             "LastLogon":"\/Date(1776781564175)\/",
             "AccountExpires":null,
             "Description":"Built-in account for administering the computer/domain",
             "FullName":"","SID":"S-1-5-21-3719225790-1524408702-1566890666-500"}
        ]"#;
        let users = parse_localuser_json(json).expect("parse");
        assert_eq!(users.len(), 1);
        let u = &users[0];
        assert_eq!(u.name, "azureadmin");
        assert_eq!(u.enabled, Some(true));
        assert_eq!(u.password_required, Some(true));
        assert_eq!(
            u.sid.as_deref(),
            Some("S-1-5-21-3719225790-1524408702-1566890666-500")
        );
        assert_eq!(
            parse_ps_date(&u.password_last_set),
            Some(1776750940256)
        );
        assert_eq!(parse_ps_date(&u.account_expires), None);
    }

    #[test]
    fn parses_single_object_form() {
        // PS 5.1 sometimes unwraps single-element arrays to an object.
        let json = r#"{"Name":"Guest","Enabled":false,"PasswordRequired":false,
                       "UserMayChangePassword":false,"PasswordLastSet":null,
                       "SID":"S-1-5-21-X-501"}"#;
        let users = parse_localuser_json(json).expect("parse");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "Guest");
        assert_eq!(users[0].enabled, Some(false));
        assert_eq!(parse_ps_date(&users[0].password_last_set), None);
    }

    #[test]
    fn parses_empty_array() {
        let users = parse_localuser_json("[]").expect("parse");
        assert!(users.is_empty());
    }

    #[test]
    fn parses_cim_json() {
        let json = r#"[
            {"Name":"azureadmin","Disabled":false,"PasswordRequired":true,
             "PasswordChangeable":true,"PasswordExpires":true,
             "SID":"S-1-5-21-X-500","Description":"built-in","FullName":"",
             "Lockout":false}
        ]"#;
        let users = parse_cim_json(json).expect("parse");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].disabled, Some(false));
        assert_eq!(users[0].lockout, Some(false));
        assert_eq!(users[0].password_expires, Some(true));
    }

    #[test]
    fn ps_date_handles_variant_encodings() {
        // Unescaped forward slashes
        assert_eq!(
            parse_ps_date(&Some("/Date(1700000000000)/".into())),
            Some(1700000000000)
        );
        // Escaped forward slashes (as JSON-decoded)
        assert_eq!(
            parse_ps_date(&Some("\\/Date(1700000000000)\\/".into())),
            Some(1700000000000)
        );
        // With trailing timezone offset
        assert_eq!(
            parse_ps_date(&Some("/Date(1700000000000+0000)/".into())),
            Some(1700000000000)
        );
        // Null-ish inputs
        assert_eq!(parse_ps_date(&None), None);
        assert_eq!(parse_ps_date(&Some(String::new())), None);
        assert_eq!(parse_ps_date(&Some("garbage".into())), None);
    }

    #[test]
    fn command_builders_emit_expected_patterns() {
        let ps = build_get_localuser_command("azureadmin", false);
        assert!(ps.contains("Get-LocalUser -Name 'azureadmin'"));
        assert!(ps.contains("UserNotFoundException"));
        assert!(ps.contains("ConvertTo-Json"));

        let rid = build_get_localuser_command("500", true);
        assert!(rid.contains("SID.Value -like 'S-1-5-21-*-500'"));

        let cim = build_cim_useraccount_command("azureadmin", false);
        assert!(cim.contains("Win32_UserAccount"));
        assert!(cim.contains("Name='azureadmin'"));

        let cim_rid = build_cim_useraccount_command("500", true);
        assert!(cim_rid.contains("SID -like 'S-1-5-21-*-500'"));
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
