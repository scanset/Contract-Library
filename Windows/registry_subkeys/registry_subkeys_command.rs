// === reg.rs ===

//! reg.exe command executor (Windows Registry queries)
//!
//! Channel-aware whitelisted executor for `reg.exe` so registry collectors
//! work against any `SharedChannel` (local, SSH, Bastion, ...).

use execution_engine::strategies::channel::SharedChannel;
use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for reg.exe execution (30 seconds)
const DEFAULT_REG_TIMEOUT_SECS: u64 = 30;

/// Whitelisted reg.exe binary paths
pub const REG_PATHS: &[&str] = &["reg", "reg.exe", "C:\\Windows\\System32\\reg.exe"];

/// Create a command executor configured for reg.exe over `channel`.
pub fn create_reg_executor(channel: SharedChannel) -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::from_channel_with_timeout(
        channel,
        Duration::from_secs(DEFAULT_REG_TIMEOUT_SECS),
    );
    executor.allow_commands(REG_PATHS);
    executor
}

/// Parse reg.exe query output to extract type and value
///
/// Input format:
/// ```text
/// HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
///     CurrentBuildNumber    REG_SZ    26100
/// ```
pub fn parse_reg_output(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
        if parts.len() >= 3 {
            let reg_type = parts.get(1).map(|s| s.trim().to_string())?;
            let value = parts.get(2).map(|s| s.trim().to_string())?;
            return Some((reg_type, value));
        }

        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() >= 3 {
            for (i, word) in words.iter().enumerate() {
                if word.starts_with("REG_") {
                    let reg_type = word.to_string();
                    let value = words.get(i + 1..).map(|s| s.join(" ")).unwrap_or_default();
                    return Some((reg_type, value));
                }
            }
        }
    }
    None
}

/// Normalize registry type to lowercase ("REG_SZ" -> "reg_sz")
pub fn normalize_reg_type(reg_type: &str) -> String {
    reg_type.to_lowercase()
}

/// Normalize registry value based on type.
///
/// DWORD/QWORD values from reg.exe arrive in hex ("0x1"); convert to decimal
/// so policies compare against plain integers.
pub fn normalize_reg_value(reg_type: &str, value: &str) -> String {
    let type_upper = reg_type.to_uppercase();

    if type_upper == "REG_DWORD"
        || type_upper == "REG_QWORD"
        || type_upper == "REG_DWORD_BIG_ENDIAN"
    {
        if let Some(hex_str) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            if let Ok(num) = u64::from_str_radix(hex_str, 16) {
                return num.to_string();
            }
        }
        if value.parse::<u64>().is_ok() {
            return value.to_string();
        }
    }

    value.to_string()
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
