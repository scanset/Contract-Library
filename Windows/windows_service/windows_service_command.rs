// === sc.rs ===

//! sc.exe command executor (Windows Service queries)
//!
//! Channel-aware whitelisted executor for `sc.exe`.

use execution_engine::strategies::channel::SharedChannel;
use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Default timeout for sc.exe execution (30 seconds)
const DEFAULT_SC_TIMEOUT_SECS: u64 = 30;

/// Whitelisted sc.exe binary paths
pub const SC_PATHS: &[&str] = &["sc.exe", "C:\\Windows\\System32\\sc.exe"];

/// sc.exe error codes
pub const SC_ERROR_SERVICE_NOT_FOUND: i32 = 1060;
pub const SC_ERROR_ACCESS_DENIED: i32 = 5;

/// Parsed output from `sc.exe query`
#[derive(Debug, Clone, Default)]
pub struct ScQueryOutput {
    pub state: String,
    pub service_type: Option<String>,
}

/// Parsed output from `sc.exe qc`
#[derive(Debug, Clone, Default)]
pub struct ScQcOutput {
    pub service_type: String,
    pub start_type: String,
    pub path: String,
    pub display_name: String,
}

/// Create a command executor configured for sc.exe over `channel`.
pub fn create_sc_executor(channel: SharedChannel) -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::from_channel_with_timeout(
        channel,
        Duration::from_secs(DEFAULT_SC_TIMEOUT_SECS),
    );
    executor.allow_commands(SC_PATHS);
    executor
}

/// Check if sc.exe output indicates the service was not found
pub fn is_service_not_found(output: &str) -> bool {
    output.contains("FAILED 1060:") || output.contains("does not exist as an installed service")
}

/// Check if sc.exe output indicates access denied
pub fn is_access_denied(output: &str) -> bool {
    output.contains("FAILED 5:") || output.to_lowercase().contains("access is denied")
}

/// Parse `sc.exe query` output to extract runtime state.
pub fn parse_sc_query_output(output: &str) -> Option<ScQueryOutput> {
    let mut result = ScQueryOutput::default();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("STATE") {
            if let Some(state) = parse_state_line(trimmed) {
                result.state = state;
            }
        }

        if trimmed.starts_with("TYPE") {
            if let Some(svc_type) = parse_type_line(trimmed) {
                result.service_type = Some(svc_type);
            }
        }
    }

    if result.state.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse `sc.exe qc` output to extract configuration.
pub fn parse_sc_qc_output(output: &str) -> Option<ScQcOutput> {
    let mut result = ScQcOutput::default();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("TYPE") {
            if let Some(svc_type) = parse_type_line(trimmed) {
                result.service_type = svc_type;
            }
        }

        if trimmed.starts_with("START_TYPE") {
            if let Some(start_type) = parse_start_type_line(trimmed) {
                result.start_type = start_type;
            }
        }

        if trimmed.starts_with("BINARY_PATH_NAME") {
            if let Some(path) = parse_key_value_line(trimmed) {
                result.path = path;
            }
        }

        if trimmed.starts_with("DISPLAY_NAME") {
            if let Some(name) = parse_key_value_line(trimmed) {
                result.display_name = name;
            }
        }
    }

    if result.start_type.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn parse_state_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();
    let state_text = extract_text_after_number(value)?;
    Some(normalize_state(&state_text))
}

fn parse_type_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();
    let type_text = extract_text_after_number(value)?;
    Some(normalize_service_type(&type_text))
}

fn parse_start_type_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();
    let start_text = extract_text_after_number(value)?;
    Some(normalize_start_type(&start_text))
}

fn parse_key_value_line(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn extract_text_after_number(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let text_start = trimmed
        .find(|c: char| !c.is_ascii_digit() && !c.is_whitespace())
        .unwrap_or(0);
    let text = trimmed.get(text_start..)?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn normalize_state(state: &str) -> String {
    match state.to_uppercase().as_str() {
        "STOPPED" => "stopped".to_string(),
        "START_PENDING" => "start_pending".to_string(),
        "STOP_PENDING" => "stop_pending".to_string(),
        "RUNNING" => "running".to_string(),
        "CONTINUE_PENDING" => "continue_pending".to_string(),
        "PAUSE_PENDING" => "pause_pending".to_string(),
        "PAUSED" => "paused".to_string(),
        _ => "unknown".to_string(),
    }
}

fn normalize_start_type(start_type: &str) -> String {
    let upper = start_type.to_uppercase();

    if upper.contains("AUTO_START") && upper.contains("DELAYED") {
        return "auto_delayed".to_string();
    }

    if upper.contains("BOOT_START") {
        "boot".to_string()
    } else if upper.contains("SYSTEM_START") {
        "system".to_string()
    } else if upper.contains("AUTO_START") {
        "auto".to_string()
    } else if upper.contains("DEMAND_START") {
        "manual".to_string()
    } else if upper.contains("DISABLED") {
        "disabled".to_string()
    } else {
        "unknown".to_string()
    }
}

fn normalize_service_type(svc_type: &str) -> String {
    let upper = svc_type.to_uppercase();

    if upper.contains("WIN32_OWN_PROCESS") && upper.contains("INTERACTIVE") {
        return "own_process_interactive".to_string();
    }

    if upper.contains("KERNEL_DRIVER") {
        "kernel_driver".to_string()
    } else if upper.contains("FILE_SYSTEM_DRIVER") {
        "file_system_driver".to_string()
    } else if upper.contains("WIN32_OWN_PROCESS") {
        "own_process".to_string()
    } else if upper.contains("WIN32_SHARE_PROCESS") {
        "share_process".to_string()
    } else if upper == "WIN32" {
        "win32".to_string()
    } else {
        "unknown".to_string()
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
