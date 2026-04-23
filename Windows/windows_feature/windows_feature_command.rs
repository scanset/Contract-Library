//! Get-WindowsFeature / Get-WindowsOptionalFeature helpers
//!
//! Two executor backends cover the two Windows feature namespaces:
//!
//! - **optionalfeature** (default, works on Client + Server): DISM-backed
//!   `Get-WindowsOptionalFeature -Online`. Scope is "Windows features"
//!   (SMB1Protocol, TelnetClient, TFTP, IIS-* components, etc.).
//!   State enum: Enabled / Disabled / EnableWithPayloadRemoved /
//!   DisabledWithPayloadRemoved. No DisplayName on this backend.
//!
//! - **windowsfeature** (Server-only): ServerManager-backed
//!   `Get-WindowsFeature`. Scope is Server Roles, Role Services, and a
//!   separate "Features" list (Web-Server, RSAT-*, Windows-Defender,
//!   etc.). Adds DisplayName and FeatureType (Role/RoleService/Feature).
//!   InstallState enum: Installed / Available / Removed.
//!
//! The two namespaces overlap partially (~43 names) but each exposes
//! roughly 200-300 features the other does not. Callers pick the backend
//! matching the STIG control's vocabulary — no automatic fallback.
//!
//! Both backends: missing feature returns empty stdout (no exception
//! class to catch). Empty stdout -> exists=false.
//!
//! Enum projection: both InstallState and State serialize as integers in
//! ConvertTo-Json despite displaying as strings on the console. We force
//! `.ToString()` in Select-Object so the JSON text is self-describing.

use serde::Deserialize;

const MAX_NAME_LEN: usize = 128;

/// Validate a feature name before string-interpolation into a PowerShell
/// `-Command` body. Windows feature names permit letters, digits, hyphen
/// (most common separator: `Web-Server`, `RSAT-AD-Tools`), dot, and
/// underscore. Reject anything that carries meaning to PowerShell's
/// parser.
pub fn is_safe_feature_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Build the PowerShell command body for the `optionalfeature` backend.
///
/// Emits `[]` when the feature name doesn't match, else a single JSON
/// object with fields: FeatureName, State (string), DisplayName (always
/// null here — this backend doesn't expose it).
pub fn build_get_optionalfeature_command(name: &str) -> String {
    format!(
        "$f = Get-WindowsOptionalFeature -Online -FeatureName '{}' -ErrorAction SilentlyContinue; \
         if ($null -eq $f) {{ Write-Output '[]' }} else {{ \
           $f | Select-Object FeatureName,\
             @{{N='State';E={{$_.State.ToString()}}}},\
             @{{N='DisplayName';E={{$null}}}},\
             @{{N='FeatureType';E={{'OptionalFeature'}}}} | \
           ConvertTo-Json -Depth 3 -Compress \
         }}",
        name
    )
}

/// Build the PowerShell command body for the `windowsfeature` backend
/// (Server-only).
///
/// Get-WindowsFeature emits a Warning line to stderr on Client SKUs
/// ("The target of the specified cmdlet cannot be a Windows client-based
/// operating system"); the collector should treat stderr warnings as
/// non-fatal when the exit code is zero.
pub fn build_get_windowsfeature_command(name: &str) -> String {
    format!(
        "$f = Get-WindowsFeature -Name '{}' -ErrorAction SilentlyContinue; \
         if ($null -eq $f -or $f.Count -eq 0) {{ Write-Output '[]' }} else {{ \
           $f | Select-Object Name,\
             @{{N='InstallState';E={{$_.InstallState.ToString()}}}},\
             DisplayName,\
             @{{N='FeatureType';E={{$_.FeatureType.ToString()}}}} | \
           ConvertTo-Json -Depth 3 -Compress \
         }}",
        name
    )
}

/// Raw JSON row from `build_get_optionalfeature_command`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawOptionalFeature {
    #[serde(rename = "FeatureName")]
    pub feature_name: String,
    #[serde(rename = "State")]
    pub state: Option<String>,
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
    #[serde(rename = "FeatureType")]
    pub feature_type: Option<String>,
}

/// Raw JSON row from `build_get_windowsfeature_command`.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawWindowsFeature {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "InstallState")]
    pub install_state: Option<String>,
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
    #[serde(rename = "FeatureType")]
    pub feature_type: Option<String>,
}

/// True if an Optional-Feature `State` string indicates the feature is
/// functionally enabled. Only the bare `"Enabled"` counts; the payload-
/// removed variants (disabled-with-payload-removed and
/// enable-with-payload-removed) are treated as not-enabled for STIG
/// purposes since the feature's binaries are absent.
pub fn optionalfeature_state_is_enabled(state: &str) -> bool {
    state.eq_ignore_ascii_case("Enabled")
}

/// True if a WindowsFeature `InstallState` string indicates the role /
/// feature is installed and active on the server. `Available` = can be
/// installed but is not; `Removed` = binaries are not even on disk.
pub fn windowsfeature_installstate_is_installed(state: &str) -> bool {
    state.eq_ignore_ascii_case("Installed")
}

/// Parse the JSON emitted by `build_get_optionalfeature_command`.
pub fn parse_optionalfeature_json(text: &str) -> Result<Vec<RawOptionalFeature>, String> {
    parse_json_maybe_array(text)
}

/// Parse the JSON emitted by `build_get_windowsfeature_command`.
pub fn parse_windowsfeature_json(text: &str) -> Result<Vec<RawWindowsFeature>, String> {
    parse_json_maybe_array(text)
}

fn parse_json_maybe_array<T: for<'de> serde::Deserialize<'de>>(
    text: &str,
) -> Result<Vec<T>, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
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
    serde_json::from_str::<T>(trimmed)
        .map(|o| vec![o])
        .map_err(|e| format!("parse_feature_json: {} (input='{}')", e, trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_feature_names() {
        assert!(is_safe_feature_name("SMB1Protocol"));
        assert!(is_safe_feature_name("TelnetClient"));
        assert!(is_safe_feature_name("Web-Server"));
        assert!(is_safe_feature_name("RSAT-AD-Tools"));
        assert!(is_safe_feature_name("Windows-Defender"));
        assert!(is_safe_feature_name("IIS-WebServerRole"));
        assert!(is_safe_feature_name("NetFx3"));
        assert!(is_safe_feature_name("TFTP"));
    }

    #[test]
    fn rejects_unsafe_feature_names() {
        assert!(!is_safe_feature_name(""));
        assert!(!is_safe_feature_name("a'; rm"));
        assert!(!is_safe_feature_name("a`b"));
        assert!(!is_safe_feature_name("a b"));
        assert!(!is_safe_feature_name("a$(whoami)"));
        assert!(!is_safe_feature_name("a;b"));
        assert!(!is_safe_feature_name(&"x".repeat(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn parses_optionalfeature_enabled() {
        let json = r#"[{"FeatureName":"SMB1Protocol","State":"Disabled",
                       "DisplayName":null,"FeatureType":"OptionalFeature"}]"#;
        let v = parse_optionalfeature_json(json).expect("parse");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].feature_name, "SMB1Protocol");
        assert_eq!(v[0].state.as_deref(), Some("Disabled"));
        assert!(!optionalfeature_state_is_enabled(v[0].state.as_deref().unwrap()));
    }

    #[test]
    fn parses_optionalfeature_single_object_form() {
        let json = r#"{"FeatureName":"TelnetClient","State":"Enabled",
                       "DisplayName":null,"FeatureType":"OptionalFeature"}"#;
        let v = parse_optionalfeature_json(json).expect("parse");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].feature_name, "TelnetClient");
        assert!(optionalfeature_state_is_enabled(v[0].state.as_deref().unwrap()));
    }

    #[test]
    fn parses_optionalfeature_not_found() {
        let v = parse_optionalfeature_json("[]").expect("parse");
        assert!(v.is_empty());
    }

    #[test]
    fn parses_windowsfeature_installed() {
        let json = r#"[{"Name":"Web-Server","InstallState":"Installed",
                       "DisplayName":"Web Server (IIS)","FeatureType":"Role"}]"#;
        let v = parse_windowsfeature_json(json).expect("parse");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "Web-Server");
        assert_eq!(v[0].install_state.as_deref(), Some("Installed"));
        assert_eq!(v[0].display_name.as_deref(), Some("Web Server (IIS)"));
        assert_eq!(v[0].feature_type.as_deref(), Some("Role"));
        assert!(windowsfeature_installstate_is_installed(
            v[0].install_state.as_deref().unwrap()
        ));
    }

    #[test]
    fn parses_windowsfeature_available() {
        let json = r#"{"Name":"Telnet-Client","InstallState":"Available",
                       "DisplayName":"Telnet Client","FeatureType":"Feature"}"#;
        let v = parse_windowsfeature_json(json).expect("parse");
        assert_eq!(v.len(), 1);
        assert!(!windowsfeature_installstate_is_installed(
            v[0].install_state.as_deref().unwrap()
        ));
    }

    #[test]
    fn parses_windowsfeature_empty() {
        let v = parse_windowsfeature_json("").expect("parse");
        assert!(v.is_empty());
        let v = parse_windowsfeature_json("[]").expect("parse");
        assert!(v.is_empty());
    }

    #[test]
    fn enabled_and_installed_helpers_are_case_insensitive() {
        assert!(optionalfeature_state_is_enabled("Enabled"));
        assert!(optionalfeature_state_is_enabled("ENABLED"));
        assert!(!optionalfeature_state_is_enabled("EnableWithPayloadRemoved"));
        assert!(!optionalfeature_state_is_enabled("DisabledWithPayloadRemoved"));
        assert!(windowsfeature_installstate_is_installed("Installed"));
        assert!(windowsfeature_installstate_is_installed("INSTALLED"));
        assert!(!windowsfeature_installstate_is_installed("Available"));
        assert!(!windowsfeature_installstate_is_installed("Removed"));
    }

    #[test]
    fn command_builders_emit_expected_patterns() {
        let opt = build_get_optionalfeature_command("SMB1Protocol");
        assert!(opt.contains("Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol'"));
        assert!(opt.contains("$_.State.ToString()"));
        assert!(opt.contains("ConvertTo-Json"));

        let srv = build_get_windowsfeature_command("Web-Server");
        assert!(srv.contains("Get-WindowsFeature -Name 'Web-Server'"));
        assert!(srv.contains("$_.InstallState.ToString()"));
        assert!(srv.contains("$_.FeatureType.ToString()"));
    }
}
