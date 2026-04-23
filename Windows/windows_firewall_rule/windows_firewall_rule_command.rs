//! Get-NetFirewallRule helpers
//!
//! Single executor backend: `Get-NetFirewallRule` with one of three
//! lookup parameters:
//!   - `-Name` (default): internal rule ID / name
//!   - `-DisplayName`: user-facing rule name
//!   - `-DisplayGroup`: name of the rule group
//!
//! STIG controls for Windows Firewall rules typically assert:
//!   - a named rule exists and is enabled
//!   - a specific display-name rule blocks inbound traffic
//!   - a rule group contains at least one active rule
//!
//! `-DisplayGroup` queries can return multiple rules; we pipe through
//! `Select-Object -First 1` to keep single-object CTN semantics.
//! Callers that need to assert on a *specific* rule within a group
//! should identify the rule by `name` or `display_name` instead.
//!
//! Shape surprises: PowerShell 5.1 serializes Enabled, Direction,
//! Action, Profile, and PrimaryStatus as integers in ConvertTo-Json,
//! same as Get-NetFirewallProfile. We translate them back on the Rust
//! side.

use serde::Deserialize;

const MAX_ID_LEN: usize = 512;

/// Validate a firewall rule identifier (Name, DisplayName, or
/// DisplayGroup) before string-interpolation into a PowerShell
/// `-Command` body. Firewall rule strings can be long and include
/// GUIDs, spaces, dashes, slashes, parens, colons, and braces - so
/// the allowlist is more permissive than the one used by file/registry
/// paths. We still reject characters that carry meaning inside a
/// single-quoted PowerShell string or the command pipeline.
pub fn is_safe_rule_identifier(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return false;
    }
    if id.contains("$(") || id.contains("${") {
        return false;
    }
    !id.chars().any(|c| {
        matches!(c, '\'' | '`' | ';' | '|' | '&' | '"' | '\n' | '\r')
    })
}

/// Identify which `Get-NetFirewallRule` parameter to use.
#[derive(Debug, Clone, Copy)]
pub enum MatchBy {
    Name,
    DisplayName,
    DisplayGroup,
}

impl MatchBy {
    pub fn parse(s: &str) -> Option<MatchBy> {
        match s {
            "name" => Some(MatchBy::Name),
            "display_name" => Some(MatchBy::DisplayName),
            "display_group" => Some(MatchBy::DisplayGroup),
            _ => None,
        }
    }

    pub fn ps_flag(self) -> &'static str {
        match self {
            MatchBy::Name => "-Name",
            MatchBy::DisplayName => "-DisplayName",
            MatchBy::DisplayGroup => "-DisplayGroup",
        }
    }
}

/// Build the PowerShell command body. On not-found, emits empty
/// stdout. On success, emits a single JSON object with the projection
/// Name,DisplayName,Description,Enabled,Direction,Action,Profile,
/// DisplayGroup,PrimaryStatus,Status.
pub fn build_get_firewall_rule_command(value: &str, match_by: MatchBy) -> String {
    // -DisplayGroup queries can return multiple rules; -First 1 keeps
    // single-object CTN semantics. STIG checks typically assert "at
    // least one rule in group X exists and is enabled"; for multi-rule
    // groups callers should pin by name.
    let flag = match_by.ps_flag();
    format!(
        "$r = Get-NetFirewallRule {flag} '{value}' -ErrorAction SilentlyContinue; \
         if ($null -eq $r) {{ Write-Output ''; exit 0 }}; \
         $r | Select-Object -First 1 Name,DisplayName,Description,Enabled,Direction,\
Action,Profile,DisplayGroup,PrimaryStatus,Status | ConvertTo-Json -Compress"
    )
}

/// Raw Get-NetFirewallRule record.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawFirewallRule {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Enabled")]
    pub enabled: Option<i64>,
    #[serde(rename = "Direction")]
    pub direction: Option<i64>,
    #[serde(rename = "Action")]
    pub action: Option<i64>,
    #[serde(rename = "Profile")]
    pub profile: Option<i64>,
    #[serde(rename = "DisplayGroup")]
    pub display_group: Option<String>,
    #[serde(rename = "PrimaryStatus")]
    pub primary_status: Option<i64>,
    #[serde(rename = "Status")]
    pub status: Option<String>,
}

/// Parse the JSON emitted by `build_get_firewall_rule_command`.
/// Returns `Ok(None)` when stdout is empty or is the JSON literal
/// `null` (both signal rule-not-found).
pub fn parse_rule_json(text: &str) -> Result<Option<RawFirewallRule>, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(None);
    }
    serde_json::from_str::<RawFirewallRule>(trimmed)
        .map(Some)
        .map_err(|e| format!("parse_rule_json: {} (input='{}')", e, trimmed))
}

/// Decode the `Enabled` GpoBoolean enum.
///   1 = True, 2 = False.
pub fn decode_rule_enabled(opt: Option<i64>) -> Option<bool> {
    match opt {
        Some(1) => Some(true),
        Some(2) => Some(false),
        _ => None,
    }
}

/// Decode the `Direction` enum.
///   1 = Inbound, 2 = Outbound.
pub fn decode_direction(opt: Option<i64>) -> Option<&'static str> {
    match opt {
        Some(1) => Some("Inbound"),
        Some(2) => Some("Outbound"),
        _ => None,
    }
}

/// Decode the `Action` enum. Same values as firewall profile actions.
pub fn decode_rule_action(opt: Option<i64>) -> Option<&'static str> {
    match opt {
        Some(2) => Some("Allow"),
        Some(4) => Some("Block"),
        Some(0) | Some(9) => Some("NotConfigured"),
        _ => None,
    }
}

/// Decode the `Profile` bitmask into a sorted comma-joined string.
///   0        = "Any"
///   1        = "Domain"
///   2        = "Private"
///   4        = "Public"
///   combined = sorted, e.g. "Domain, Private, Public"
pub fn decode_profile_bitmask(opt: Option<i64>) -> Option<String> {
    let v = opt?;
    if v == 0 {
        return Some("Any".to_string());
    }
    let mut out: Vec<&str> = Vec::new();
    if (v & 1) != 0 {
        out.push("Domain");
    }
    if (v & 2) != 0 {
        out.push("Private");
    }
    if (v & 4) != 0 {
        out.push("Public");
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join(", "))
}

/// Decode the `PrimaryStatus` enum.
pub fn decode_primary_status(opt: Option<i64>) -> Option<&'static str> {
    match opt {
        Some(1) => Some("OK"),
        Some(2) => Some("Degraded"),
        Some(3) => Some("Error"),
        Some(4) => Some("Unknown"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_rule_identifiers() {
        assert!(is_safe_rule_identifier("RemoteDesktop-UserMode-In-TCP"));
        assert!(is_safe_rule_identifier("Remote Desktop (TCP-In)"));
        assert!(is_safe_rule_identifier("{12345678-ABCD-1234-EFAB-0123456789AB}"));
        assert!(is_safe_rule_identifier("File and Printer Sharing"));
    }

    #[test]
    fn rejects_injection_rule_identifiers() {
        assert!(!is_safe_rule_identifier(""));
        assert!(!is_safe_rule_identifier("abc$(whoami)"));
        assert!(!is_safe_rule_identifier("abc${evil}"));
        assert!(!is_safe_rule_identifier("abc'evil"));
        assert!(!is_safe_rule_identifier("abc`evil"));
        assert!(!is_safe_rule_identifier("abc;evil"));
        assert!(!is_safe_rule_identifier("abc|evil"));
        assert!(!is_safe_rule_identifier("abc&evil"));
        assert!(!is_safe_rule_identifier("abc\"evil"));
        assert!(!is_safe_rule_identifier("abc\nevil"));
    }

    #[test]
    fn command_builder_name_mode() {
        let cmd = build_get_firewall_rule_command("RDP-In", MatchBy::Name);
        assert!(cmd.contains("Get-NetFirewallRule -Name 'RDP-In'"));
        assert!(cmd.contains("Select-Object -First 1"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    #[test]
    fn command_builder_display_name_mode() {
        let cmd = build_get_firewall_rule_command("Remote Desktop (TCP-In)", MatchBy::DisplayName);
        assert!(cmd.contains("Get-NetFirewallRule -DisplayName 'Remote Desktop (TCP-In)'"));
    }

    #[test]
    fn command_builder_display_group_mode() {
        let cmd = build_get_firewall_rule_command("Remote Desktop", MatchBy::DisplayGroup);
        assert!(cmd.contains("Get-NetFirewallRule -DisplayGroup 'Remote Desktop'"));
    }

    #[test]
    fn match_by_parser() {
        assert!(matches!(MatchBy::parse("name"), Some(MatchBy::Name)));
        assert!(matches!(
            MatchBy::parse("display_name"),
            Some(MatchBy::DisplayName)
        ));
        assert!(matches!(
            MatchBy::parse("display_group"),
            Some(MatchBy::DisplayGroup)
        ));
        assert!(MatchBy::parse("other").is_none());
    }

    #[test]
    fn decodes_profile_bitmask_values() {
        assert_eq!(decode_profile_bitmask(Some(0)).as_deref(), Some("Any"));
        assert_eq!(decode_profile_bitmask(Some(1)).as_deref(), Some("Domain"));
        assert_eq!(decode_profile_bitmask(Some(2)).as_deref(), Some("Private"));
        assert_eq!(decode_profile_bitmask(Some(4)).as_deref(), Some("Public"));
        assert_eq!(
            decode_profile_bitmask(Some(7)).as_deref(),
            Some("Domain, Private, Public")
        );
        assert_eq!(
            decode_profile_bitmask(Some(3)).as_deref(),
            Some("Domain, Private")
        );
        assert_eq!(decode_profile_bitmask(None), None);
    }

    #[test]
    fn decodes_action_direction_status() {
        assert_eq!(decode_rule_action(Some(2)), Some("Allow"));
        assert_eq!(decode_rule_action(Some(4)), Some("Block"));
        assert_eq!(decode_direction(Some(1)), Some("Inbound"));
        assert_eq!(decode_direction(Some(2)), Some("Outbound"));
        assert_eq!(decode_primary_status(Some(1)), Some("OK"));
        assert_eq!(decode_primary_status(Some(3)), Some("Error"));
    }

    #[test]
    fn parses_rule_json_sample() {
        let json = r#"{"Name":"RemoteDesktop-UserMode-In-TCP",
                       "DisplayName":"Remote Desktop - User Mode (TCP-In)",
                       "Description":"Inbound rule for Remote Desktop",
                       "Enabled":1,"Direction":1,"Action":2,"Profile":7,
                       "DisplayGroup":"Remote Desktop","PrimaryStatus":1,
                       "Status":"The rule was parsed successfully from the store."}"#;
        let r = parse_rule_json(json).expect("parse").expect("some");
        assert_eq!(r.name.as_deref(), Some("RemoteDesktop-UserMode-In-TCP"));
        assert_eq!(decode_rule_enabled(r.enabled), Some(true));
        assert_eq!(decode_direction(r.direction), Some("Inbound"));
        assert_eq!(decode_rule_action(r.action), Some("Allow"));
        assert_eq!(
            decode_profile_bitmask(r.profile).as_deref(),
            Some("Domain, Private, Public")
        );
        assert_eq!(r.display_group.as_deref(), Some("Remote Desktop"));
    }

    #[test]
    fn parses_rule_json_empty_as_none() {
        assert!(parse_rule_json("").unwrap().is_none());
        assert!(parse_rule_json("null").unwrap().is_none());
    }
}
