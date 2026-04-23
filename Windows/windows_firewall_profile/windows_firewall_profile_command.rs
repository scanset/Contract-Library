//! Get-NetFirewallProfile helpers
//!
//! Single executor backend: `Get-NetFirewallProfile -Name <profile>`.
//! STIG controls for Windows Firewall typically assert things like:
//!   - the Domain / Private / Public profile is enabled
//!   - default inbound action is Block
//!   - log-allowed and log-blocked are both enabled
//!   - notifications are enabled
//!
//! Shape surprises: PowerShell 5.1 serializes all of NetSecurity's
//! GpoMultiConfig enums as integers in ConvertTo-Json, even though
//! they display as strings on the console. We translate the ints back
//! to strings / bools on the Rust side so the CTN fields are
//! self-describing.

use serde::Deserialize;

/// Validate and canonicalise a firewall-profile name. Accepts
/// Domain / Private / Public in any case; returns the title-cased
/// form expected by Get-NetFirewallProfile. Returns None for any
/// other value.
pub fn canonical_profile_name(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "domain" => Some("Domain"),
        "private" => Some("Private"),
        "public" => Some("Public"),
        _ => None,
    }
}

/// True iff `name` (case-insensitive) is Domain, Private, or Public.
pub fn is_safe_profile_name(name: &str) -> bool {
    canonical_profile_name(name).is_some()
}

/// Build the PowerShell command body. On not-found, emits empty
/// stdout. On success, emits a single JSON object with keys: Name,
/// Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed,
/// LogBlocked, LogFileName, NotifyOnListen.
pub fn build_get_firewall_profile_command(canonical_name: &str) -> String {
    format!(
        "$p = Get-NetFirewallProfile -Name '{canonical_name}' -ErrorAction SilentlyContinue; \
         if ($null -eq $p) {{ Write-Output ''; exit 0 }}; \
         $p | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,\
LogAllowed,LogBlocked,LogFileName,NotifyOnListen | ConvertTo-Json -Compress"
    )
}

/// Raw Get-NetFirewallProfile record. All numeric enum fields are
/// optional because the profile-not-found case yields an empty-object
/// JSON body.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawFirewallProfile {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Enabled")]
    pub enabled: Option<i64>,
    #[serde(rename = "DefaultInboundAction")]
    pub default_inbound_action: Option<i64>,
    #[serde(rename = "DefaultOutboundAction")]
    pub default_outbound_action: Option<i64>,
    #[serde(rename = "LogAllowed")]
    pub log_allowed: Option<i64>,
    #[serde(rename = "LogBlocked")]
    pub log_blocked: Option<i64>,
    #[serde(rename = "LogFileName")]
    pub log_file_name: Option<String>,
    #[serde(rename = "NotifyOnListen")]
    pub notify_on_listen: Option<i64>,
}

/// Parse the JSON emitted by `build_get_firewall_profile_command`.
/// Returns `Ok(None)` when stdout is empty or is the JSON literal
/// `null` (both signal profile-not-found).
pub fn parse_profile_json(text: &str) -> Result<Option<RawFirewallProfile>, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(None);
    }
    serde_json::from_str::<RawFirewallProfile>(trimmed)
        .map(Some)
        .map_err(|e| format!("parse_profile_json: {} (input='{}')", e, trimmed))
}

/// Decode the `Enabled` GpoBoolean enum.
///   1 = True, 2 = False, 0 = NotConfigured (returns None so callers
/// may skip emitting the field rather than pretend "configured
/// disabled").
pub fn decode_enabled(opt: Option<i64>) -> Option<bool> {
    match opt {
        Some(1) => Some(true),
        Some(2) => Some(false),
        _ => None,
    }
}

/// Decode the `Default*Action` GpoAction enum.
///   2 = Allow, 4 = Block, 0/9 = NotConfigured.
pub fn decode_action(opt: Option<i64>) -> Option<&'static str> {
    match opt {
        Some(2) => Some("Allow"),
        Some(4) => Some("Block"),
        Some(0) | Some(9) => Some("NotConfigured"),
        _ => None,
    }
}

/// Decode the `LogAllowed` / `LogBlocked` GpoBoolean enum.
///   1 = True, 2 = False, 0 = NotConfigured (None).
pub fn decode_log_flag(opt: Option<i64>) -> Option<bool> {
    match opt {
        Some(1) => Some(true),
        Some(2) => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_profile_name() {
        assert_eq!(canonical_profile_name("Domain"), Some("Domain"));
        assert_eq!(canonical_profile_name("private"), Some("Private"));
        assert_eq!(canonical_profile_name("PUBLIC"), Some("Public"));
        assert_eq!(canonical_profile_name("Any"), None);
        assert_eq!(canonical_profile_name(""), None);
    }

    #[test]
    fn validator_accepts_three_profiles() {
        assert!(is_safe_profile_name("Domain"));
        assert!(is_safe_profile_name("private"));
        assert!(is_safe_profile_name("PUBLIC"));
        assert!(!is_safe_profile_name("Any"));
        assert!(!is_safe_profile_name(""));
    }

    #[test]
    fn decodes_enabled_values() {
        assert_eq!(decode_enabled(Some(1)), Some(true));
        assert_eq!(decode_enabled(Some(2)), Some(false));
        assert_eq!(decode_enabled(Some(0)), None);
        assert_eq!(decode_enabled(None), None);
    }

    #[test]
    fn decodes_action_values() {
        assert_eq!(decode_action(Some(2)), Some("Allow"));
        assert_eq!(decode_action(Some(4)), Some("Block"));
        assert_eq!(decode_action(Some(0)), Some("NotConfigured"));
        assert_eq!(decode_action(Some(9)), Some("NotConfigured"));
        assert_eq!(decode_action(None), None);
    }

    #[test]
    fn decodes_log_flag_values() {
        assert_eq!(decode_log_flag(Some(1)), Some(true));
        assert_eq!(decode_log_flag(Some(2)), Some(false));
        assert_eq!(decode_log_flag(Some(0)), None);
    }

    #[test]
    fn parses_profile_json_sample() {
        let json = r#"{"Name":"Domain","Enabled":1,"DefaultInboundAction":4,
                       "DefaultOutboundAction":2,"LogAllowed":2,"LogBlocked":1,
                       "LogFileName":"%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log",
                       "NotifyOnListen":1}"#;
        let p = parse_profile_json(json).expect("parse").expect("some");
        assert_eq!(p.name, "Domain");
        assert_eq!(decode_enabled(p.enabled), Some(true));
        assert_eq!(decode_action(p.default_inbound_action), Some("Block"));
        assert_eq!(decode_action(p.default_outbound_action), Some("Allow"));
        assert_eq!(decode_log_flag(p.log_allowed), Some(false));
        assert_eq!(decode_log_flag(p.log_blocked), Some(true));
        assert!(p.log_file_name.is_some());
        assert_eq!(decode_log_flag(p.notify_on_listen), Some(true));
    }

    #[test]
    fn parses_profile_json_empty_as_none() {
        assert!(parse_profile_json("").unwrap().is_none());
        assert!(parse_profile_json("null").unwrap().is_none());
    }

    #[test]
    fn command_builder_embeds_profile_name() {
        let cmd = build_get_firewall_profile_command("Domain");
        assert!(cmd.contains("Get-NetFirewallProfile -Name 'Domain'"));
        assert!(cmd.contains("ConvertTo-Json"));
        assert!(cmd.contains("NotifyOnListen"));
    }
}
