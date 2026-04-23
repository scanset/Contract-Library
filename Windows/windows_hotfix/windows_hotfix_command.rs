//! Get-HotFix helpers (Windows Update installed-patch enumeration)
//!
//! Single executor backend: `Get-HotFix -Id <kb>` via PowerShell.
//! STIG controls for Windows Update patch compliance typically assert
//! things like "KB5036893 is installed" or "the newest cumulative
//! update was installed within the last 30 days".
//!
//! Shape surprises captured from live Win2022 probes:
//!
//! - `InstalledOn` serializes as a **nested object**
//!   `{"value":"/Date(1711742400000)/","DateTime":"Monday, March 29, 2024 ..."}`.
//!   We parse the `.value` field (wire date) rather than the locale-
//!   dependent `DateTime` string.
//! - Missing hotfix: `Get-HotFix -Id X` with `-ErrorAction SilentlyContinue`
//!   returns `$null` (no exception). We emit an empty stdout in that
//!   case -> exists=false.

use serde::Deserialize;

const MAX_KB_LEN: usize = 16;

/// Validate a KB identifier before string-interpolation into a
/// PowerShell `-Command` body. Must be the literal prefix `KB`
/// followed by one or more ASCII digits.
pub fn is_safe_kb_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_KB_LEN {
        return false;
    }
    let bytes = id.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    if &bytes[0..2] != b"KB" {
        return false;
    }
    bytes[2..].iter().all(|b| b.is_ascii_digit())
}

/// Build the PowerShell command body. On not-found, emits empty stdout.
/// On success, emits a single JSON object with keys: Exists, HotFixID,
/// Description, InstalledOn (nested `{value, DateTime}`), InstalledBy.
pub fn build_get_hotfix_command(kb_id: &str) -> String {
    format!(
        "$h = Get-HotFix -Id '{kb_id}' -ErrorAction SilentlyContinue; \
         if ($null -eq $h) {{ Write-Output ''; exit 0 }}; \
         [PSCustomObject]@{{ \
           Exists = $true; \
           HotFixID = $h.HotFixID; \
           Description = $h.Description; \
           InstalledOn = $h.InstalledOn; \
           InstalledBy = $h.InstalledBy \
         }} | ConvertTo-Json -Compress"
    )
}

/// Nested `InstalledOn` shape.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct InstalledOnShape {
    #[serde(rename = "value")]
    pub value: Option<String>,
}

/// Raw Get-HotFix record.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawHotFix {
    #[serde(rename = "Exists")]
    pub exists: Option<bool>,
    #[serde(rename = "HotFixID")]
    pub hot_fix_id: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "InstalledOn")]
    pub installed_on: Option<InstalledOnShape>,
    #[serde(rename = "InstalledBy")]
    pub installed_by: Option<String>,
}

impl RawHotFix {
    pub fn is_found(&self) -> bool {
        self.exists == Some(true)
    }
}

/// Parse the JSON emitted by `build_get_hotfix_command`. Empty or
/// whitespace-only input yields a default (not-found) record.
pub fn parse_hotfix_json(text: &str) -> Result<RawHotFix, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(RawHotFix::default());
    }
    serde_json::from_str::<RawHotFix>(trimmed)
        .map_err(|e| format!("parse_hotfix_json: {} (input='{}')", e, trimmed))
}

/// Parse a PowerShell wire-format date string like `/Date(1711742400000)/`
/// into a raw milliseconds-since-epoch value. Accepts an optional
/// trailing `[+-]NNNN` timezone offset (e.g. `/Date(1711742400000-0400)/`);
/// the offset is ignored because the base ms value is already UTC.
/// Returns None on any malformed input.
pub fn parse_ps_date_string(s: &str) -> Option<i64> {
    let s = s.trim();
    let inner = s.strip_prefix("/Date(")?.strip_suffix(")/")?;
    // Split off any trailing timezone offset.
    let digits_end = inner
        .char_indices()
        .find(|(i, c)| *i > 0 && (*c == '+' || *c == '-'))
        .map(|(i, _)| i)
        .unwrap_or(inner.len());
    let ms_part = &inner[..digits_end];
    ms_part.parse::<i64>().ok()
}

/// Compute the whole number of days between two ms-since-epoch
/// timestamps. Positive when `past_ms` is before `now_ms`.
pub fn days_between_ms(now_ms: i64, past_ms: i64) -> i64 {
    (now_ms - past_ms) / 86_400_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_kb_ids() {
        assert!(is_safe_kb_id("KB5036893"));
        assert!(is_safe_kb_id("KB123"));
        assert!(is_safe_kb_id("KB12345678"));
    }

    #[test]
    fn rejects_bad_kb_ids() {
        assert!(!is_safe_kb_id(""));
        assert!(!is_safe_kb_id("KB"));
        assert!(!is_safe_kb_id("5036893"));
        assert!(!is_safe_kb_id("KB5036893; evil"));
        assert!(!is_safe_kb_id("kb5036893")); // require uppercase KB
        assert!(!is_safe_kb_id("KB5036893A"));
        assert!(!is_safe_kb_id("KB$(whoami)"));
        assert!(!is_safe_kb_id(&format!("KB{}", "1".repeat(MAX_KB_LEN))));
    }

    #[test]
    fn parses_ps_date_string_basic() {
        assert_eq!(
            parse_ps_date_string("/Date(1711742400000)/"),
            Some(1711742400000)
        );
    }

    #[test]
    fn parses_ps_date_string_with_offset() {
        assert_eq!(
            parse_ps_date_string("/Date(1711742400000-0400)/"),
            Some(1711742400000)
        );
        assert_eq!(
            parse_ps_date_string("/Date(1711742400000+0100)/"),
            Some(1711742400000)
        );
    }

    #[test]
    fn parses_ps_date_string_invalid() {
        assert_eq!(parse_ps_date_string(""), None);
        assert_eq!(parse_ps_date_string("1711742400000"), None);
        assert_eq!(parse_ps_date_string("/Date(abc)/"), None);
    }

    #[test]
    fn days_between_ms_basic() {
        // 1 day between these.
        assert_eq!(days_between_ms(86_400_000, 0), 1);
        assert_eq!(days_between_ms(0, 0), 0);
        // 10 days ago
        assert_eq!(
            days_between_ms(10 * 86_400_000 + 1_000_000, 0),
            10
        );
    }

    #[test]
    fn parses_hotfix_json_with_nested_installed_on() {
        let json = r#"{
            "Exists":true,
            "HotFixID":"KB5036893",
            "Description":"Security Update",
            "InstalledOn":{"value":"/Date(1711742400000)/","DateTime":"Monday, March 29, 2024"},
            "InstalledBy":"NT AUTHORITY\\SYSTEM"
        }"#;
        let h = parse_hotfix_json(json).expect("parse");
        assert!(h.is_found());
        assert_eq!(h.hot_fix_id.as_deref(), Some("KB5036893"));
        assert_eq!(h.description.as_deref(), Some("Security Update"));
        assert_eq!(
            h.installed_on.as_ref().and_then(|v| v.value.as_deref()),
            Some("/Date(1711742400000)/")
        );
        assert_eq!(h.installed_by.as_deref(), Some("NT AUTHORITY\\SYSTEM"));
    }

    #[test]
    fn parses_hotfix_not_found() {
        let h = parse_hotfix_json("").expect("parse");
        assert!(!h.is_found());
        assert!(h.hot_fix_id.is_none());
    }

    #[test]
    fn command_builder_embeds_kb_id() {
        let cmd = build_get_hotfix_command("KB5036893");
        assert!(cmd.contains("Get-HotFix -Id 'KB5036893'"));
        assert!(cmd.contains("SilentlyContinue"));
        assert!(cmd.contains("ConvertTo-Json"));
    }
}
