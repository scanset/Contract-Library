//! auditpol.exe helpers (Windows Advanced Audit Policy)
//!
//! `auditpol /get /category:* /r` emits CSV on stdout with columns:
//! `Machine Name, Policy Target, Subcategory, Subcategory GUID,
//!  Inclusion Setting, Exclusion Setting`
//!
//! We use a lightweight CSV parser (no external crate) since the output
//! is uniform — no embedded newlines in quoted fields, no escaping more
//! elaborate than doubled quotes.

use execution_engine::strategies::channel::SharedChannel;
use execution_engine::strategies::SystemCommandExecutor;
use std::collections::HashMap;
use std::time::Duration;

const DEFAULT_AUDITPOL_TIMEOUT_SECS: u64 = 30;

/// Whitelisted auditpol.exe binary paths
pub const AUDITPOL_PATHS: &[&str] =
    &["auditpol", "auditpol.exe", "C:\\Windows\\System32\\auditpol.exe"];

/// Create a command executor configured for auditpol.exe over `channel`.
pub fn create_auditpol_executor(channel: SharedChannel) -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::from_channel_with_timeout(
        channel,
        Duration::from_secs(DEFAULT_AUDITPOL_TIMEOUT_SECS),
    );
    executor.allow_commands(AUDITPOL_PATHS);
    executor
}

/// Parsed `auditpol /get /category:* /r` output.
///
/// Maps **subcategory name** (e.g. `"Credential Validation"`) to its
/// raw inclusion-setting string. Possible values:
/// - `"No Auditing"`
/// - `"Success"`
/// - `"Failure"`
/// - `"Success and Failure"`
#[derive(Debug, Default, Clone)]
pub struct AuditpolSnapshot {
    pub subcategories: HashMap<String, String>,
}

impl AuditpolSnapshot {
    /// Get raw inclusion setting for a subcategory (case-insensitive match
    /// on the subcategory name).
    pub fn get(&self, subcategory: &str) -> Option<&str> {
        let target = subcategory.trim().to_lowercase();
        self.subcategories
            .iter()
            .find(|(k, _)| k.to_lowercase() == target)
            .map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, subcategory: &str) -> bool {
        self.get(subcategory).is_some()
    }
}

/// Parse the CSV output of `auditpol /get /category:* /r`.
///
/// The header row is recognised by containing `Subcategory` and skipped.
/// Rows where `Subcategory` is empty or begins with `System audit policy`
/// (auditpol's own section divider) are skipped.
pub fn parse_auditpol_csv(text: &str) -> AuditpolSnapshot {
    let mut out = AuditpolSnapshot::default();
    let mut header_idx: Option<(usize, usize)> = None; // (subcategory col, inclusion col)

    for raw in text.lines() {
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }

        let fields = split_csv_row(line);

        if header_idx.is_none() {
            let sub = fields
                .iter()
                .position(|f| f.eq_ignore_ascii_case("Subcategory"));
            let inc = fields
                .iter()
                .position(|f| f.eq_ignore_ascii_case("Inclusion Setting"));
            if let (Some(s), Some(i)) = (sub, inc) {
                header_idx = Some((s, i));
            }
            continue;
        }

        let (si, ii) = header_idx.unwrap();
        let Some(sub) = fields.get(si).map(|s| s.trim()) else {
            continue;
        };
        if sub.is_empty() || sub.starts_with("System audit policy") {
            continue;
        }
        let inclusion = fields
            .get(ii)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.subcategories.insert(sub.to_string(), inclusion);
    }

    out
}

/// Minimal RFC-4180 CSV row splitter (quoted fields + doubled quotes).
/// auditpol does not use embedded newlines, so per-line is sufficient.
fn split_csv_row(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => {
                in_quotes = true;
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// True if the setting string audits success events.
pub fn audits_success(setting: &str) -> bool {
    let s = setting.to_lowercase();
    s.contains("success") && !s.starts_with("no auditing")
}

/// True if the setting string audits failure events.
pub fn audits_failure(setting: &str) -> bool {
    let s = setting.to_lowercase();
    s.contains("failure") && !s.starts_with("no auditing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_output() {
        let csv = "\
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
WIN-EXAMPLE,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,
WIN-EXAMPLE,System,Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},No Auditing,
WIN-EXAMPLE,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success,
WIN-EXAMPLE,System,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},Failure,
";
        let s = parse_auditpol_csv(csv);
        assert_eq!(s.get("Credential Validation"), Some("Success and Failure"));
        assert_eq!(s.get("Kerberos Authentication Service"), Some("No Auditing"));
        assert_eq!(s.get("Security Group Management"), Some("Success"));
        assert_eq!(s.get("Sensitive Privilege Use"), Some("Failure"));

        // case-insensitive lookup
        assert_eq!(s.get("credential validation"), Some("Success and Failure"));

        // audits_success / audits_failure
        assert!(audits_success("Success and Failure"));
        assert!(audits_failure("Success and Failure"));
        assert!(audits_success("Success"));
        assert!(!audits_failure("Success"));
        assert!(!audits_success("No Auditing"));
        assert!(!audits_failure("No Auditing"));
    }

    #[test]
    fn handles_quoted_fields() {
        let csv = "\
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
HOST,System,\"Object Access, Detailed\",{guid},Success,
";
        let s = parse_auditpol_csv(csv);
        assert_eq!(s.get("Object Access, Detailed"), Some("Success"));
    }

    #[test]
    fn skips_bom_and_blank_lines() {
        let csv = "\u{feff}\n\nMachine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\nH,System,Logon,{g},Success and Failure,\n\n";
        let s = parse_auditpol_csv(csv);
        assert_eq!(s.get("Logon"), Some("Success and Failure"));
    }
}
