//! Get-ScheduledTask / Get-ScheduledTaskInfo helpers
//!
//! Single executor backend: `Get-ScheduledTask` combined with
//! `Get-ScheduledTaskInfo`, via PowerShell. STIG controls for scheduled
//! tasks typically assert things like:
//!   - a specific task exists and is enabled (`\Microsoft\Windows\Defrag\ScheduledDefrag`)
//!   - a task last ran within the last N days
//!   - a task's last result is 0 (success)
//!
//! Task identification requires splitting the caller-supplied path on
//! the last backslash: everything before becomes `-TaskPath` (note the
//! required trailing backslash), and the leaf becomes `-TaskName`.
//! Root-level tasks have an empty parent; for them we emit `-TaskPath '\\'`.
//!
//! Not-found: `Get-ScheduledTask` with `-ErrorAction SilentlyContinue`
//! returns `$null`. We emit empty stdout in that case -> exists=false.
//!
//! State enum (System.Int32 on the wire):
//!   0 = Unknown
//!   1 = Disabled
//!   2 = Queued
//!   3 = Ready
//!   4 = Running
//!
//! Date fields (LastRunTime, NextRunTime) serialize as
//! `/Date(<ms>)/` wire-format strings, same as Get-HotFix's InstalledOn.

use serde::Deserialize;

const MAX_PATH_LEN: usize = 1024;

/// Validate a task path before string-interpolation into a PowerShell
/// `-Command` body. Must start with `\` and consist of reasonable
/// path-name characters. Rejects anything that carries meaning to
/// PowerShell's single-quoted string parser.
pub fn is_safe_task_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return false;
    }
    if !path.starts_with('\\') {
        return false;
    }
    if path.contains("$(") || path.contains("${") {
        return false;
    }
    path.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '\\' | '/' | ' ' | '.' | '-' | '_' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
}

/// Split a full task path into `(parent, leaf)` on the last backslash.
/// Root-level tasks (`\ScheduledDefrag`) yield `("", "ScheduledDefrag")`.
/// An empty leaf or missing separator yields None.
pub fn split_task_path(path: &str) -> Option<(String, String)> {
    let idx = path.rfind('\\')?;
    let parent = &path[..idx];
    let leaf = &path[idx + 1..];
    if leaf.is_empty() {
        return None;
    }
    Some((parent.to_string(), leaf.to_string()))
}

/// Build the PowerShell command body. On not-found, emits empty
/// stdout. On success, emits a single JSON object with keys: Exists,
/// State (int), Author, Description, LastRunTime, NextRunTime,
/// LastTaskResult.
pub fn build_get_scheduled_task_command(path: &str) -> String {
    // The caller is expected to have validated `path` already.
    let (parent, leaf) = match split_task_path(path) {
        Some(p) => p,
        None => {
            // Should not happen - collector validates first. Emit a
            // body that produces empty stdout so downstream parses it
            // as not-found rather than failing on malformed JSON.
            return "Write-Output ''".to_string();
        }
    };
    // Get-ScheduledTask wants the parent path with a trailing
    // backslash. For root-level tasks, parent is "" and we need "\".
    let task_path = if parent.is_empty() {
        "\\".to_string()
    } else {
        format!("{}\\", parent)
    };
    format!(
        "$t = Get-ScheduledTask -TaskPath '{task_path}' -TaskName '{leaf}' -ErrorAction SilentlyContinue; \
         if ($null -eq $t) {{ Write-Output ''; exit 0 }}; \
         $i = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; \
         [PSCustomObject]@{{ \
           Exists = $true; \
           State = [int]$t.State; \
           Author = $t.Author; \
           Description = $t.Description; \
           LastRunTime = $i.LastRunTime; \
           NextRunTime = $i.NextRunTime; \
           LastTaskResult = $i.LastTaskResult \
         }} | ConvertTo-Json -Compress"
    )
}

/// Decode the `State` integer into its canonical string name.
pub fn decode_task_state(state: i64) -> &'static str {
    match state {
        0 => "Unknown",
        1 => "Disabled",
        2 => "Queued",
        3 => "Ready",
        4 => "Running",
        _ => "Unknown",
    }
}

/// Raw Get-ScheduledTask / Get-ScheduledTaskInfo record.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawScheduledTask {
    #[serde(rename = "Exists")]
    pub exists: Option<bool>,
    #[serde(rename = "State")]
    pub state: Option<i64>,
    #[serde(rename = "Author")]
    pub author: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "LastRunTime")]
    pub last_run_time: Option<String>,
    #[serde(rename = "NextRunTime")]
    pub next_run_time: Option<String>,
    #[serde(rename = "LastTaskResult")]
    pub last_task_result: Option<i64>,
}

impl RawScheduledTask {
    pub fn is_found(&self) -> bool {
        self.exists == Some(true)
    }
}

/// Parse the JSON emitted by `build_get_scheduled_task_command`.
pub fn parse_scheduled_task_json(text: &str) -> Result<RawScheduledTask, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(RawScheduledTask::default());
    }
    serde_json::from_str::<RawScheduledTask>(trimmed)
        .map_err(|e| format!("parse_scheduled_task_json: {} (input='{}')", e, trimmed))
}

/// Parse a PowerShell wire-format date string like `/Date(1711742400000)/`
/// into raw milliseconds since epoch. Duplicated here rather than
/// imported so the scheduled-task module stays independent of
/// `get_hotfix`.
pub fn parse_ps_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let inner = s.strip_prefix("/Date(")?.strip_suffix(")/")?;
    let digits_end = inner
        .char_indices()
        .find(|(i, c)| *i > 0 && (*c == '+' || *c == '-'))
        .map(|(i, _)| i)
        .unwrap_or(inner.len());
    inner[..digits_end].parse::<i64>().ok()
}

/// Compute the whole number of days between two ms-since-epoch
/// timestamps. Positive when `past_ms` is before `now_ms`, negative
/// when `past_ms` is after `now_ms` (a future scheduled run).
pub fn days_delta_ms(now_ms: i64, other_ms: i64) -> i64 {
    (now_ms - other_ms) / 86_400_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_task_paths() {
        assert!(is_safe_task_path(r"\Microsoft\Windows\Defrag\ScheduledDefrag"));
        assert!(is_safe_task_path(r"\Microsoft\Windows\Defender\Windows Defender Scheduled Scan"));
        assert!(is_safe_task_path(r"\RootTask"));
    }

    #[test]
    fn rejects_injection_task_paths() {
        assert!(!is_safe_task_path(""));
        assert!(!is_safe_task_path(r"Microsoft\Windows"));
        assert!(!is_safe_task_path(r"\$(whoami)"));
        assert!(!is_safe_task_path(r"\${evil}"));
        assert!(!is_safe_task_path("\\'evil"));
        assert!(!is_safe_task_path("\\`x`"));
        assert!(!is_safe_task_path(r"\a;b"));
        assert!(!is_safe_task_path(r"\a|b"));
        assert!(!is_safe_task_path("\\x\n"));
    }

    #[test]
    fn splits_nested_task_path() {
        let (p, l) = split_task_path(r"\Microsoft\Windows\Defrag\ScheduledDefrag").unwrap();
        assert_eq!(p, r"\Microsoft\Windows\Defrag");
        assert_eq!(l, "ScheduledDefrag");
    }

    #[test]
    fn splits_root_task_path() {
        let (p, l) = split_task_path(r"\ScheduledDefrag").unwrap();
        assert_eq!(p, "");
        assert_eq!(l, "ScheduledDefrag");
    }

    #[test]
    fn split_rejects_trailing_separator() {
        assert!(split_task_path(r"\Microsoft\").is_none());
    }

    #[test]
    fn decodes_task_state_values() {
        assert_eq!(decode_task_state(0), "Unknown");
        assert_eq!(decode_task_state(1), "Disabled");
        assert_eq!(decode_task_state(2), "Queued");
        assert_eq!(decode_task_state(3), "Ready");
        assert_eq!(decode_task_state(4), "Running");
        assert_eq!(decode_task_state(99), "Unknown");
    }

    #[test]
    fn parses_ps_date_basic() {
        assert_eq!(parse_ps_date("/Date(1711742400000)/"), Some(1711742400000));
        assert_eq!(
            parse_ps_date("/Date(1711742400000-0400)/"),
            Some(1711742400000)
        );
        assert_eq!(parse_ps_date(""), None);
        assert_eq!(parse_ps_date("/Date(bogus)/"), None);
    }

    #[test]
    fn days_delta_ms_fixed_now() {
        let now: i64 = 1_800_000_000_000;
        // 1 day ago
        assert_eq!(days_delta_ms(now, now - 86_400_000), 1);
        // Exactly same instant
        assert_eq!(days_delta_ms(now, now), 0);
        // 2 days in the future = -2 days ago
        assert_eq!(days_delta_ms(now, now + 2 * 86_400_000), -2);
    }

    #[test]
    fn parses_scheduled_task_json_full() {
        let json = r#"{
            "Exists":true,
            "State":3,
            "Author":"Microsoft Corporation",
            "Description":"Runs defrag on a schedule",
            "LastRunTime":"/Date(1711742400000)/",
            "NextRunTime":"/Date(1712347200000)/",
            "LastTaskResult":0
        }"#;
        let t = parse_scheduled_task_json(json).expect("parse");
        assert!(t.is_found());
        assert_eq!(t.state, Some(3));
        assert_eq!(t.author.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(t.last_run_time.as_deref(), Some("/Date(1711742400000)/"));
        assert_eq!(t.next_run_time.as_deref(), Some("/Date(1712347200000)/"));
        assert_eq!(t.last_task_result, Some(0));
    }

    #[test]
    fn parses_scheduled_task_not_found() {
        let t = parse_scheduled_task_json("").expect("parse");
        assert!(!t.is_found());
    }

    #[test]
    fn command_builder_for_nested_task() {
        let cmd = build_get_scheduled_task_command(r"\Microsoft\Windows\Defrag\ScheduledDefrag");
        assert!(cmd.contains("Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Defrag\\'"));
        assert!(cmd.contains("-TaskName 'ScheduledDefrag'"));
        assert!(cmd.contains("Get-ScheduledTaskInfo"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    #[test]
    fn command_builder_for_root_task() {
        let cmd = build_get_scheduled_task_command(r"\RootTask");
        assert!(cmd.contains("Get-ScheduledTask -TaskPath '\\'"));
        assert!(cmd.contains("-TaskName 'RootTask'"));
    }
}
