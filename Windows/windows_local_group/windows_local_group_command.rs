// === get_local_group.rs ===

//! Get-LocalGroup / Win32_Group helpers (Windows local group enumeration)
//!
//! Two executor backends:
//!
//! - **powershell** (default): `Get-LocalGroup` + `Get-LocalGroupMember`.
//!   Exposes `PrincipalSource` (Local / ActiveDirectory / AzureAD /
//!   MicrosoftAccount / Unknown) which is the STIG-relevant distinction
//!   between legitimate-local vs federated members.
//!
//! - **cim**: `Win32_Group` + `Win32_GroupUser` association. No
//!   PrincipalSource; adds `SIDType` (1=user, 2=group, 4=alias,
//!   5=well-known).
//!
//! SID-matching mode (`match_by_sid=true`) treats the `name` object
//! field as a full SID (`S-1-5-32-544`) and resolves via SID match —
//! handles localized group names (e.g. "Administratoren" on de-DE).
//!
//! Two PS 5.1 quirks to avoid in the generated command:
//! - `Get-LocalGroupMember ... | Select-Object -First N` raises
//!   PipelineStoppedException on stderr.
//! - `,@(Get-LocalGroupMember ...)` (force-array prefix) same.
//! Safer pattern: `@(Get-LocalGroupMember ... | Select-Object ...)`.

use serde::Deserialize;

const MAX_NAME_LEN: usize = 256;

/// Validate a group name or SID before string-interpolation into a
/// PowerShell `-Command` body. Group names allow the same character set
/// as account names plus the space character (Windows local group names
/// commonly contain spaces, e.g. `"Backup Operators"`).
/// SIDs (when `match_by_sid=true`) match the `S-1-...` pattern.
pub fn is_safe_group_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return false;
    }
    name.chars().all(|c| {
        c.is_alphanumeric()
            || c == '.'
            || c == '_'
            || c == '-'
            || c == '$'
            || c == ' '
    })
}

/// Validate a SID string. Format: `S-1-<auth>-<sub>[-<sub>...]`.
pub fn is_safe_sid(sid: &str) -> bool {
    if !sid.starts_with("S-1-") || sid.len() > MAX_NAME_LEN {
        return false;
    }
    sid.chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == 'S')
}

/// Build the PowerShell command body for the `powershell` executor.
///
/// Emits either `{}` (group not found) or a single JSON object with
/// denormalised comma-joined member lists — member names, SIDs,
/// ObjectClasses, and PrincipalSources each as a comma-separated
/// string.
pub fn build_get_localgroup_command(name_or_sid: &str, match_by_sid: bool) -> String {
    let selector = if match_by_sid {
        format!(
            "$g = Get-LocalGroup | Where-Object {{ $_.SID.Value -eq '{}' }} | Select-Object -First 1",
            name_or_sid
        )
    } else {
        format!(
            "try {{ $g = Get-LocalGroup -Name '{}' -ErrorAction Stop }} \
             catch [Microsoft.PowerShell.Commands.GroupNotFoundException] {{ $g = $null }}",
            name_or_sid
        )
    };

    // Note: avoid `-First N` and `,@()` force-array on Get-LocalGroupMember
    // to dodge the PS 5.1 PipelineStoppedException bug.
    format!(
        "{}; \
         if ($null -eq $g) {{ Write-Output '{{}}' }} else {{ \
           try {{ \
             $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | \
               Select-Object Name,\
                 @{{N='SID';E={{$_.SID.Value}}}},\
                 ObjectClass,\
                 @{{N='PrincipalSource';E={{$_.PrincipalSource.ToString()}}}}) \
           }} catch {{ $members = @() }}; \
           [PSCustomObject]@{{ \
             Name = $g.Name; \
             Description = $g.Description; \
             SID = $g.SID.Value; \
             MemberCount = $members.Count; \
             Members = (@($members | ForEach-Object {{ $_.Name }}) -join ','); \
             MemberSids = (@($members | ForEach-Object {{ $_.SID }}) -join ','); \
             MemberClasses = (@($members | ForEach-Object {{ $_.ObjectClass }}) -join ','); \
             MemberSources = (@($members | ForEach-Object {{ $_.PrincipalSource }}) -join ',') \
           }} | ConvertTo-Json -Depth 2 -Compress \
         }}",
        selector
    )
}

/// Build the PowerShell command body for the `cim` executor.
pub fn build_cim_group_command(name_or_sid: &str, match_by_sid: bool) -> String {
    let selector = if match_by_sid {
        format!(
            "$g = Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=TRUE' | \
             Where-Object {{ $_.SID -eq '{}' }} | Select-Object -First 1",
            name_or_sid
        )
    } else {
        format!(
            "$g = Get-CimInstance -ClassName Win32_Group \
             -Filter \"LocalAccount=TRUE AND Name='{}'\" | Select-Object -First 1",
            name_or_sid
        )
    };

    // Win32_GroupUser is an association class; ResultRole=PartComponent
    // returns the user/group members. SIDType 1=user, 2=group, 3=domain,
    // 4=alias/builtin, 5=well-known.
    format!(
        "{}; \
         if ($null -eq $g) {{ Write-Output '{{}}' }} else {{ \
           try {{ \
             $members = @($g | Get-CimAssociatedInstance -Association Win32_GroupUser | \
               Select-Object Name,Domain,SID,SIDType,\
                 @{{N='FullName';E={{\"$($_.Domain)\\\\$($_.Name)\"}}}}) \
           }} catch {{ $members = @() }}; \
           [PSCustomObject]@{{ \
             Name = $g.Name; \
             Description = $g.Description; \
             SID = $g.SID; \
             MemberCount = $members.Count; \
             Members = (@($members | ForEach-Object {{ $_.FullName }}) -join ','); \
             MemberSids = (@($members | ForEach-Object {{ $_.SID }}) -join ','); \
             MemberClasses = (@($members | ForEach-Object {{ \
               switch ($_.SIDType) {{ 1 {{'User'}} 2 {{'Group'}} \
                                      3 {{'Domain'}} 4 {{'Alias'}} \
                                      5 {{'WellKnown'}} default {{'Unknown'}} }} \
             }}) -join ','); \
             MemberSources = '' \
           }} | ConvertTo-Json -Depth 2 -Compress \
         }}",
        selector
    )
}

/// Denormalised group record — members flattened to comma-joined
/// strings by the PS command so the Rust side doesn't have to walk
/// nested structures.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct LocalGroupRecord {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "SID")]
    pub sid: Option<String>,
    #[serde(rename = "MemberCount")]
    pub member_count: Option<i64>,
    #[serde(rename = "Members")]
    pub members: Option<String>,
    #[serde(rename = "MemberSids")]
    pub member_sids: Option<String>,
    #[serde(rename = "MemberClasses")]
    pub member_classes: Option<String>,
    #[serde(rename = "MemberSources")]
    pub member_sources: Option<String>,
}

impl LocalGroupRecord {
    /// True iff the PS command emitted a populated record. An empty
    /// `{}` means the group was not found.
    pub fn is_found(&self) -> bool {
        !self.name.is_empty()
    }
}

/// Parse the JSON emitted by `build_get_localgroup_command` or
/// `build_cim_group_command`. The PS command always emits a single
/// object (or `{}` for not-found) — never an array.
pub fn parse_group_json(text: &str) -> Result<LocalGroupRecord, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(LocalGroupRecord::default());
    }
    serde_json::from_str::<LocalGroupRecord>(trimmed)
        .map_err(|e| format!("parse_group_json: {} (input='{}')", e, trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_group_names() {
        assert!(is_safe_group_identifier("Administrators"));
        assert!(is_safe_group_identifier("Backup Operators"));
        assert!(is_safe_group_identifier("Remote Desktop Users"));
        assert!(is_safe_group_identifier("IIS_IUSRS"));
        assert!(is_safe_group_identifier("Hyper-V Administrators"));
    }

    #[test]
    fn rejects_unsafe_group_names() {
        assert!(!is_safe_group_identifier(""));
        assert!(!is_safe_group_identifier("a'; rm -rf /"));
        assert!(!is_safe_group_identifier("a`b"));
        assert!(!is_safe_group_identifier("a\"b"));
        assert!(!is_safe_group_identifier("a$(whoami)"));
        assert!(!is_safe_group_identifier("a;b"));
    }

    #[test]
    fn accepts_valid_sids() {
        assert!(is_safe_sid("S-1-5-32-544"));
        assert!(is_safe_sid("S-1-5-32-545"));
        assert!(is_safe_sid("S-1-5-21-3719225790-1524408702-1566890666-500"));
    }

    #[test]
    fn rejects_invalid_sids() {
        assert!(!is_safe_sid("Administrators"));
        assert!(!is_safe_sid("S-1-5-'; evil"));
        assert!(!is_safe_sid(""));
    }

    #[test]
    fn parses_full_group_record() {
        let json = r#"{
            "Name":"Administrators",
            "Description":"Administrators have complete access",
            "SID":"S-1-5-32-544",
            "MemberCount":1,
            "Members":"win-server2022\\azureadmin",
            "MemberSids":"S-1-5-21-X-500",
            "MemberClasses":"User",
            "MemberSources":"Local"
        }"#;
        let r = parse_group_json(json).expect("parse");
        assert!(r.is_found());
        assert_eq!(r.name, "Administrators");
        assert_eq!(r.member_count, Some(1));
        assert_eq!(r.members.as_deref(), Some("win-server2022\\azureadmin"));
        assert_eq!(r.member_sids.as_deref(), Some("S-1-5-21-X-500"));
        assert_eq!(r.member_classes.as_deref(), Some("User"));
        assert_eq!(r.member_sources.as_deref(), Some("Local"));
    }

    #[test]
    fn parses_empty_group() {
        let json = r#"{
            "Name":"Backup Operators",
            "Description":"can override security restrictions",
            "SID":"S-1-5-32-551",
            "MemberCount":0,
            "Members":"",
            "MemberSids":"",
            "MemberClasses":"",
            "MemberSources":""
        }"#;
        let r = parse_group_json(json).expect("parse");
        assert!(r.is_found());
        assert_eq!(r.member_count, Some(0));
        assert_eq!(r.members.as_deref(), Some(""));
    }

    #[test]
    fn parses_not_found_shape() {
        let r = parse_group_json("{}").expect("parse");
        assert!(!r.is_found());
        assert_eq!(r.name, "");
    }

    #[test]
    fn parses_multi_member_group() {
        // Users group with two foreign principals (typical Win2022 default)
        let json = r#"{
            "Name":"Users","Description":"","SID":"S-1-5-32-545",
            "MemberCount":2,
            "Members":"NT AUTHORITY\\Authenticated Users,NT AUTHORITY\\INTERACTIVE",
            "MemberSids":"S-1-5-11,S-1-5-4",
            "MemberClasses":"Group,Group",
            "MemberSources":"Unknown,Unknown"
        }"#;
        let r = parse_group_json(json).expect("parse");
        assert_eq!(r.member_count, Some(2));
        assert_eq!(
            r.member_sids.as_deref(),
            Some("S-1-5-11,S-1-5-4")
        );
    }

    #[test]
    fn command_builders_match_expected_patterns() {
        let ps = build_get_localgroup_command("Administrators", false);
        assert!(ps.contains("Get-LocalGroup -Name 'Administrators'"));
        assert!(ps.contains("GroupNotFoundException"));
        assert!(ps.contains("Get-LocalGroupMember"));
        assert!(!ps.contains(",@(")); // avoid the PS 5.1 pipeline-stop bug
        assert!(!ps.contains("-First "));

        let ps_sid = build_get_localgroup_command("S-1-5-32-544", true);
        assert!(ps_sid.contains("SID.Value -eq 'S-1-5-32-544'"));

        let cim = build_cim_group_command("Administrators", false);
        assert!(cim.contains("Win32_Group"));
        assert!(cim.contains("Win32_GroupUser"));
        assert!(cim.contains("Name='Administrators'"));

        let cim_sid = build_cim_group_command("S-1-5-32-544", true);
        assert!(cim_sid.contains("SID -eq 'S-1-5-32-544'"));
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
