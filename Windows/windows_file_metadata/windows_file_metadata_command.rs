//! Get-Item + Get-Acl helpers (Windows file/directory metadata enumeration)
//!
//! Single executor backend: `Get-Item <path>` (plus `Get-Acl <path>` for
//! owner SID resolution) via PowerShell. Missing paths raise
//! `System.Management.Automation.ItemNotFoundException`; we catch it to
//! emit `{}` -> exists=false.
//!
//! All STIG-relevant attributes come from `$item.Attributes` bit tests
//! against `[System.IO.FileAttributes]`. Owner (friendly) and owner_id
//! (SID) come from a secondary `Get-Acl` call with `.Translate()` to a
//! `SecurityIdentifier` - we fall back to parsing the `O:` segment of
//! the SDDL if translation throws.
//!
//! `writable` here is a ReadOnly-attribute heuristic, NOT an ACL-based
//! write check - true ACL writability belongs on `windows_file_acl`.

use serde::Deserialize;

// Re-export the path validator from get_file_acl - same ruleset.
pub use crate::contract_kit::commands::get_file_acl::is_safe_path;

/// Build the PowerShell command body. On not-found, returns `{}`.
/// On success, returns a single JSON object with file metadata keys.
pub fn build_get_file_metadata_command(path: &str) -> String {
    // Single-quoted PS string literal for the path. Caller must have
    // validated via is_safe_path (rejects single quote).
    //
    // -LiteralPath prevents bracket/dollar glob interpretation.
    //
    // Attribute bit tests use [System.IO.FileAttributes] enum values.
    //
    // Owner resolution is a separate try-block: Get-Acl can fail even
    // when Get-Item succeeds (e.g. files the caller can enumerate but
    // not read security on). A failed Get-Acl leaves Owner/OwnerId null
    // and captures the exception message in OwnerError so downstream
    // policies can distinguish "ACL unreadable" from "file has no owner".
    format!(
        "try {{ $item = Get-Item -LiteralPath '{path}' -Force -ErrorAction Stop }} \
         catch [System.Management.Automation.ItemNotFoundException] {{ \
           Write-Output '{{}}'; exit 0 }} \
         catch {{ Write-Output '{{}}'; exit 0 }}; \
         $attrs = $item.Attributes; \
         $isDir = $item.PSIsContainer; \
         $isHidden = [bool]($attrs -band [System.IO.FileAttributes]::Hidden); \
         $isSystem = [bool]($attrs -band [System.IO.FileAttributes]::System); \
         $isReadOnly = [bool]($attrs -band [System.IO.FileAttributes]::ReadOnly); \
         $isArchive = [bool]($attrs -band [System.IO.FileAttributes]::Archive); \
         $size = if ($isDir) {{ 0 }} else {{ [int64]$item.Length }}; \
         $attrString = $attrs.ToString(); \
         $readable = $false; \
         try {{ \
           if ($isDir) {{ \
             $null = Get-ChildItem -LiteralPath '{path}' -Force -ErrorAction Stop | Select-Object -First 1; \
             $readable = $true \
           }} else {{ \
             $fs = [System.IO.File]::OpenRead('{path}'); \
             $fs.Close(); \
             $readable = $true \
           }} \
         }} catch {{ $readable = $false }}; \
         $writable = -not $isReadOnly; \
         $owner = $null; $ownerId = $null; $ownerError = $null; \
         try {{ \
           $acl = Get-Acl -LiteralPath '{path}' -ErrorAction Stop; \
           $owner = $acl.Owner; \
           try {{ \
             $sid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]); \
             $ownerId = $sid.Value \
           }} catch {{ \
             if ($acl.Sddl -match 'O:([^:DGSU]+)') {{ \
               $ownerId = $Matches[1] \
             }} \
           }} \
         }} catch {{ $ownerError = $_.Exception.Message }}; \
         [PSCustomObject]@{{ \
           Exists = $true; \
           Path = '{path}'; \
           IsDirectory = $isDir; \
           Size = $size; \
           IsHidden = $isHidden; \
           IsSystem = $isSystem; \
           IsReadonly = $isReadOnly; \
           IsArchive = $isArchive; \
           Attributes = $attrString; \
           Readable = $readable; \
           Writable = $writable; \
           Owner = $owner; \
           OwnerId = $ownerId; \
           OwnerError = $ownerError \
         }} | ConvertTo-Json -Compress"
    )
}

/// Raw file-metadata record.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawFileMetadata {
    #[serde(rename = "Exists")]
    pub exists: Option<bool>,
    #[serde(rename = "Path")]
    pub path: Option<String>,
    #[serde(rename = "IsDirectory")]
    pub is_directory: Option<bool>,
    #[serde(rename = "Size")]
    pub size: Option<i64>,
    #[serde(rename = "IsHidden")]
    pub is_hidden: Option<bool>,
    #[serde(rename = "IsSystem")]
    pub is_system: Option<bool>,
    #[serde(rename = "IsReadonly")]
    pub is_readonly: Option<bool>,
    #[serde(rename = "IsArchive")]
    pub is_archive: Option<bool>,
    #[serde(rename = "Attributes")]
    pub attributes: Option<String>,
    #[serde(rename = "Readable")]
    pub readable: Option<bool>,
    #[serde(rename = "Writable")]
    pub writable: Option<bool>,
    #[serde(rename = "Owner")]
    pub owner: Option<String>,
    #[serde(rename = "OwnerId")]
    pub owner_id: Option<String>,
    #[serde(rename = "OwnerError")]
    pub owner_error: Option<String>,
}

impl RawFileMetadata {
    /// True iff `Exists` was set by the PS command (not-found returns
    /// `{}` which leaves this None).
    pub fn is_found(&self) -> bool {
        self.exists == Some(true)
    }
}

/// Parse the JSON emitted by `build_get_file_metadata_command`.
pub fn parse_file_metadata_json(text: &str) -> Result<RawFileMetadata, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(RawFileMetadata::default());
    }
    serde_json::from_str::<RawFileMetadata>(trimmed)
        .map_err(|e| format!("parse_file_metadata_json: {} (input='{}')", e, trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_metadata_record() {
        let json = r#"{
            "Exists":true,
            "Path":"C:\\Windows\\System32\\drivers\\etc\\hosts",
            "IsDirectory":false,
            "Size":824,
            "IsHidden":false,
            "IsSystem":false,
            "IsReadonly":false,
            "IsArchive":true,
            "Attributes":"Archive",
            "Readable":true,
            "Writable":true,
            "Owner":"NT SERVICE\\TrustedInstaller",
            "OwnerId":"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        }"#;
        let m = parse_file_metadata_json(json).expect("parse");
        assert!(m.is_found());
        assert_eq!(m.is_directory, Some(false));
        assert_eq!(m.size, Some(824));
        assert_eq!(m.is_hidden, Some(false));
        assert_eq!(m.is_system, Some(false));
        assert_eq!(m.is_readonly, Some(false));
        assert_eq!(m.is_archive, Some(true));
        assert_eq!(m.attributes.as_deref(), Some("Archive"));
        assert_eq!(m.readable, Some(true));
        assert_eq!(m.writable, Some(true));
        assert_eq!(m.owner.as_deref(), Some("NT SERVICE\\TrustedInstaller"));
        assert!(m.owner_id.as_deref().unwrap().starts_with("S-1-5-"));
    }

    #[test]
    fn parses_not_found_shape() {
        let m = parse_file_metadata_json("{}").expect("parse");
        assert!(!m.is_found());
        assert_eq!(m.exists, None);
    }

    #[test]
    fn parses_empty_input() {
        let m = parse_file_metadata_json("").expect("parse");
        assert!(!m.is_found());
    }

    #[test]
    fn parses_directory_record() {
        let json = r#"{
            "Exists":true,
            "Path":"C:\\Windows\\System32\\drivers\\etc",
            "IsDirectory":true,
            "Size":0,
            "IsHidden":false,
            "IsSystem":false,
            "IsReadonly":false,
            "IsArchive":false,
            "Attributes":"Directory",
            "Readable":true,
            "Writable":true,
            "Owner":"NT SERVICE\\TrustedInstaller",
            "OwnerId":"S-1-5-18"
        }"#;
        let m = parse_file_metadata_json(json).expect("parse");
        assert!(m.is_found());
        assert_eq!(m.is_directory, Some(true));
        assert_eq!(m.size, Some(0));
    }

    #[test]
    fn command_builder_embeds_path_and_get_item() {
        let cmd = build_get_file_metadata_command(r"C:\Windows\System32\drivers\etc\hosts");
        assert!(cmd.contains(r"C:\Windows\System32\drivers\etc\hosts"));
        assert!(cmd.contains("Get-Item"));
        assert!(cmd.contains("-LiteralPath"));
        assert!(cmd.contains("ItemNotFoundException"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    #[test]
    fn parses_owner_error_when_acl_unreadable() {
        let json = r#"{
            "Exists":true,
            "Path":"C:\\Windows\\System32\\config\\SAM",
            "IsDirectory":false,
            "Size":65536,
            "IsHidden":true,
            "IsSystem":true,
            "IsReadonly":false,
            "IsArchive":true,
            "Attributes":"Hidden, System, Archive",
            "Readable":false,
            "Writable":true,
            "Owner":null,
            "OwnerId":null,
            "OwnerError":"Attempted to perform an unauthorized operation."
        }"#;
        let m = parse_file_metadata_json(json).expect("parse");
        assert!(m.is_found());
        assert_eq!(m.owner, None);
        assert_eq!(m.owner_id, None);
        assert_eq!(
            m.owner_error.as_deref(),
            Some("Attempted to perform an unauthorized operation.")
        );
    }

    #[test]
    fn command_builder_captures_acl_exception_message() {
        let cmd = build_get_file_metadata_command(r"C:\Windows\System32\config\SAM");
        assert!(cmd.contains("$ownerError"));
        assert!(cmd.contains("$_.Exception.Message"));
        assert!(cmd.contains("OwnerError = $ownerError"));
    }

    #[test]
    fn command_builder_translates_owner_to_sid() {
        let cmd = build_get_file_metadata_command(r"C:\Windows\System32\cmd.exe");
        assert!(cmd.contains("SecurityIdentifier"));
        assert!(cmd.contains("Get-Acl"));
    }

    #[test]
    fn reuses_safe_path_validator_from_file_acl() {
        // Sanity: the re-exported is_safe_path still rejects injection.
        assert!(is_safe_path(r"C:\Windows\System32\cmd.exe"));
        assert!(!is_safe_path(r"C:\$(whoami)"));
        assert!(!is_safe_path(""));
    }
}
