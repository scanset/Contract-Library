//! Get-Acl helpers (Windows file/directory ACL enumeration)
//!
//! Single executor backend: `Get-Acl <path>` via PowerShell. Missing
//! paths raise `System.Management.Automation.ItemNotFoundException`
//! (FullyQualifiedErrorId `GetAcl_PathNotFound_Exception`); we catch it
//! to emit `{}` -> exists=false.
//!
//! Shape surprises captured from live Win2022 probes:
//!
//! - `IdentityReference` serializes as a **nested object** `{"Value":"..."}`.
//!   We flatten it in the Select-Object projection.
//! - `AccessControlType` serializes as an int: `0`=Allow, `1`=Deny.
//!   We translate to strings in PS.
//! - `FileSystemRights` serializes as an **int bitmask**, NOT a string
//!   or enum-name list. Values range from well-known combinations
//!   (2032127=FullControl, 1179817=ReadAndExecute+Synchronize) to raw
//!   generic masks that don't appear in the FileSystemRights enum at
//!   all (0x10000000=GenericAll, 0x80000000=GenericRead,
//!   0xA0000000=GenericRead+GenericExecute).
//! - Generic flags appear on real inherited ACEs. Decoding them
//!   correctly is essential for meaningful STIG assertions - otherwise
//!   the `rights` field shows `"-1610612736"` instead of
//!   `"ReadAndExecute, Synchronize"`.
//!
//! Rights decoding is done Rust-side (not in PS) so the generic-flag
//! translation table is version-controlled with the rest of the parser.

use serde::Deserialize;

const MAX_PATH_LEN: usize = 1024;

/// Validate a path before string-interpolation into a PowerShell
/// `-Command` body. Windows paths are permissive (drive letters, UNC,
/// spaces, dots, parens, dashes) but we reject anything that could
/// break out of the single-quoted string context or inject commands.
pub fn is_safe_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return false;
    }
    // Reject PS subexpression / variable-braced expansion as a substring.
    // Bare `$` and bare `(` `)` `{` `}` each need to stay allowed
    // (admin shares like `admin$`, filenames like `file (1).txt`), but
    // their combinations `$(` and `${` are always injection vectors.
    if path.contains("$(") || path.contains("${") {
        return false;
    }
    // Allow: letters, digits, path separators, drive colon, spaces,
    // dots, parens, brackets, braces, underscore, hyphen, dollar (for
    // admin shares), comma. Reject: single quote, backtick, ;, |, &,
    // newline, double quote - all carry meaning to PS's single-quote
    // string parser or the command pipeline.
    path.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '\\' | '/' | ':' | ' ' | '.' | '(' | ')' | '_' | '-' | '$' | '[' | ']' | '{' | '}' | ','
            )
    })
}

/// Build the PowerShell command body. On not-found, returns `{}`.
/// On success, returns a single JSON object with keys: Exists, Path,
/// Owner, Group, Sddl, InheritanceProtected, AceCount, Aces
/// (array of { Identity, Type, RightsMask, IsInherited, InheritanceFlags,
/// PropagationFlags }).
pub fn build_get_acl_command(path: &str) -> String {
    // Use single-quoted PS string literal for the path. Caller must
    // have validated via is_safe_path (rejects single quote).
    //
    // AccessControlType int->string: 0=Allow, 1=Deny. We translate in
    // PS to avoid a second lookup table on the Rust side.
    //
    // IdentityReference is flattened via $_.IdentityReference.Value.
    // That's a string like "NT AUTHORITY\\SYSTEM" or, for app-package
    // and unresolved SIDs, the bare SID string.
    format!(
        "try {{ $a = Get-Acl -Path '{path}' -ErrorAction Stop }} \
         catch [System.Management.Automation.ItemNotFoundException] {{ \
           Write-Output '{{}}'; exit 0 }} \
         catch {{ Write-Output '{{}}'; exit 0 }}; \
         $aces = @($a.Access | ForEach-Object {{ \
           [PSCustomObject]@{{ \
             Identity = $_.IdentityReference.Value; \
             Type = if ($_.AccessControlType -eq 0) {{ 'Allow' }} else {{ 'Deny' }}; \
             RightsMask = [int]$_.FileSystemRights; \
             IsInherited = $_.IsInherited; \
             InheritanceFlags = [int]$_.InheritanceFlags; \
             PropagationFlags = [int]$_.PropagationFlags \
           }} \
         }}); \
         [PSCustomObject]@{{ \
           Exists = $true; \
           Path = '{path}'; \
           Owner = $a.Owner; \
           Group = $a.Group; \
           Sddl = $a.Sddl; \
           InheritanceProtected = $a.AreAccessRulesProtected; \
           AceCount = $aces.Count; \
           Aces = $aces \
         }} | ConvertTo-Json -Depth 4 -Compress"
    )
}

/// Raw ACL root record.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawAcl {
    #[serde(rename = "Exists")]
    pub exists: Option<bool>,
    #[serde(rename = "Path")]
    pub path: Option<String>,
    #[serde(rename = "Owner")]
    pub owner: Option<String>,
    #[serde(rename = "Group")]
    pub group: Option<String>,
    #[serde(rename = "Sddl")]
    pub sddl: Option<String>,
    #[serde(rename = "InheritanceProtected")]
    pub inheritance_protected: Option<bool>,
    #[serde(rename = "AceCount")]
    pub ace_count: Option<i64>,
    #[serde(rename = "Aces")]
    pub aces: Vec<RawAce>,
}

impl RawAcl {
    /// True iff `Exists` was set by the PS command (not-found returns
    /// `{}` which leaves this None).
    pub fn is_found(&self) -> bool {
        self.exists == Some(true)
    }
}

/// A single Access Control Entry (ACE).
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawAce {
    #[serde(rename = "Identity")]
    pub identity: String,
    #[serde(rename = "Type")]
    pub ace_type: String, // "Allow" or "Deny"
    #[serde(rename = "RightsMask")]
    pub rights_mask: i64,
    #[serde(rename = "IsInherited")]
    pub is_inherited: Option<bool>,
    #[serde(rename = "InheritanceFlags")]
    pub inheritance_flags: Option<i64>,
    #[serde(rename = "PropagationFlags")]
    pub propagation_flags: Option<i64>,
}

/// Parse the JSON emitted by `build_get_acl_command`.
pub fn parse_acl_json(text: &str) -> Result<RawAcl, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(RawAcl::default());
    }
    serde_json::from_str::<RawAcl>(trimmed)
        .map_err(|e| format!("parse_acl_json: {} (input='{}')", e, trimmed))
}

// =======================================================================
// FileSystemRights decoder
// =======================================================================
//
// Two-layer strategy:
//
// 1. If the mask matches one of the canonical combinations (FullControl,
//    Modify+Sync, ReadAndExecute+Sync, ...) exactly, return the canonical
//    name. This is what `FileSystemRights.ToString()` would emit in PS
//    for the same value.
//
// 2. Otherwise, decompose bit-by-bit using the named flag constants.
//    Also translate raw Win32 GENERIC_* bits (upper nibble) into their
//    FILE_GENERIC_* equivalents when `decode_generic_flags` is true.

// Named right flags (subset of System.Security.AccessControl.FileSystemRights).
// Order matters: larger composites first so (Modify = Write+Read+Execute+Delete)
// is preferred over individual bits.
const FSR_FULL_CONTROL: i64 = 0x001f01ff; // 2032127
const FSR_MODIFY: i64 = 0x000301bf; // 197055 (Modify without Synchronize)
const FSR_READ_AND_EXECUTE: i64 = 0x000200a9; // 131241
const FSR_READ: i64 = 0x00020089; // 131209
const FSR_WRITE: i64 = 0x00000116; // 278
const FSR_SYNCHRONIZE: i64 = 0x00100000; // 1048576
const FSR_DELETE: i64 = 0x00010000; // 65536
const FSR_CHANGE_PERMISSIONS: i64 = 0x00040000; // 262144
const FSR_TAKE_OWNERSHIP: i64 = 0x00080000; // 524288
const FSR_DELETE_SUBDIRS: i64 = 0x00000040; // 64 (DeleteSubdirectoriesAndFiles)
const FSR_READ_PERMISSIONS: i64 = 0x00020000; // 131072

// Generic bits from WinNT.h (top nibble).
// All defined as positive i64 values. The JSON parser path converts
// PS-emitted negative i32 values (e.g. -2147483648 for 0x80000000) into
// the equivalent positive i64 via the `(mask as u32) as i64` normalisation
// in `decode_rights_mask`. Defining these constants as positive keeps
// the bitwise `&` tests correct - a sign-extended negative i64 constant
// would mis-match the normalised positive mask.
const GEN_READ: i64 = 0x80000000;
const GEN_WRITE: i64 = 0x40000000;
const GEN_EXECUTE: i64 = 0x20000000;
const GEN_ALL: i64 = 0x10000000;

// FILE_* generic mappings (from ntifs.h / WinNT.h).
// GenericRead translates to these bits OR'd together:
const FILE_GENERIC_READ: i64 = 0x00120089; // ReadData|ReadAttr|ReadEA|ReadPerm|Sync
const FILE_GENERIC_WRITE: i64 = 0x00120116; // Write|Append|WriteAttr|WriteEA|ReadPerm|Sync
const FILE_GENERIC_EXECUTE: i64 = 0x001200a0; // Execute|ReadAttr|ReadPerm|Sync
const FILE_ALL_ACCESS: i64 = 0x001f01ff; // = FullControl

/// Decode a `FileSystemRights` integer mask into a canonical string
/// like `"FullControl"` or `"ReadAndExecute, Synchronize"`. When
/// `decode_generic_flags` is true, generic Win32 bits are first
/// translated to their FILE_GENERIC_* equivalents.
pub fn decode_rights_mask(mask: i64, decode_generic_flags: bool) -> String {
    // Normalise the mask: PS serializes 0xA0000000 as negative i32
    // (-1610612736). Reinterpret via u32 to pick up the true unsigned
    // bit pattern.
    let normalised = (mask as u32) as i64;

    let effective = if decode_generic_flags {
        translate_generic_bits(normalised)
    } else {
        normalised
    };

    // Fast-path: exact canonical names.
    match effective {
        FSR_FULL_CONTROL => return "FullControl".to_string(),
        m if m == FSR_MODIFY | FSR_SYNCHRONIZE => return "Modify, Synchronize".to_string(),
        FSR_MODIFY => return "Modify".to_string(),
        m if m == FSR_READ_AND_EXECUTE | FSR_SYNCHRONIZE => {
            return "ReadAndExecute, Synchronize".to_string()
        }
        FSR_READ_AND_EXECUTE => return "ReadAndExecute".to_string(),
        m if m == FSR_READ | FSR_SYNCHRONIZE => return "Read, Synchronize".to_string(),
        FSR_READ => return "Read".to_string(),
        FSR_WRITE => return "Write".to_string(),
        FSR_SYNCHRONIZE => return "Synchronize".to_string(),
        0 => return "NoAccess".to_string(),
        _ => {}
    }

    // Fallback: bit-by-bit decomposition. Consume composites first so
    // the output uses the most compact canonical form.
    let mut names: Vec<&str> = Vec::new();
    let mut remaining = effective;

    let check = |remaining: &mut i64, names: &mut Vec<&'static str>, bit: i64, name: &'static str| {
        if (*remaining & bit) == bit {
            names.push(name);
            *remaining &= !bit;
        }
    };

    // Composites first.
    check(&mut remaining, &mut names, FSR_MODIFY, "Modify");
    check(&mut remaining, &mut names, FSR_READ_AND_EXECUTE, "ReadAndExecute");
    check(&mut remaining, &mut names, FSR_READ, "Read");
    check(&mut remaining, &mut names, FSR_WRITE, "Write");

    // Individual bits (only those not folded into composites above).
    check(&mut remaining, &mut names, FSR_SYNCHRONIZE, "Synchronize");
    check(&mut remaining, &mut names, FSR_DELETE, "Delete");
    check(&mut remaining, &mut names, FSR_CHANGE_PERMISSIONS, "ChangePermissions");
    check(&mut remaining, &mut names, FSR_TAKE_OWNERSHIP, "TakeOwnership");
    check(&mut remaining, &mut names, FSR_DELETE_SUBDIRS, "DeleteSubdirectoriesAndFiles");
    check(&mut remaining, &mut names, FSR_READ_PERMISSIONS, "ReadPermissions");

    // If generic bits survived translation (because decode_generic_flags=false),
    // label them.
    if !decode_generic_flags {
        if (remaining & GEN_ALL) == GEN_ALL {
            names.push("GenericAll");
            remaining &= !GEN_ALL;
        }
        if (remaining & GEN_READ) == GEN_READ {
            names.push("GenericRead");
            remaining &= !GEN_READ;
        }
        if (remaining & GEN_WRITE) == GEN_WRITE {
            names.push("GenericWrite");
            remaining &= !GEN_WRITE;
        }
        if (remaining & GEN_EXECUTE) == GEN_EXECUTE {
            names.push("GenericExecute");
            remaining &= !GEN_EXECUTE;
        }
    }

    if names.is_empty() {
        return format!("0x{:X}", effective);
    }
    if remaining != 0 {
        // Leftover bits -> append raw hex so callers can see something
        // unusual is present rather than silently swallowing it.
        let mut out = names.join(", ");
        out.push_str(&format!(", 0x{:X}", remaining));
        return out;
    }
    names.join(", ")
}

fn translate_generic_bits(mask: i64) -> i64 {
    let mut out = mask & 0x00ffffff; // strip generic bits
    if (mask & GEN_ALL) == GEN_ALL {
        out |= FILE_ALL_ACCESS;
    }
    if (mask & GEN_READ) == GEN_READ {
        out |= FILE_GENERIC_READ;
    }
    if (mask & GEN_WRITE) == GEN_WRITE {
        out |= FILE_GENERIC_WRITE;
    }
    if (mask & GEN_EXECUTE) == GEN_EXECUTE {
        out |= FILE_GENERIC_EXECUTE;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------ path safety
    #[test]
    fn accepts_common_paths() {
        assert!(is_safe_path(r"C:\Windows\System32\cmd.exe"));
        assert!(is_safe_path(r"C:\Program Files\app\bin\tool.exe"));
        assert!(is_safe_path(r"C:\Windows\System32\drivers\etc"));
        assert!(is_safe_path(r"\\server\share\path"));
        assert!(is_safe_path(r"D:\data\file (1).txt"));
        assert!(is_safe_path(r"C:\users\admin$\file"));
    }

    #[test]
    fn rejects_injection_paths() {
        assert!(!is_safe_path(""));
        assert!(!is_safe_path(r"C:\path\';evil"));
        assert!(!is_safe_path("C:\\`whoami`"));
        assert!(!is_safe_path(r"C:\$(whoami)"));
        assert!(!is_safe_path("C:\\\"injected"));
        assert!(!is_safe_path(r"C:\a;b"));
        assert!(!is_safe_path(r"C:\a|b"));
    }

    // ----------------------------------------------------- rights decoding
    #[test]
    fn decodes_full_control_exact() {
        assert_eq!(decode_rights_mask(2032127, true), "FullControl");
    }

    #[test]
    fn decodes_read_and_execute_synchronize() {
        assert_eq!(
            decode_rights_mask(1179817, true),
            "ReadAndExecute, Synchronize"
        );
    }

    #[test]
    fn decodes_modify_synchronize() {
        assert_eq!(decode_rights_mask(1245631, true), "Modify, Synchronize");
    }

    #[test]
    fn decodes_synchronize_only() {
        assert_eq!(decode_rights_mask(1048576, true), "Synchronize");
    }

    #[test]
    fn decodes_zero_as_no_access() {
        assert_eq!(decode_rights_mask(0, true), "NoAccess");
    }

    #[test]
    fn decodes_generic_all_when_enabled() {
        // 0x10000000 = GenericAll. Translated: FullControl.
        assert_eq!(decode_rights_mask(0x10000000, true), "FullControl");
    }

    #[test]
    fn decodes_generic_read_plus_execute_when_enabled() {
        // -1610612736 (PS-emitted i32 for 0xA0000000) translates to
        // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE = 0x001200a9
        // = ReadAndExecute, Synchronize.
        assert_eq!(
            decode_rights_mask(-1610612736, true),
            "ReadAndExecute, Synchronize"
        );
    }

    #[test]
    fn keeps_generic_bits_when_disabled() {
        // With decode_generic_flags=false, generic bits appear as named
        // "Generic*" labels rather than being translated.
        assert_eq!(decode_rights_mask(0x10000000, false), "GenericAll");
        let out = decode_rights_mask(-1610612736, false);
        assert!(out.contains("GenericRead"), "expected GenericRead in '{}'", out);
        assert!(out.contains("GenericExecute"), "expected GenericExecute in '{}'", out);
    }

    #[test]
    fn decodes_registry_like_mask_keeps_trailing_bits() {
        // 983103 = 0xF003F = registry KEY_ALL_ACCESS (different enum).
        // We don't model RegistryRights yet - for FileSystemRights this
        // is an unusual mask. The decoder should still produce something
        // meaningful rather than an empty string.
        let out = decode_rights_mask(983103, true);
        assert!(!out.is_empty());
    }

    // ------------------------------------------------------------- parsing
    #[test]
    fn parses_acl_json_full_record() {
        let json = r#"{
            "Exists":true,
            "Path":"C:\\Windows\\System32\\cmd.exe",
            "Owner":"NT SERVICE\\TrustedInstaller",
            "Group":"NT SERVICE\\TrustedInstaller",
            "Sddl":"O:S-1-5-...D:PAI(A;;0x1200a9;;;SY)",
            "InheritanceProtected":true,
            "AceCount":2,
            "Aces":[
                {"Identity":"NT AUTHORITY\\SYSTEM","Type":"Allow","RightsMask":1179817,
                 "IsInherited":false,"InheritanceFlags":0,"PropagationFlags":0},
                {"Identity":"NT SERVICE\\TrustedInstaller","Type":"Allow","RightsMask":2032127,
                 "IsInherited":false,"InheritanceFlags":0,"PropagationFlags":0}
            ]
        }"#;
        let acl = parse_acl_json(json).expect("parse");
        assert!(acl.is_found());
        assert_eq!(acl.owner.as_deref(), Some("NT SERVICE\\TrustedInstaller"));
        assert_eq!(acl.inheritance_protected, Some(true));
        assert_eq!(acl.ace_count, Some(2));
        assert_eq!(acl.aces.len(), 2);
        assert_eq!(acl.aces[0].identity, "NT AUTHORITY\\SYSTEM");
        assert_eq!(acl.aces[0].ace_type, "Allow");
        assert_eq!(acl.aces[0].rights_mask, 1179817);
        assert_eq!(acl.aces[1].rights_mask, 2032127);
    }

    #[test]
    fn parses_acl_not_found_shape() {
        let acl = parse_acl_json("{}").expect("parse");
        assert!(!acl.is_found());
        assert!(acl.aces.is_empty());
    }

    #[test]
    fn parses_acl_empty_input() {
        let acl = parse_acl_json("").expect("parse");
        assert!(!acl.is_found());
    }

    #[test]
    fn parses_negative_rights_mask_from_ps_i32() {
        // Real-world inherited ACE on BUILTIN\Users for
        // C:\Windows\System32\drivers\etc - PS emits -1610612736.
        let json = r#"{
            "Exists":true,"Path":"x","Owner":"SYSTEM","Group":"SYSTEM",
            "Sddl":"","InheritanceProtected":false,"AceCount":1,
            "Aces":[{"Identity":"BUILTIN\\Users","Type":"Allow",
                     "RightsMask":-1610612736,"IsInherited":true,
                     "InheritanceFlags":0,"PropagationFlags":0}]
        }"#;
        let acl = parse_acl_json(json).expect("parse");
        assert_eq!(acl.aces[0].rights_mask, -1610612736);
        assert_eq!(
            decode_rights_mask(acl.aces[0].rights_mask, true),
            "ReadAndExecute, Synchronize"
        );
    }

    // ----------------------------------------------------- command builder
    #[test]
    fn command_builder_embeds_path_and_catch() {
        let cmd = build_get_acl_command(r"C:\Windows\System32\cmd.exe");
        assert!(cmd.contains(r"Get-Acl -Path 'C:\Windows\System32\cmd.exe'"));
        assert!(cmd.contains("ItemNotFoundException"));
        assert!(cmd.contains("ConvertTo-Json"));
        assert!(cmd.contains("[int]$_.FileSystemRights"));
        assert!(cmd.contains("$_.IdentityReference.Value"));
    }
}
