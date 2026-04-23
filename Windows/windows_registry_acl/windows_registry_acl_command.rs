//! Get-Acl helpers for Windows registry keys
//!
//! Registry-key ACLs expose `RegistryRights` rather than
//! `FileSystemRights`. The named bits and canonical composites differ
//! from the filesystem enum (QueryValues/SetValue/CreateSubKey vs
//! Read/Write/Modify), so registry ACLs have their own decoder and
//! their own CTN.
//!
//! Single executor backend: positional `Get-Acl '<path>'` via PowerShell.
//! Windows PowerShell 5.1's `Get-Acl -LiteralPath` has a confirmed quirk
//! with registry-provider paths - the drive qualifier (HKLM:/Registry::)
//! is stripped during parameter binding, leading to spurious
//! `ItemNotFoundException` even on root-level keys that clearly exist.
//! Positional `Get-Acl` dispatches via the provider system correctly.
//! Wildcard exposure is bounded because `is_safe_key_path` rejects `*`
//! and `?` (brackets remain permitted but a mismatched pattern fails
//! cleanly as path-not-found rather than returning the wrong ACL).
//! Missing keys raise `System.Management.Automation.ItemNotFoundException`
//! (FullyQualifiedErrorId `GetAcl_PathNotFound_Exception`); we catch it
//! to emit `{}` -> exists=false.
//!
//! Shape surprises - same as file ACL:
//!
//! - `IdentityReference` serializes as a nested object `{"Value":"..."}`.
//!   We flatten via the Select-Object projection.
//! - `AccessControlType` is an int: 0=Allow, 1=Deny. We translate to
//!   strings in PS.
//! - `RegistryRights` is an int bitmask. Values range from canonical
//!   combinations (983103=FullControl, 131097=ReadKey, 131078=WriteKey)
//!   to generic-bit masks on inherited ACEs.
//!
//! For registry, Win32 GENERIC_EXECUTE maps to KEY_READ (registry has
//! no separate execute right). GENERIC_ALL maps to KEY_ALL_ACCESS.

use serde::Deserialize;

const MAX_PATH_LEN: usize = 1024;

/// Validate a registry key path before string-interpolation into a
/// PowerShell `-Command` body. Accepts both PS-provider form
/// (`HKLM:\SOFTWARE\Foo`) and native hive-prefix form
/// (`HKEY_LOCAL_MACHINE\SOFTWARE\Foo`). Rejects anything that could
/// break out of the single-quoted PS string context.
pub fn is_safe_key_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return false;
    }
    if path.contains("$(") || path.contains("${") {
        return false;
    }
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
pub fn build_get_registry_acl_command(path: &str) -> String {
    // Positional Get-Acl (NOT -LiteralPath). Windows PowerShell 5.1 strips
    // the drive qualifier from registry-provider paths when bound via
    // -LiteralPath, causing ItemNotFoundException on existing keys. Caller
    // must have validated via is_safe_key_path (rejects single quote and
    // wildcards * ?; brackets [ ] remain allowed for registry key names).
    format!(
        "try {{ $a = Get-Acl '{path}' -ErrorAction Stop }} \
         catch [System.Management.Automation.ItemNotFoundException] {{ \
           Write-Output '{{}}'; exit 0 }} \
         catch {{ Write-Output '{{}}'; exit 0 }}; \
         $aces = @($a.Access | ForEach-Object {{ \
           [PSCustomObject]@{{ \
             Identity = $_.IdentityReference.ToString(); \
             Type = if ($_.AccessControlType -eq 0) {{ 'Allow' }} else {{ 'Deny' }}; \
             RightsMask = [int]$_.RegistryRights; \
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
pub struct RawRegistryAcl {
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
    pub aces: Vec<RawRegistryAce>,
}

impl RawRegistryAcl {
    /// True iff `Exists` was set by the PS command (not-found returns
    /// `{}` which leaves this None).
    pub fn is_found(&self) -> bool {
        self.exists == Some(true)
    }
}

/// A single Access Control Entry (ACE).
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RawRegistryAce {
    #[serde(rename = "Identity")]
    pub identity: Option<String>,
    #[serde(rename = "Type")]
    pub ace_type: Option<String>, // "Allow" or "Deny"
    #[serde(rename = "RightsMask")]
    pub rights_mask: i64,
    #[serde(rename = "IsInherited")]
    pub is_inherited: Option<bool>,
    #[serde(rename = "InheritanceFlags")]
    pub inheritance_flags: Option<i64>,
    #[serde(rename = "PropagationFlags")]
    pub propagation_flags: Option<i64>,
}

/// Parse the JSON emitted by `build_get_registry_acl_command`.
pub fn parse_registry_acl_json(text: &str) -> Result<RawRegistryAcl, String> {
    let trimmed = text.trim().trim_start_matches('\u{feff}');
    if trimmed.is_empty() {
        return Ok(RawRegistryAcl::default());
    }
    serde_json::from_str::<RawRegistryAcl>(trimmed)
        .map_err(|e| format!("parse_registry_acl_json: {} (input='{}')", e, trimmed))
}

// =======================================================================
// RegistryRights decoder
// =======================================================================

// Named right flags (System.Security.AccessControl.RegistryRights).
const RR_QUERY_VALUES: i64 = 0x0001;
const RR_SET_VALUE: i64 = 0x0002;
const RR_CREATE_SUBKEY: i64 = 0x0004;
const RR_ENUMERATE_SUBKEYS: i64 = 0x0008;
const RR_NOTIFY: i64 = 0x0010;
const RR_CREATE_LINK: i64 = 0x0020;
const RR_DELETE: i64 = 0x10000;
const RR_READ_PERMISSIONS: i64 = 0x20000;
const RR_CHANGE_PERMISSIONS: i64 = 0x40000;
const RR_TAKE_OWNERSHIP: i64 = 0x80000;

// Canonical composites.
const RR_FULL_CONTROL: i64 = 0xF003F; // 983103 = KEY_ALL_ACCESS
const RR_READ_KEY: i64 = 0x20019; // 131097 = ReadPermissions|QueryValues|EnumerateSubKeys|Notify
const RR_WRITE_KEY: i64 = 0x20006; // 131078 = ReadPermissions|SetValue|CreateSubKey

// Generic bits (WinNT.h). Defined as positive i64 literals to avoid
// sign-extension when tested against the normalized positive mask.
const GEN_READ: i64 = 0x80000000;
const GEN_WRITE: i64 = 0x40000000;
const GEN_EXECUTE: i64 = 0x20000000;
const GEN_ALL: i64 = 0x10000000;

/// Decode a `RegistryRights` integer mask. When `decode_generic_flags`
/// is true, raw Win32 GENERIC_* bits are first translated to their
/// KEY_* equivalents.
pub fn decode_registry_rights_mask(mask: i64, decode_generic_flags: bool) -> String {
    // Normalise: PS emits 0x80000000 as a negative i32. Reinterpret
    // via u32 to recover the true unsigned bit pattern.
    let normalised = (mask as u32) as i64;

    let effective = if decode_generic_flags {
        translate_generic_bits(normalised)
    } else {
        normalised
    };

    // Fast-path canonical names.
    match effective {
        RR_FULL_CONTROL => return "FullControl".to_string(),
        RR_READ_KEY => return "ReadKey".to_string(),
        RR_WRITE_KEY => return "WriteKey".to_string(),
        0 => return "NoAccess".to_string(),
        _ => {}
    }

    let mut names: Vec<&str> = Vec::new();
    let mut remaining = effective;

    let check = |remaining: &mut i64, names: &mut Vec<&'static str>, bit: i64, name: &'static str| {
        if (*remaining & bit) == bit {
            names.push(name);
            *remaining &= !bit;
        }
    };

    // Composites first.
    check(&mut remaining, &mut names, RR_READ_KEY, "ReadKey");
    check(&mut remaining, &mut names, RR_WRITE_KEY, "WriteKey");

    // Individual bits.
    check(&mut remaining, &mut names, RR_QUERY_VALUES, "QueryValues");
    check(&mut remaining, &mut names, RR_SET_VALUE, "SetValue");
    check(&mut remaining, &mut names, RR_CREATE_SUBKEY, "CreateSubKey");
    check(&mut remaining, &mut names, RR_ENUMERATE_SUBKEYS, "EnumerateSubKeys");
    check(&mut remaining, &mut names, RR_NOTIFY, "Notify");
    check(&mut remaining, &mut names, RR_CREATE_LINK, "CreateLink");
    check(&mut remaining, &mut names, RR_DELETE, "Delete");
    check(&mut remaining, &mut names, RR_READ_PERMISSIONS, "ReadPermissions");
    check(&mut remaining, &mut names, RR_CHANGE_PERMISSIONS, "ChangePermissions");
    check(&mut remaining, &mut names, RR_TAKE_OWNERSHIP, "TakeOwnership");

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
        let mut out = names.join(", ");
        out.push_str(&format!(", 0x{:X}", remaining));
        return out;
    }
    names.join(", ")
}

fn translate_generic_bits(mask: i64) -> i64 {
    let mut out = mask & 0x00ffffff; // strip generic bits
    if (mask & GEN_ALL) == GEN_ALL {
        out |= RR_FULL_CONTROL;
    }
    if (mask & GEN_READ) == GEN_READ {
        out |= RR_READ_KEY;
    }
    if (mask & GEN_WRITE) == GEN_WRITE {
        out |= RR_WRITE_KEY;
    }
    if (mask & GEN_EXECUTE) == GEN_EXECUTE {
        // Registry GENERIC_EXECUTE maps to KEY_READ.
        out |= RR_READ_KEY;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------- key-path safety
    #[test]
    fn accepts_common_key_paths() {
        assert!(is_safe_key_path(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"));
        assert!(is_safe_key_path(r"HKLM:\SYSTEM\CurrentControlSet\Services\Foo"));
        assert!(is_safe_key_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\X"));
        assert!(is_safe_key_path(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defender"));
    }

    #[test]
    fn rejects_injection_key_paths() {
        assert!(!is_safe_key_path(""));
        assert!(!is_safe_key_path(r"HKLM:\$(whoami)"));
        assert!(!is_safe_key_path(r"HKLM:\${evil}"));
        assert!(!is_safe_key_path("HKLM:\\'evil"));
        assert!(!is_safe_key_path("HKLM:\\`whoami`"));
        assert!(!is_safe_key_path(r"HKLM:\a;b"));
        assert!(!is_safe_key_path(r"HKLM:\a|b"));
        assert!(!is_safe_key_path("HKLM:\\\"x"));
    }

    // ----------------------------------------------------- rights decoding
    #[test]
    fn decodes_registry_full_control_exact() {
        assert_eq!(decode_registry_rights_mask(983103, true), "FullControl");
    }

    #[test]
    fn decodes_read_key_exact() {
        assert_eq!(decode_registry_rights_mask(131097, true), "ReadKey");
    }

    #[test]
    fn decodes_write_key_exact() {
        assert_eq!(decode_registry_rights_mask(131078, true), "WriteKey");
    }

    #[test]
    fn decodes_zero_as_no_access() {
        assert_eq!(decode_registry_rights_mask(0, true), "NoAccess");
    }

    #[test]
    fn decodes_generic_all_when_enabled() {
        assert_eq!(decode_registry_rights_mask(0x10000000, true), "FullControl");
    }

    #[test]
    fn decodes_generic_read_when_enabled() {
        // 0x80000000 as i32 = -2147483648. Translates to KEY_READ.
        assert_eq!(
            decode_registry_rights_mask(-2147483648_i64, true),
            "ReadKey"
        );
    }

    #[test]
    fn keeps_generic_bits_when_disabled() {
        assert_eq!(decode_registry_rights_mask(0x10000000, false), "GenericAll");
        let out = decode_registry_rights_mask(-2147483648_i64, false);
        assert!(out.contains("GenericRead"), "expected GenericRead in '{}'", out);
    }

    // --------------------------------------------------------------- parsing
    #[test]
    fn parses_registry_acl_json() {
        let json = r#"{
            "Exists":true,
            "Path":"HKLM:\\SOFTWARE\\Foo",
            "Owner":"BUILTIN\\Administrators",
            "Group":"BUILTIN\\Administrators",
            "Sddl":"O:BAG:BAD:PAI(A;;KA;;;SY)",
            "InheritanceProtected":true,
            "AceCount":2,
            "Aces":[
                {"Identity":"NT AUTHORITY\\SYSTEM","Type":"Allow","RightsMask":983103,
                 "IsInherited":false,"InheritanceFlags":0,"PropagationFlags":0},
                {"Identity":"BUILTIN\\Users","Type":"Allow","RightsMask":131097,
                 "IsInherited":true,"InheritanceFlags":0,"PropagationFlags":0}
            ]
        }"#;
        let acl = parse_registry_acl_json(json).expect("parse");
        assert!(acl.is_found());
        assert_eq!(acl.owner.as_deref(), Some("BUILTIN\\Administrators"));
        assert_eq!(acl.ace_count, Some(2));
        assert_eq!(acl.aces.len(), 2);
        assert_eq!(acl.aces[0].rights_mask, 983103);
        assert_eq!(acl.aces[1].rights_mask, 131097);
    }

    #[test]
    fn parses_not_found() {
        let acl = parse_registry_acl_json("{}").expect("parse");
        assert!(!acl.is_found());
        assert!(acl.aces.is_empty());
    }

    // ------------------------------------------------------ command builder
    #[test]
    fn command_builder_embeds_key_path_and_catch() {
        let cmd = build_get_registry_acl_command(r"HKLM:\SOFTWARE\Foo");
        assert!(cmd.contains(r"Get-Acl 'HKLM:\SOFTWARE\Foo'"));
        assert!(cmd.contains("ItemNotFoundException"));
        assert!(cmd.contains("[int]$_.RegistryRights"));
        assert!(cmd.contains("ConvertTo-Json"));
    }
}
