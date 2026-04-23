//! Windows File Metadata CTN Contract
//!
//! Covers basic filesystem metadata on a single file or directory,
//! exposed via `Get-Item` (plus `Get-Acl` for owner SID resolution).
//! Complements `windows_file_acl`, which covers the full ACL / SDDL.
//!
//! STIG controls addressed include ownership (`owner_id`), size bounds
//! (security log), attribute flags (hidden/system on pagefile/BCD/SAM),
//! and basic reachability (`readable`/`writable`).

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_file_metadata` CTN contract.
pub fn create_file_metadata_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_file_metadata".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "Filesystem path (file or directory) to inspect. Accepts drive-letter \
                          paths, UNC paths, and admin shares. Do not use PowerShell-provider \
                          paths (e.g. HKLM:\\...) - registry metadata gets a separate CTN."
                .to_string(),
            example_values: vec![
                "C:\\Windows\\System32\\cmd.exe".to_string(),
                "C:\\Windows\\System32\\drivers\\etc".to_string(),
                "C:\\Program Files".to_string(),
                "\\\\server\\share\\sensitive".to_string(),
            ],
            validation_notes: Some(
                "Path is passed to PS Get-Item verbatim. Allowed chars: alphanumerics, \
                 path separators, drive colon, space, dot, parentheses, brackets, \
                 underscore, hyphen, dollar. Paths containing quotes, backticks, \
                 semicolons, or subexpression syntax are rejected."
                    .to_string(),
            ),
        });

    // ---------------------------------------------------------------- STATE
    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::LessThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThanOrEqual,
    ];
    let str_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::NotContains,
        Operation::StartsWith,
        Operation::EndsWith,
        Operation::CaseInsensitiveEquals,
        Operation::CaseInsensitiveNotEqual,
        Operation::PatternMatch,
    ];

    let add_bool = |c: &mut CtnContract, name: &str, desc: &str| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: desc.to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: None,
        });
    };
    let add_int = |c: &mut CtnContract, name: &str, desc: &str| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: desc.to_string(),
            example_values: vec!["0".to_string(), "824".to_string()],
            validation_notes: None,
        });
    };
    let add_str = |c: &mut CtnContract, name: &str, desc: &str, examples: Vec<&str>| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops.clone(),
            description: desc.to_string(),
            example_values: examples.into_iter().map(String::from).collect(),
            validation_notes: None,
        });
    };

    // Required.
    contract.state_requirements.add_required_field(StateFieldSpec {
        name: "exists".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: bool_ops.clone(),
        description: "Whether the path resolves on this host. Missing paths short-circuit \
                      all other fields to absent".to_string(),
        example_values: vec!["true".to_string(), "false".to_string()],
        validation_notes: None,
    });

    // Optional.
    add_bool(
        &mut contract,
        "readable",
        "True when the current principal can open the file for reading \
         (files: File.OpenRead; directories: Get-ChildItem first item)",
    );
    add_bool(
        &mut contract,
        "writable",
        "True when the ReadOnly attribute is clear. NOTE: this is a \
         ReadOnly-attribute heuristic, not an ACL-based write check - \
         true ACL writability belongs on windows_file_acl",
    );
    add_bool(
        &mut contract,
        "is_hidden",
        "True when the Hidden FileAttributes bit is set",
    );
    add_bool(
        &mut contract,
        "is_system",
        "True when the System FileAttributes bit is set",
    );
    add_bool(
        &mut contract,
        "is_directory",
        "True for directories (PSIsContainer), false for files",
    );
    add_bool(
        &mut contract,
        "is_readonly",
        "True when the ReadOnly FileAttributes bit is set",
    );
    add_bool(
        &mut contract,
        "is_archive",
        "True when the Archive FileAttributes bit is set",
    );

    add_int(
        &mut contract,
        "size",
        "File size in bytes (0 for directories)",
    );

    add_str(
        &mut contract,
        "owner",
        "Owner identity (friendly form when resolvable)",
        vec![
            "NT SERVICE\\TrustedInstaller",
            "BUILTIN\\Administrators",
            "NT AUTHORITY\\SYSTEM",
        ],
    );
    add_str(
        &mut contract,
        "owner_id",
        "Owner SID in string form (e.g. S-1-5-18 for SYSTEM). Resolved \
         via NTAccount.Translate(SecurityIdentifier); falls back to the \
         O: segment of the SDDL when translation fails",
        vec![
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        ],
    );
    add_str(
        &mut contract,
        "owner_error",
        "Exception message when Get-Acl failed (e.g. insufficient \
         privileges to read SDDL on a protected hive). Present iff \
         owner/owner_id are absent AND the failure was non-fatal. Lets \
         policies distinguish 'ACL unreadable under current auth context' \
         from 'file genuinely has no owner'",
        vec![
            "Attempted to perform an unauthorized operation.",
            "The process does not possess the 'SeSecurityPrivilege' privilege which is required for this operation.",
        ],
    );
    add_str(
        &mut contract,
        "attributes",
        "Comma-joined .NET FileAttributes enum string \
         (e.g. 'Archive' or 'Hidden, System, ReadOnly')",
        vec!["Archive", "Hidden, System", "Directory"],
    );

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "readable".to_string(),
        "writable".to_string(),
        "is_hidden".to_string(),
        "is_system".to_string(),
        "size".to_string(),
        "owner_id".to_string(),
        "owner".to_string(),
        "owner_error".to_string(),
        "is_directory".to_string(),
        "is_readonly".to_string(),
        "is_archive".to_string(),
        "attributes".to_string(),
    ];

    for f in [
        "exists",
        "readable",
        "writable",
        "is_hidden",
        "is_system",
        "size",
        "owner_id",
        "owner",
        "owner_error",
        "is_directory",
        "is_readonly",
        "is_archive",
        "attributes",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_file_metadata".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(400),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // No behaviors for v1.

    contract
}
