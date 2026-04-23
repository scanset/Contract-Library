//! Windows Registry ACL CTN Contract
//!
//! Covers the security descriptor on a single registry key, exposed via
//! `Get-Acl -LiteralPath`. STIG controls typically assert things like:
//!   - owner must be SYSTEM / Administrators / TrustedInstaller
//!   - no ACE grants Users WriteKey on a policy key
//!   - inheritance is blocked on specific keys
//!   - SDDL matches a fixed golden string
//!
//! Denormalised ACE data lets those checks use plain string
//! `contains`/`not_contains`/`pattern_match` operators without the ESP
//! policy needing to walk nested structures.

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_registry_acl` CTN contract.
pub fn create_registry_acl_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_registry_acl".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "key_path".to_string(),
            data_type: DataType::String,
            description: "Registry key path to inspect. Accepts PS-provider form \
                          (HKLM:\\SOFTWARE\\Foo) or native hive-prefix form \
                          (HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo). File and directory ACLs \
                          get a separate CTN."
                .to_string(),
            example_values: vec![
                "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".to_string(),
                "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters".to_string(),
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Defender".to_string(),
            ],
            validation_notes: Some(
                "Key path is passed to PS Get-Acl -LiteralPath verbatim. Allowed chars: \
                 alphanumerics, path separators, colon, space, dot, parentheses, brackets, \
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
            example_values: vec!["0".to_string(), "6".to_string()],
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

    add_bool(
        &mut contract,
        "exists",
        "Whether the registry key resolves on this host. Missing keys short-circuit \
         all other fields to absent",
    );
    add_bool(
        &mut contract,
        "inheritance_protected",
        "True when inheritance from parent registry keys is blocked \
         (AreAccessRulesProtected). STIG often requires this on locked-down policy keys",
    );

    add_str(
        &mut contract,
        "owner",
        "Owner identity for the registry key (friendly form when resolvable, else SID)",
        vec![
            "NT SERVICE\\TrustedInstaller",
            "BUILTIN\\Administrators",
            "NT AUTHORITY\\SYSTEM",
        ],
    );
    add_str(
        &mut contract,
        "group",
        "Primary group on the registry key. Rarely meaningful on Windows but included \
         for completeness",
        vec!["NT SERVICE\\TrustedInstaller"],
    );
    add_str(
        &mut contract,
        "sddl",
        "Full ACL in SDDL form. Deterministic single-line representation, \
         suitable for exact-equality against a golden string",
        vec!["O:BAG:SYD:PAI(A;;KA;;;SY)(A;;KA;;;BA)"],
    );

    add_int(
        &mut contract,
        "ace_count",
        "Number of Access Control Entries on the registry key",
    );

    add_str(
        &mut contract,
        "aces",
        "Newline-joined per-ACE records. Each line is \
         `IDENTITY|TYPE|RIGHTS[|inherited]` where TYPE is `Allow` or `Deny` and \
         RIGHTS is the decoded RegistryRights string \
         (e.g. `FullControl` or `ReadKey` or `SetValue, CreateSubKey`). \
         Use `contains`/`not_contains` to assert the presence or absence of \
         specific (identity, type, rights) combinations. \
         The trailing `|inherited` suffix is present on inherited ACEs only",
        vec![
            "BUILTIN\\Administrators|Allow|FullControl",
            "BUILTIN\\Users|Allow|ReadKey|inherited",
        ],
    );
    add_str(
        &mut contract,
        "allow_identities",
        "Comma-joined unique identity strings with any Allow ACE on this registry key. \
         Convenience field for checks that don't care about specific rights",
        vec!["NT AUTHORITY\\SYSTEM,BUILTIN\\Administrators,BUILTIN\\Users"],
    );
    add_str(
        &mut contract,
        "deny_identities",
        "Comma-joined unique identity strings with any Deny ACE on this registry key. \
         Empty string when the key has no Deny ACEs",
        vec!["Everyone"],
    );

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("key_path".to_string(), "key_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "inheritance_protected".to_string(),
        "owner".to_string(),
        "group".to_string(),
        "sddl".to_string(),
        "ace_count".to_string(),
        "aces".to_string(),
        "allow_identities".to_string(),
        "deny_identities".to_string(),
    ];

    for f in [
        "exists",
        "inheritance_protected",
        "owner",
        "group",
        "sddl",
        "ace_count",
        "aces",
        "allow_identities",
        "deny_identities",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_registry_acl".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // ----------------------------------------------------------- BEHAVIORS
    contract.add_supported_behavior(SupportedBehavior {
        name: "decode_generic_flags".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "decode_generic_flags".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("true".to_string()),
            description: "When \"true\" (default), raw Win32 GENERIC_* bits \
                          (0x80000000/0x40000000/0x20000000/0x10000000) are translated \
                          into their KEY_* equivalents before stringifying. \
                          When \"false\", generic bits appear as `GenericRead`, \
                          `GenericWrite`, `GenericExecute`, `GenericAll` labels in the \
                          rights string"
                .to_string(),
        }],
        description: "Control Win32 generic-bit translation in rights decoding".to_string(),
        example: "behavior decode_generic_flags false".to_string(),
    });

    contract
}
