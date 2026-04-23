//! Local Group CTN Contract (Windows)
//!
//! Covers a single Windows local group + its direct members. Data
//! source: `Get-LocalGroup` + `Get-LocalGroupMember` (powershell,
//! default) or `Win32_Group` + `Win32_GroupUser` association (cim,
//! fallback — no PrincipalSource).
//!
//! Member lists are exposed as comma-separated strings (SAM names,
//! SIDs, ObjectClasses, PrincipalSources) so STIG assertions can use
//! standard `contains` / `not_contains` ops. For numeric thresholds
//! (e.g. "no more than 3 admins"), use `member_count`.
//!
//! Localized-group-name support via `behavior match_by_sid true` —
//! treat the `name` object field as a full SID.

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_local_group` CTN contract.
pub fn create_local_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_local_group".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Local group name, or a full SID when \
                          `behavior match_by_sid true` is set"
                .to_string(),
            example_values: vec![
                "Administrators".to_string(),
                "Backup Operators".to_string(),
                "Remote Desktop Users".to_string(),
                "S-1-5-32-544".to_string(),
            ],
            validation_notes: Some(
                "Name is case-insensitive. When match_by_sid=true, `name` must be a \
                 full well-known SID (e.g. S-1-5-32-544 for Administrators) so the \
                 check survives localized group names and renames."
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

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "exists".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: bool_ops.clone(),
        description: "Whether the local group was found on this host".to_string(),
        example_values: vec!["true".to_string(), "false".to_string()],
        validation_notes: None,
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "sid".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Group Security Identifier".to_string(),
        example_values: vec!["S-1-5-32-544".to_string()],
        validation_notes: None,
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "description".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Group description from SAM".to_string(),
        example_values: vec![],
        validation_notes: None,
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "member_count".to_string(),
        data_type: DataType::Int,
        allowed_operations: int_ops.clone(),
        description: "Number of direct members (including foreign principals)".to_string(),
        example_values: vec!["0".to_string(), "1".to_string(), "3".to_string()],
        validation_notes: Some(
            "Nested group membership is NOT recursively expanded; only direct \
             members are counted. This matches `Get-LocalGroupMember` semantics."
                .to_string(),
        ),
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "members".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Comma-separated member display names in DOMAIN\\Name form \
                      (e.g. 'win-server\\azureadmin,NT AUTHORITY\\SYSTEM'). Use \
                      contains / not_contains for membership assertions"
            .to_string(),
        example_values: vec![
            "win-server\\Administrator".to_string(),
            "NT AUTHORITY\\Authenticated Users,NT AUTHORITY\\INTERACTIVE".to_string(),
        ],
        validation_notes: Some(
            "SAM account names cannot legally contain commas, so comma is a safe \
             delimiter. Match by SID (`member_sids contains ...`) for \
             rename-resilient checks."
                .to_string(),
        ),
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "member_sids".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Comma-separated member SIDs. Prefer this over `members` \
                      for rename-resilient assertions"
            .to_string(),
        example_values: vec![
            "S-1-5-21-X-500".to_string(),
            "S-1-5-11,S-1-5-4".to_string(),
        ],
        validation_notes: None,
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "member_object_classes".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Comma-separated ObjectClass per member (User / Group). \
                      Use `contains Group` to detect nested groups"
            .to_string(),
        example_values: vec!["User".to_string(), "User,Group".to_string()],
        validation_notes: None,
    });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "member_sources".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "Comma-separated PrincipalSource per member (Local, \
                      ActiveDirectory, AzureAD, MicrosoftAccount, Unknown). \
                      powershell executor only (empty on cim)"
            .to_string(),
        example_values: vec!["Local".to_string(), "ActiveDirectory,Local".to_string()],
        validation_notes: Some(
            "Use `member_sources not_contains AzureAD` to flag federated admins \
             on machines that should be locally-administered only."
                .to_string(),
        ),
    });

    // -------------------------------------------------------------- MAPPINGS
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["exists".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "sid".to_string(),
        "description".to_string(),
        "member_count".to_string(),
        "members".to_string(),
        "member_sids".to_string(),
        "member_object_classes".to_string(),
        "member_sources".to_string(),
    ];

    for f in [
        "exists",
        "sid",
        "description",
        "member_count",
        "members",
        "member_sids",
        "member_object_classes",
        "member_sources",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_local_group".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(600),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // ----------------------------------------------------------- BEHAVIORS
    contract.add_supported_behavior(SupportedBehavior {
        name: "executor".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "executor".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("powershell".to_string()),
            description: "Collection backend: powershell (Get-LocalGroup + \
                          Get-LocalGroupMember, includes PrincipalSource) or \
                          cim (Win32_Group + Win32_GroupUser, no PrincipalSource)"
                .to_string(),
        }],
        description: "Select the local-group collection backend".to_string(),
        example: "behavior executor cim".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "match_by_sid".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "match_by_sid".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("false".to_string()),
            description: "When \"true\", interpret the `name` object field as a \
                          full SID (e.g. S-1-5-32-544) and resolve via SID match. \
                          Use this for well-known groups whose names are localized \
                          (e.g. 'Administratoren' on de-DE)"
                .to_string(),
        }],
        description: "Enable SID-based lookup for localized group names".to_string(),
        example: "behavior match_by_sid true".to_string(),
    });

    contract
}
