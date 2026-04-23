//! Local User CTN Contract (Windows)
//!
//! Covers a single Windows local account (one per CTN object). Data
//! source: `Get-LocalUser` (powershell, default) or `Win32_UserAccount`
//! (cim, fallback — loses date fields, gains lockout).
//!
//! Handles the renamed-Administrator case via `behavior match_by_rid
//! true` — treat the `name` field as a RID suffix ("500", "501", "503").

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_local_user` CTN contract.
pub fn create_local_user_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_local_user".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Local account name (SAM name), or a RID suffix when \
                          `behavior match_by_rid true` is set"
                .to_string(),
            example_values: vec![
                "Administrator".to_string(),
                "Guest".to_string(),
                "DefaultAccount".to_string(),
                "500".to_string(),
            ],
            validation_notes: Some(
                "Name is case-insensitive. When match_by_rid=true, `name` must be the \
                 numeric RID suffix (last segment of the SID) to resolve the well-known \
                 account regardless of rename."
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
    let add_int = |c: &mut CtnContract, name: &str, desc: &str, notes: Option<&str>| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: desc.to_string(),
            example_values: vec!["0".to_string(), "35".to_string(), "90".to_string()],
            validation_notes: notes.map(|s| s.to_string()),
        });
    };
    let add_str = |c: &mut CtnContract, name: &str, desc: &str| {
        c.state_requirements.add_optional_field(StateFieldSpec {
            name: name.to_string(),
            data_type: DataType::String,
            allowed_operations: str_ops.clone(),
            description: desc.to_string(),
            example_values: vec![],
            validation_notes: None,
        });
    };

    add_bool(
        &mut contract,
        "exists",
        "Whether the local account was found on this host",
    );
    add_bool(
        &mut contract,
        "enabled",
        "True if the account is enabled. Maps to Get-LocalUser `Enabled` \
         or the inverse of Win32_UserAccount `Disabled`",
    );
    add_bool(
        &mut contract,
        "password_required",
        "True if a password is required for interactive logon",
    );
    add_bool(
        &mut contract,
        "user_may_change_password",
        "True if the user may change their own password (powershell executor only)",
    );
    add_bool(
        &mut contract,
        "password_expires",
        "True if the password-expiry policy applies to this account \
         (policy flag, not the expiry timestamp)",
    );
    add_bool(
        &mut contract,
        "lockout",
        "True if the account is currently locked out (cim executor only)",
    );

    add_str(&mut contract, "sid", "Security Identifier (SDDL string)");
    add_str(
        &mut contract,
        "description",
        "Account description from SAM",
    );
    add_str(&mut contract, "full_name", "Account full name (display name)");

    add_int(
        &mut contract,
        "password_last_set_days",
        "Days since the password was last set. Negative if never set. \
         powershell executor only",
        Some("Missing if Get-LocalUser returned null for PasswordLastSet"),
    );
    add_int(
        &mut contract,
        "password_expires_days",
        "Days until the password expires. Negative if already expired. \
         powershell executor only",
        Some("Missing if the account has no expiry policy"),
    );
    add_int(
        &mut contract,
        "last_logon_days",
        "Days since the last interactive logon. Huge value (e.g. 36500) if \
         never logged on. powershell executor only",
        Some("Missing if Get-LocalUser returned null for LastLogon"),
    );
    add_int(
        &mut contract,
        "account_expires_days",
        "Days until the account expires. Negative if already expired. \
         powershell executor only",
        Some("Missing if the account has no expiry date"),
    );

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
        "enabled".to_string(),
        "password_required".to_string(),
        "user_may_change_password".to_string(),
        "password_expires".to_string(),
        "lockout".to_string(),
        "sid".to_string(),
        "description".to_string(),
        "full_name".to_string(),
        "password_last_set_days".to_string(),
        "password_expires_days".to_string(),
        "last_logon_days".to_string(),
        "account_expires_days".to_string(),
    ];

    for f in [
        "exists",
        "enabled",
        "password_required",
        "user_may_change_password",
        "password_expires",
        "lockout",
        "sid",
        "description",
        "full_name",
        "password_last_set_days",
        "password_expires_days",
        "last_logon_days",
        "account_expires_days",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_local_user".to_string(),
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
        name: "executor".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "executor".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("powershell".to_string()),
            description: "Collection backend: powershell (Get-LocalUser, full fidelity) \
                          or cim (Win32_UserAccount, no date fields, adds lockout)"
                .to_string(),
        }],
        description: "Select the local-user collection backend".to_string(),
        example: "behavior executor cim".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "match_by_rid".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "match_by_rid".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("false".to_string()),
            description: "When \"true\", interpret the `name` object field as a RID \
                          suffix and resolve the account via SID pattern. Use \"500\" \
                          to find the well-known Administrator regardless of rename"
                .to_string(),
        }],
        description: "Enable RID-based lookup for well-known renamed accounts"
            .to_string(),
        example: "behavior match_by_rid true".to_string(),
    });

    contract
}
