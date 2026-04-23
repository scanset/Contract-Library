//! Windows Feature CTN Contract
//!
//! Covers a single Windows feature (one per CTN object). Two data
//! sources — pick with `behavior executor`:
//!
//! - **optionalfeature** (default): `Get-WindowsOptionalFeature -Online`.
//!   Works on both Client and Server. Scope: DISM "Windows features"
//!   (SMB1Protocol, TelnetClient, TFTP, IIS-* components, NetFx3, ...).
//!
//! - **windowsfeature** (Server-only): `Get-WindowsFeature`. Scope:
//!   Server Roles, Role Services, and ServerManager "Features"
//!   (Web-Server, RSAT-*, Windows-Defender, ...). Adds DisplayName and
//!   FeatureType.
//!
//! The two namespaces overlap partially. Pick the backend that matches
//! the vocabulary of the STIG control you're mapping — no automatic
//! fallback.

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_feature` CTN contract.
pub fn create_windows_feature_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_feature".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Windows feature name. Syntax varies by backend: \
                          optionalfeature uses DISM names (SMB1Protocol, TelnetClient); \
                          windowsfeature uses ServerManager names (Web-Server, RSAT-AD-Tools)"
                .to_string(),
            example_values: vec![
                "SMB1Protocol".to_string(),
                "TelnetClient".to_string(),
                "Web-Server".to_string(),
                "RSAT-AD-Tools".to_string(),
                "Windows-Defender".to_string(),
            ],
            validation_notes: Some(
                "Feature names are case-insensitive on Windows but we preserve the \
                 case you provide. Allowed chars: alphanumerics, hyphen, underscore, dot."
                    .to_string(),
            ),
        });

    // ---------------------------------------------------------------- STATE
    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
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
        "Whether the feature name resolved on the active backend. \
         False means the name is not recognized by Get-WindowsOptionalFeature / \
         Get-WindowsFeature (likely wrong backend, or feature not present in this SKU)",
    );
    add_bool(
        &mut contract,
        "enabled",
        "True iff the feature is fully enabled/installed. For optionalfeature: \
         State == \"Enabled\" (payload-removed variants are treated as not enabled). \
         For windowsfeature: InstallState == \"Installed\"",
    );

    add_str(
        &mut contract,
        "state",
        "Raw backend state string. optionalfeature: \"Enabled\" | \"Disabled\" | \
         \"EnableWithPayloadRemoved\" | \"DisabledWithPayloadRemoved\". \
         windowsfeature: \"Installed\" | \"Available\" | \"Removed\"",
        vec![
            "Enabled",
            "Disabled",
            "Installed",
            "Available",
            "DisabledWithPayloadRemoved",
        ],
    );
    add_str(
        &mut contract,
        "display_name",
        "Human-readable feature name. Populated by the windowsfeature backend only; \
         optionalfeature does not expose a display name and leaves this field absent",
        vec!["Web Server (IIS)", "Telnet Client", "SMB 1.0/CIFS File Sharing Support"],
    );
    add_str(
        &mut contract,
        "feature_type",
        "Feature category. windowsfeature backend emits \"Role\" | \"RoleService\" | \
         \"Feature\". optionalfeature backend always emits \"OptionalFeature\"",
        vec!["Role", "RoleService", "Feature", "OptionalFeature"],
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
        "state".to_string(),
        "display_name".to_string(),
        "feature_type".to_string(),
    ];

    for f in ["exists", "enabled", "state", "display_name", "feature_type"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_feature".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            // Get-WindowsFeature is notably slower than Get-WindowsOptionalFeature
            // on Server SKUs (walks the ServerManager catalog).
            expected_collection_time_ms: Some(2_000),
            memory_usage_mb: Some(2),
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
            default_value: Some("optionalfeature".to_string()),
            description: "Collection backend: optionalfeature (Get-WindowsOptionalFeature, \
                          Client+Server) or windowsfeature (Get-WindowsFeature, Server-only \
                          but exposes DisplayName + FeatureType)"
                .to_string(),
        }],
        description: "Select the Windows feature collection backend".to_string(),
        example: "behavior executor windowsfeature".to_string(),
    });

    // `behavior executor windowsfeature` parses as flags=["executor","windowsfeature"]
    // because the behavior parser treats single-word alphabetic identifiers as flag-like.
    // Accept both flag forms so validate_behavior_hints does not reject them.
    contract.add_supported_behavior(SupportedBehavior {
        name: "windowsfeature".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Parsed flag form of 'behavior executor windowsfeature'".to_string(),
        example: "behavior executor windowsfeature".to_string(),
    });
    contract.add_supported_behavior(SupportedBehavior {
        name: "optionalfeature".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Parsed flag form of 'behavior executor optionalfeature'".to_string(),
        example: "behavior executor optionalfeature".to_string(),
    });

    contract
}
