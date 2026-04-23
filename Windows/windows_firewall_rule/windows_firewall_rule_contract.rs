//! Windows Firewall Rule CTN Contract
//!
//! Covers a single Windows Firewall rule, exposed via
//! `Get-NetFirewallRule`. STIG controls typically assert things like:
//!   - a named rule exists and is enabled
//!   - a specific inbound rule blocks traffic
//!   - a rule group contains at least one active rule

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_firewall_rule` CTN contract.
pub fn create_firewall_rule_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_firewall_rule".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Rule lookup value. The meaning depends on behavior match_by: \
                          when match_by=name (default) this is the internal rule Name/ID; \
                          when match_by=display_name this is the user-facing DisplayName; \
                          when match_by=display_group this is the rule group name."
                .to_string(),
            example_values: vec![
                "RemoteDesktop-UserMode-In-TCP".to_string(),
                "Remote Desktop - User Mode (TCP-In)".to_string(),
                "Remote Desktop".to_string(),
                "{12345678-ABCD-1234-EFAB-0123456789AB}".to_string(),
            ],
            validation_notes: Some(
                "Up to 512 chars. Rejects quotes, backticks, pipes, semicolons, \
                 ampersands, subexpression syntax, and newlines."
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
        "Whether any rule matched the lookup. Missing rules short-circuit all \
         other fields to absent",
    );
    add_bool(
        &mut contract,
        "enabled",
        "True when the rule is enabled (Enabled == True)",
    );
    add_str(
        &mut contract,
        "direction",
        "Traffic direction the rule applies to. Inbound or Outbound",
        vec!["Inbound", "Outbound"],
    );
    add_str(
        &mut contract,
        "action",
        "Action the rule takes. Allow, Block, or NotConfigured",
        vec!["Allow", "Block"],
    );
    add_str(
        &mut contract,
        "profile",
        "Comma-joined sorted list of profiles the rule applies to. \
         One of: Any (mask 0), Domain, Private, Public, or combinations like \
         \"Domain, Private\" or \"Domain, Private, Public\"",
        vec!["Domain, Private, Public", "Any", "Public"],
    );
    add_str(
        &mut contract,
        "display_name",
        "User-facing display name of the rule",
        vec!["Remote Desktop - User Mode (TCP-In)"],
    );
    add_str(
        &mut contract,
        "description",
        "Long-form description of the rule, usually set by the rule author",
        vec!["Inbound rule for Remote Desktop"],
    );
    add_str(
        &mut contract,
        "display_group",
        "Group the rule belongs to (user-facing grouping in the firewall UI)",
        vec!["Remote Desktop", "Windows Defender Firewall"],
    );
    add_str(
        &mut contract,
        "primary_status",
        "Rule primary status. One of: OK, Degraded, Error, Unknown",
        vec!["OK", "Error"],
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
        "direction".to_string(),
        "action".to_string(),
        "profile".to_string(),
        "display_name".to_string(),
        "description".to_string(),
        "display_group".to_string(),
        "primary_status".to_string(),
    ];

    for f in [
        "exists",
        "enabled",
        "direction",
        "action",
        "profile",
        "display_name",
        "description",
        "display_group",
        "primary_status",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_firewall_rule".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(1_500),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    // ----------------------------------------------------------- BEHAVIORS
    contract.add_supported_behavior(SupportedBehavior {
        name: "match_by".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "match_by".to_string(),
            data_type: DataType::String,
            required: false,
            default_value: Some("name".to_string()),
            description: "Which Get-NetFirewallRule parameter to use for the lookup. \
                          Valid values: name (default, internal rule ID), display_name \
                          (user-facing name), display_group (rule group; returns first \
                          matching rule in the group)"
                .to_string(),
        }],
        description: "Choose which firewall-rule attribute the object name maps to"
            .to_string(),
        example: "behavior match_by display_name".to_string(),
    });

    contract
}
