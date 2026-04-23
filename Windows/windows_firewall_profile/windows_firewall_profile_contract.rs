//! Windows Firewall Profile CTN Contract
//!
//! Covers a single NetFirewallProfile (Domain, Private, or Public),
//! exposed via `Get-NetFirewallProfile -Name <profile>`. STIG controls
//! typically assert things like:
//!   - profile Enabled == true
//!   - DefaultInboundAction == "Block"
//!   - LogAllowed == true and LogBlocked == true
//!   - NotifyOnListen == true

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create the `windows_firewall_profile` CTN contract.
pub fn create_firewall_profile_contract() -> CtnContract {
    let mut contract = CtnContract::new("windows_firewall_profile".to_string());

    // ---------------------------------------------------------------- OBJECT
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Firewall profile name. Must be one of: Domain, Private, Public \
                          (case-insensitive)."
                .to_string(),
            example_values: vec![
                "Domain".to_string(),
                "Private".to_string(),
                "Public".to_string(),
            ],
            validation_notes: Some(
                "Case-insensitive. Normalised to title case before being passed to \
                 Get-NetFirewallProfile."
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
        "Whether the profile resolved. The three standard profile names always \
         resolve on a normally-configured Windows host; false usually means the \
         NetSecurity module is unavailable",
    );
    add_bool(&mut contract, "enabled", "True when the profile is Enabled (firewall active for this profile)");
    add_str(
        &mut contract,
        "default_inbound_action",
        "Default action for inbound connections not matched by a specific rule. \
         One of: Allow, Block, NotConfigured",
        vec!["Block", "Allow", "NotConfigured"],
    );
    add_str(
        &mut contract,
        "default_outbound_action",
        "Default action for outbound connections not matched by a specific rule. \
         One of: Allow, Block, NotConfigured",
        vec!["Allow", "Block", "NotConfigured"],
    );
    add_bool(
        &mut contract,
        "log_allowed",
        "Whether connection-allowed events are written to the firewall log",
    );
    add_bool(
        &mut contract,
        "log_blocked",
        "Whether connection-blocked events are written to the firewall log",
    );
    add_str(
        &mut contract,
        "log_file_name",
        "Path to the firewall log for this profile",
        vec!["%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"],
    );
    add_bool(
        &mut contract,
        "notify_on_listen",
        "Whether the user is notified when a program starts listening for inbound \
         connections",
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
        "default_inbound_action".to_string(),
        "default_outbound_action".to_string(),
        "log_allowed".to_string(),
        "log_blocked".to_string(),
        "log_file_name".to_string(),
        "notify_on_listen".to_string(),
    ];

    for f in [
        "exists",
        "enabled",
        "default_inbound_action",
        "default_outbound_action",
        "log_allowed",
        "log_blocked",
        "log_file_name",
        "notify_on_listen",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(f.to_string(), f.to_string());
    }

    // ---------------------------------------------------------- COLLECTION
    contract.collection_strategy = CollectionStrategy {
        collector_type: "windows_firewall_profile".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["powershell_exec".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(800),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
