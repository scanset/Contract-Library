//! Azure Diagnostic Setting CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_diagnostic_setting;
//  pub use az_diagnostic_setting::create_az_diagnostic_setting_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates a single named Azure
//! diagnostic setting attached to a target resource, via
//! `az monitor diagnostic-settings show --name <setting> --resource <ARM ID>
//! --output json`. Exposes sink/destination scalars (workspace, event hub,
//! storage, marketplace), per-category log + metric record arrays, and
//! derived counts (enabled log categories, enabled metric categories,
//! destination count). Requires only `Reader` at subscription / RG / target
//! resource scope. Subscription-level activity-log diagnostic settings are
//! a separate API surface and are out of scope for this CTN.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE diag_to_workspace
//!     found boolean = true
//!     has_workspace_destination boolean = true
//!     all_log_categories_enabled boolean = true
//!     log_categories_enabled_count int >= 1
//!     destination_count int >= 1
//!     record
//!         field logs[?category==`AuditEvent`].enabled boolean = true
//!     record_end
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_diagnostic_setting_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_diagnostic_setting".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_id".to_string(),
            data_type: DataType::String,
            description: "Full ARM resource ID of the target resource the diagnostic setting is \
                          attached to"
                .to_string(),
            example_values: vec![
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/\
                 rg-prooflayer-demo-eastus/providers/Microsoft.KeyVault/vaults/\
                 kv-prooflayer-demo-ybuu"
                    .to_string(),
            ],
            validation_notes: Some(
                "Must be a full ARM resource ID including /subscriptions/.../providers/... . \
                 Copy from `az <service> show --query id -o tsv`. Azure will lower-case some \
                 segments in the response id; don't compare against the input verbatim."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "setting_name".to_string(),
            data_type: DataType::String,
            description: "Name of the diagnostic setting on the target resource".to_string(),
            example_values: vec!["diag-kv".to_string()],
            validation_notes: Some(
                "Passed to az monitor diagnostic-settings show --name. A missing or malformed \
                 name returns ResourceNotFound with the message \"The diagnostic setting 'X' \
                 doesn't exist.\" - the collector maps that to found=false."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "subscription".to_string(),
            data_type: DataType::String,
            description: "Subscription ID override".to_string(),
            example_values: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            validation_notes: Some(
                "Usually redundant because the resource_id already embeds the subscription. \
                 Overriding is only useful for cross-subscription auth contexts."
                    .to_string(),
            ),
        });

    // -- State requirements -------------------------------------------

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    // scalar strings
    for (name, ops, desc, example) in [
        (
            "name",
            str_full.clone(),
            "Diagnostic setting name",
            "diag-kv",
        ),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID of the diagnostic setting (Azure-normalized, may be \
             lowercased)",
            "/subscriptions/.../diagnosticSettings/diag-kv",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type (always Microsoft.Insights/diagnosticSettings)",
            "Microsoft.Insights/diagnosticSettings",
        ),
        (
            "target_resource_group",
            str_full.clone(),
            "Resource group of the TARGET resource the setting is attached to",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "workspace_id",
            str_full.clone(),
            "Log Analytics workspace ARM ID (empty string when not configured)",
            "/subscriptions/.../workspaces/law-prooflayer-demo",
        ),
        (
            "event_hub_name",
            str_eq.clone(),
            "Event Hub name (empty string when not configured)",
            "diag-eh",
        ),
        (
            "event_hub_authorization_rule_id",
            str_full.clone(),
            "Event Hub authorization rule ARM ID (empty string when not configured)",
            "/subscriptions/.../authorizationRules/RootManageSharedAccessKey",
        ),
        (
            "storage_account_id",
            str_full.clone(),
            "Storage account ARM ID for archival destination (empty string when not configured)",
            "/subscriptions/.../storageAccounts/stlogsprooflayerdemog71v",
        ),
        (
            "marketplace_partner_id",
            str_full.clone(),
            "Marketplace partner solution ARM ID (empty string when not configured)",
            "",
        ),
        (
            "service_bus_rule_id",
            str_eq.clone(),
            "Legacy service bus rule ID (deprecated; empty string on modern settings)",
            "",
        ),
        (
            "log_analytics_destination_type",
            str_eq.clone(),
            "Log Analytics destination type (Dedicated, AzureDiagnostics, or empty when not LAW)",
            "AzureDiagnostics",
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::String,
                allowed_operations: ops,
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    // booleans
    for (name, desc, example, notes) in [
        (
            "found",
            "Whether the diagnostic setting was found on the target resource",
            "true",
            None,
        ),
        (
            "has_workspace_destination",
            "Derived: true when workspace_id is non-empty",
            "true",
            Some("Core compliance signal - Log Analytics is the canonical SIEM sink."),
        ),
        (
            "has_event_hub_destination",
            "Derived: true when event_hub_authorization_rule_id is non-empty",
            "false",
            None,
        ),
        (
            "has_storage_destination",
            "Derived: true when storage_account_id is non-empty",
            "false",
            Some("Archive-to-storage pattern; counts as a valid sink for long-term retention."),
        ),
        (
            "has_marketplace_destination",
            "Derived: true when marketplace_partner_id is non-empty",
            "false",
            None,
        ),
        (
            "all_log_categories_enabled",
            "Derived: true when every entry in logs[] has enabled=true",
            "true",
            Some(
                "Vacuously true when logs[] is empty. Use log_categories_enabled_count for \
                 existence + enablement in one check.",
            ),
        ),
        (
            "all_metric_categories_enabled",
            "Derived: true when every entry in metrics[] has enabled=true",
            "true",
            Some("Vacuously true when metrics[] is empty."),
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: bool_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    // integers
    for (name, desc, example, notes) in [
        (
            "destination_count",
            "Number of populated destinations (workspace + event hub + storage + marketplace)",
            "1",
            Some("Should be >= 1 for a valid setting. 0 means broken/orphaned."),
        ),
        (
            "log_category_count",
            "Total number of log category entries in logs[]",
            "2",
            None,
        ),
        (
            "metric_category_count",
            "Total number of metric category entries in metrics[]",
            "1",
            None,
        ),
        (
            "log_categories_enabled_count",
            "Number of log categories with enabled=true",
            "2",
            Some(
                "Prefer this over all_log_categories_enabled when you need to assert at least N \
                 categories are on.",
            ),
        ),
        (
            "metric_categories_enabled_count",
            "Number of metric categories with enabled=true",
            "1",
            None,
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Int,
                allowed_operations: int_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: notes.map(str::to_string),
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full diagnostic setting object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for per-category assertions: \
                 `field logs[?category==\\`AuditEvent\\`].enabled boolean = true` or \
                 `field metrics[?category==\\`AllMetrics\\`].enabled boolean = true` or \
                 `field logAnalyticsDestinationType string = \\`AzureDiagnostics\\``."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("resource_id", "resource_id"),
        ("setting_name", "setting_name"),
        ("subscription", "subscription"),
    ] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(obj.to_string(), col.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "name".to_string(),
        "id".to_string(),
        "type".to_string(),
        "target_resource_group".to_string(),
        "workspace_id".to_string(),
        "event_hub_name".to_string(),
        "event_hub_authorization_rule_id".to_string(),
        "storage_account_id".to_string(),
        "marketplace_partner_id".to_string(),
        "service_bus_rule_id".to_string(),
        "log_analytics_destination_type".to_string(),
        "has_workspace_destination".to_string(),
        "has_event_hub_destination".to_string(),
        "has_storage_destination".to_string(),
        "has_marketplace_destination".to_string(),
        "all_log_categories_enabled".to_string(),
        "all_metric_categories_enabled".to_string(),
        "destination_count".to_string(),
        "log_category_count".to_string(),
        "metric_category_count".to_string(),
        "log_categories_enabled_count".to_string(),
        "metric_categories_enabled_count".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "target_resource_group",
        "workspace_id",
        "event_hub_name",
        "event_hub_authorization_rule_id",
        "storage_account_id",
        "marketplace_partner_id",
        "service_bus_rule_id",
        "log_analytics_destination_type",
        "has_workspace_destination",
        "has_event_hub_destination",
        "has_storage_destination",
        "has_marketplace_destination",
        "all_log_categories_enabled",
        "all_metric_categories_enabled",
        "destination_count",
        "log_category_count",
        "metric_category_count",
        "log_categories_enabled_count",
        "metric_categories_enabled_count",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "resource".to_string());

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_diagnostic_setting".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
