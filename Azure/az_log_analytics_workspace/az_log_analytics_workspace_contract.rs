//! Azure Log Analytics Workspace (LAW) CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_log_analytics_workspace;
//  pub use az_log_analytics_workspace::create_az_log_analytics_workspace_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates an Azure Log Analytics Workspace
//! via `az monitor log-analytics workspace show --workspace-name <name>
//! --resource-group <rg>`. Exposes SKU, retention, access control, public
//! network access, daily quota cap, local auth, and derived compliance
//! threshold fields. Full workspace document available as RecordData for
//! tag-based record_checks. Requires only the `Reader` role.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE law_baseline
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     sku_name string = `PerGB2018`
//!     retention_meets_90_days boolean = true
//!     local_auth_disabled boolean = true
//!     public_network_access_ingestion string = `Disabled`
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_log_analytics_workspace_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_log_analytics_workspace".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Log Analytics Workspace name".to_string(),
            example_values: vec!["law-prooflayer-demo".to_string()],
            validation_notes: Some(
                "Passed to az monitor log-analytics workspace show --workspace-name."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the workspace".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Required by az monitor log-analytics workspace show.".to_string(),
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
                "Uses AZURE_SUBSCRIPTION_ID env / cached default if not specified".to_string(),
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
            "Workspace name",
            "law-prooflayer-demo",
        ),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../workspaces/law-prooflayer-demo",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the workspace",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "customer_id",
            str_full.clone(),
            "Workspace customer ID (GUID used for data ingestion)",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ),
        (
            "created_date",
            str_full.clone(),
            "ISO 8601 creation timestamp",
            "2026-04-14T17:24:56.3509416Z",
        ),
        (
            "sku_name",
            str_eq.clone(),
            "Pricing tier SKU name",
            "PerGB2018",
        ),
        (
            "public_network_access_ingestion",
            str_eq.clone(),
            "Public network access for data ingestion",
            "Enabled",
        ),
        (
            "public_network_access_query",
            str_eq.clone(),
            "Public network access for queries",
            "Enabled",
        ),
        (
            "data_ingestion_status",
            str_eq.clone(),
            "Current data ingestion status from workspace capping",
            "RespectQuota",
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
        ("found", "Whether the workspace was found", "true", None),
        (
            "local_auth_disabled",
            "Whether local authentication is disabled (features.disableLocalAuth)",
            "false",
            Some("True means only AAD auth is accepted -- stronger security posture."),
        ),
        (
            "resource_permissions_enabled",
            "Whether resource-context access control is enabled",
            "true",
            Some("features.enableLogAccessUsingOnlyResourcePermissions"),
        ),
        (
            "has_daily_cap",
            "Derived: true when dailyQuotaGb > 0 (not unlimited)",
            "false",
            Some("dailyQuotaGb of -1.0 means unlimited (no cap)."),
        ),
        (
            "retention_meets_90_days",
            "Derived: true when retentionInDays >= 90",
            "true",
            Some("Common compliance threshold (FedRAMP Moderate, CMMC L2)."),
        ),
        (
            "retention_meets_365_days",
            "Derived: true when retentionInDays >= 365",
            "false",
            Some("Stricter compliance threshold (FedRAMP High, some NIST controls)."),
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
            "retention_in_days",
            "Data retention period in days",
            "30",
            Some("Default is 30; configurable up to 730."),
        ),
        (
            "daily_quota_gb",
            "Daily data ingestion quota in GB (-1 = unlimited)",
            "-1",
            Some("Stored as integer; -1 means no cap."),
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
            description: "Full workspace object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag assertions: \
                 `field tags.Environment string = \\`demo\\``."
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("name", "name"),
        ("resource_group", "resource_group"),
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
        "location".to_string(),
        "resource_group".to_string(),
        "provisioning_state".to_string(),
        "customer_id".to_string(),
        "created_date".to_string(),
        "sku_name".to_string(),
        "retention_in_days".to_string(),
        "public_network_access_ingestion".to_string(),
        "public_network_access_query".to_string(),
        "local_auth_disabled".to_string(),
        "resource_permissions_enabled".to_string(),
        "daily_quota_gb".to_string(),
        "has_daily_cap".to_string(),
        "data_ingestion_status".to_string(),
        "retention_meets_90_days".to_string(),
        "retention_meets_365_days".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "location",
        "resource_group",
        "provisioning_state",
        "customer_id",
        "created_date",
        "sku_name",
        "retention_in_days",
        "public_network_access_ingestion",
        "public_network_access_query",
        "local_auth_disabled",
        "resource_permissions_enabled",
        "daily_quota_gb",
        "has_daily_cap",
        "data_ingestion_status",
        "retention_meets_90_days",
        "retention_meets_365_days",
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
        collector_type: "az_log_analytics_workspace".to_string(),
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
