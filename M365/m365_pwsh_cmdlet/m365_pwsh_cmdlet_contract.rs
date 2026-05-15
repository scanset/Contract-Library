//! Contract for the `m365_pwsh_cmdlet` CTN.
//!
//! Single-CTN discovery primitive for Microsoft surfaces only reachable
//! via PowerShell (Connect-IPPSSession / Connect-ExchangeOnline against
//! Microsoft's compliance + EXO backends). Shells out to a local `pwsh`
//! process, authenticates the SPN via certificate, runs the requested
//! cmdlet, and returns the JSON-serialized result rows.
//!
//! Sibling of `m365_graph_query` — same Outputs shape (found / row_count /
//! rows) so handlers downstream don't have to fork on auth-channel kind.
//! Differs only in how the bearer/auth context is established.
//!
//! ## Inputs
//!
//! - `cmdlet`       — PowerShell cmdlet name to execute (required).
//!                    Must be a non-mutating Get-* cmdlet available
//!                    after `Connect-IPPSSession` succeeds.
//!                    Examples: `Get-ComplianceTag`,
//!                    `Get-DlpCompliancePolicy`,
//!                    `Get-UnifiedAuditLogRetentionPolicy`.
//! - `organization` — Tenant primary domain (required). Passed to
//!                    Connect-IPPSSession's `-Organization` parameter.
//!                    Example: `scanset.io`.
//! - `filter`       — optional string passed to cmdlet's `-Filter`
//!                    parameter (KQL or cmdlet-specific filter syntax).
//!
//! ## Outputs (in CollectedData) — identical shape to m365_graph_query
//!
//! - `found`     — boolean, true on successful cmdlet execution.
//! - `row_count` — integer.
//! - `rows`      — RecordData (JSON array of objects from the cmdlet).
//!
//! ## Auth
//!
//! Reads the following env vars (set by `inventory::resolver::build_env`
//! for any `azure_spn_cert` credential):
//!
//! - `M365_PWSH_TENANT_ID`    — tenant id
//! - `M365_PWSH_CLIENT_ID`    — app registration client id (the cert SPN)
//! - `M365_PWSH_PFX_PATH`     — path to PFX bundle (cert + key) in the
//!                              per-scan tempdir
//! - `M365_PWSH_PFX_PASSWORD` — usually empty (TF-generated cert has
//!                              no password); set if rotated to a
//!                              password-protected cert.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_m365_pwsh_cmdlet_contract() -> CtnContract {
    let mut contract = CtnContract::new("m365_pwsh_cmdlet".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "cmdlet".to_string(),
            data_type: DataType::String,
            description:
                "PowerShell cmdlet to execute against the active \
                 IPPSSession. Must be a read-only Get-* cmdlet. The \
                 SPN's compliance role-group membership (e.g. \
                 ComplianceAdministrator) determines which cmdlets \
                 are authorized."
                    .to_string(),
            example_values: vec![
                "Get-ComplianceTag".to_string(),
                "Get-DlpCompliancePolicy".to_string(),
                "Get-UnifiedAuditLogRetentionPolicy".to_string(),
                "Get-MailboxAuditConfig".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "organization".to_string(),
            data_type: DataType::String,
            description:
                "Tenant primary domain (the `-Organization` parameter \
                 of Connect-IPPSSession). Typically the *.onmicrosoft.com \
                 domain or the customer-vanity equivalent."
                    .to_string(),
            example_values: vec!["scanset.io".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "filter".to_string(),
            data_type: DataType::String,
            description:
                "Optional filter expression passed to the cmdlet's \
                 `-Filter` parameter. Cmdlet-specific syntax."
                    .to_string(),
            example_values: vec!["Enabled -eq $true".to_string()],
            validation_notes: None,
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let int_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::GreaterThan,
        Operation::GreaterThanOrEqual,
        Operation::LessThan,
        Operation::LessThanOrEqual,
    ];

    contract
        .state_requirements
        .add_required_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether the cmdlet executed and parsed successfully.".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "row_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of rows the cmdlet returned.".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rows".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description:
                "Full result rows, each a JSON object from the cmdlet's \
                 ConvertTo-Json output. Discovery iterates this array \
                 and creates / enriches assets per-row."
                    .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [
        ("cmdlet", "cmdlet"),
        ("organization", "organization"),
        ("filter", "filter"),
    ] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(obj.to_string(), col.to_string());
    }

    contract.field_mappings.collection_mappings.required_data_fields = vec!["found".to_string()];

    contract.field_mappings.collection_mappings.optional_data_fields =
        vec!["row_count".to_string(), "rows".to_string()];

    for state_key in &["found", "row_count", "rows"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert((*state_key).to_string(), (*state_key).to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "m365_pwsh_cmdlet".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec![
            "pwsh_runtime".to_string(),
            "azure_spn_cert_env".to_string(),
            "exo_compliance_role".to_string(),
        ],
        performance_hints: PerformanceHints {
            // Each invocation: pwsh cold start (~1s) + Connect-IPPSSession
            // (~2-3s) + cmdlet round-trip (~1-3s) + Disconnect (~1s) =
            // 5-8s typical. Slower than Graph but acceptable for the
            // quarterly compliance-config cadence this discovery surface
            // serves.
            expected_collection_time_ms: Some(6000),
            memory_usage_mb: Some(120),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
