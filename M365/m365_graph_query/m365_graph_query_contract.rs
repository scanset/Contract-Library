//! Contract for the `m365_graph_query` CTN.
//!
//! Single-CTN discovery primitive for Microsoft Graph (M365 / Entra ID /
//! Intune / Purview / SharePoint / Teams). GETs an arbitrary collection
//! path and returns the result rows. Follows `@odata.nextLink` to
//! exhaust pagination transparently.
//!
//! ## Inputs
//!
//! - `path`   — Graph collection path (required). Leading slash optional.
//!              Examples: `/users`, `users`, `groups`,
//!              `identity/conditionalAccess/policies`,
//!              `deviceManagement/managedDevices`.
//! - `select` — optional `$select` clause (comma-separated field list).
//! - `filter` — optional `$filter` clause (OData filter expression).
//! - `expand` — optional `$expand` clause.
//! - `top`    — optional integer page size for `$top`. Defaults to 999.
//!              Special value `0` skips the `$top` parameter entirely —
//!              required for endpoints like
//!              `/identity/conditionalAccess/authenticationContextClassReferences`
//!              that reject `$top`.
//!
//! ## Outputs
//!
//! - `found`     — boolean.
//! - `row_count` — integer.
//! - `rows`      — RecordData (array of objects from Graph).

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_m365_graph_query_contract() -> CtnContract {
    let mut contract = CtnContract::new("m365_graph_query".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description:
                "Microsoft Graph collection path. GET against \
                 https://graph.microsoft.com/v1.0/<path>. Leading slash optional. \
                 The app registration must grant a Graph permission that covers \
                 the resource type (e.g. User.Read.All for /users)."
                    .to_string(),
            example_values: vec![
                "/users".to_string(),
                "groups".to_string(),
                "identity/conditionalAccess/policies".to_string(),
                "deviceManagement/managedDevices".to_string(),
            ],
            validation_notes: None,
        });

    for (name, desc, example) in [
        (
            "select",
            "Comma-separated field list for $select.",
            "id,displayName,userPrincipalName",
        ),
        (
            "filter",
            "OData filter expression for $filter.",
            "accountEnabled eq true",
        ),
        (
            "expand",
            "Related-resource expansion for $expand.",
            "memberOf",
        ),
    ] {
        contract
            .object_requirements
            .add_optional_field(ObjectFieldSpec {
                name: name.to_string(),
                data_type: DataType::String,
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "top".to_string(),
            data_type: DataType::Int,
            description:
                "Per-page result count for $top. Graph clamps each resource type \
                 to its own max (commonly 999). Default 999. \
                 Set to 0 to skip the $top parameter entirely — needed for \
                 the small handful of Graph endpoints that reject $top \
                 (e.g. authenticationContextClassReferences)."
                    .to_string(),
            example_values: vec!["999".to_string()],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "api_version".to_string(),
            data_type: DataType::String,
            description:
                "Graph API version. `v1.0` (default) for stable endpoints; `beta` \
                 for resources that haven't graduated yet (e.g. Purview \
                 sensitivity labels at `/informationProtection/policy/labels`). \
                 Beta endpoints are subject to breaking changes by Microsoft."
                    .to_string(),
            example_values: vec!["v1.0".to_string(), "beta".to_string()],
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
            description: "Whether the query executed and parsed successfully.".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "row_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops,
            description: "Number of rows returned across all pagination fetches.".to_string(),
            example_values: vec!["42".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "rows".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description:
                "Full result rows, each a JSON object from Graph. \
                 Discovery iterates this array and creates / enriches assets per-row."
                    .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    for (obj, col) in [
        ("path", "path"),
        ("select", "select"),
        ("filter", "filter"),
        ("expand", "expand"),
        ("top", "top"),
        ("api_version", "api_version"),
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
        .required_data_fields = vec!["found".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["row_count".to_string(), "rows".to_string()];

    for state_key in &["found", "row_count", "rows"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert((*state_key).to_string(), (*state_key).to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "m365_graph_query".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec![
            "azure_spn_env".to_string(),
            "graph_api_reader".to_string(),
        ],
        performance_hints: PerformanceHints {
            // Graph is fast at the API layer (~200-600ms typical). A
            // multi-page user list against a small tenant (3-10 pages)
            // can run 1-3s. Estimate is "single-page typical".
            expected_collection_time_ms: Some(800),
            memory_usage_mb: Some(8),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
