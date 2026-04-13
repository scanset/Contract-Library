//! HTTP Probe CTN Contract
//!
//! Makes an HTTP/HTTPS request to a URL and reports the status code,
//! response headers, protocol version, and body snippet.
//! Uses `curl` under the hood. Platform-agnostic.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod http_probe;
//  pub use http_probe::create_http_probe_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_http_probe_contract() -> CtnContract {
    let mut contract = CtnContract::new("http_probe".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "url".to_string(),
            data_type: DataType::String,
            description: "URL to probe".to_string(),
            example_values: vec![
                "https://localhost:443/".to_string(),
                "http://localhost:8080/health".to_string(),
            ],
            validation_notes: Some("Full URL including scheme".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "method".to_string(),
            data_type: DataType::String,
            description: "HTTP method".to_string(),
            example_values: vec!["GET".to_string(), "HEAD".to_string()],
            validation_notes: Some("Defaults to GET. Only GET and HEAD are safe.".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "insecure".to_string(),
            data_type: DataType::String,
            description: "Skip TLS certificate verification".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Defaults to false. Set true for self-signed certs.".to_string()),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "connected".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the HTTP request completed".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "status_code".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "HTTP response status code".to_string(),
            example_values: vec!["200".to_string(), "301".to_string(), "403".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "protocol".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "HTTP protocol version negotiated".to_string(),
            example_values: vec!["HTTP/2".to_string(), "HTTP/1.1".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "headers".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Raw response headers as a single string".to_string(),
            example_values: vec!["Strict-Transport-Security:".to_string()],
            validation_notes: Some(
                "Use contains to check for specific header presence".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "body".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Response body (first 4KB)".to_string(),
            example_values: vec![],
            validation_notes: Some(
                "Truncated to 4KB. Use contains/not_contains for content checks.".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "redirect_url".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Location header value if redirect".to_string(),
            example_values: vec!["https://example.com/".to_string()],
            validation_notes: None,
        });

    // -- Field mappings -----------------------------------------------

    for field in &["url", "method", "insecure"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["connected".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "status_code".to_string(),
        "protocol".to_string(),
        "headers".to_string(),
        "body".to_string(),
        "redirect_url".to_string(),
    ];

    for field in &["connected", "status_code", "protocol", "headers", "body", "redirect_url"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "http_probe".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["curl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(2),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
