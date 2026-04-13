//! TLS Probe CTN Contract
//!
//! Connects to a host:port via TLS handshake and reports the negotiated
//! protocol version, cipher suite, certificate chain details, and
//! connection success/failure. Uses `openssl s_client` under the hood.
//! Platform-agnostic.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod tls_probe;
//  pub use tls_probe::create_tls_probe_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_tls_probe_contract() -> CtnContract {
    let mut contract = CtnContract::new("tls_probe".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "host".to_string(),
            data_type: DataType::String,
            description: "Hostname or IP to connect to".to_string(),
            example_values: vec![
                "localhost".to_string(),
                "10.0.0.1".to_string(),
                "api.example.com".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "port".to_string(),
            data_type: DataType::String,
            description: "Port number".to_string(),
            example_values: vec![
                "443".to_string(),
                "6443".to_string(),
                "5432".to_string(),
                "2379".to_string(),
            ],
            validation_notes: Some("String type to allow variable substitution".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "servername".to_string(),
            data_type: DataType::String,
            description: "SNI server name for the TLS handshake".to_string(),
            example_values: vec!["api.example.com".to_string()],
            validation_notes: Some("Used with -servername flag. Defaults to host value.".to_string()),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "connected".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether TLS handshake completed successfully".to_string(),
            example_values: vec!["true".to_string()],
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
            description: "Negotiated TLS protocol version".to_string(),
            example_values: vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cipher".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Negotiated cipher suite".to_string(),
            example_values: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cert_subject".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Subject of the server certificate".to_string(),
            example_values: vec!["CN=localhost".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cert_issuer".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Issuer of the server certificate".to_string(),
            example_values: vec!["CN=localhost".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cert_not_after".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Certificate expiration date".to_string(),
            example_values: vec!["Apr 10 00:44:04 2027 GMT".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "self_signed".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the certificate is self-signed".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some("Derived: subject == issuer".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "verify_result".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "OpenSSL verification result string".to_string(),
            example_values: vec!["ok".to_string(), "self-signed certificate".to_string()],
            validation_notes: None,
        });

    // -- Field mappings -----------------------------------------------

    for field in &["host", "port", "servername"] {
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
        "protocol".to_string(),
        "cipher".to_string(),
        "cert_subject".to_string(),
        "cert_issuer".to_string(),
        "cert_not_after".to_string(),
        "self_signed".to_string(),
        "verify_result".to_string(),
    ];

    for field in &[
        "connected", "protocol", "cipher", "cert_subject", "cert_issuer",
        "cert_not_after", "self_signed", "verify_result",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "tls_probe".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["openssl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(2000),
            memory_usage_mb: Some(1),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
