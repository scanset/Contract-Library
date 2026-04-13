//! OpenSSL Certificate CTN Contract
//!
//! Inspects X.509 certificates via `openssl x509` and parses subject, issuer,
//! validity dates, and common name. Platform-agnostic.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod openssl_cert;
//  pub use openssl_cert::create_openssl_cert_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_openssl_cert_contract() -> CtnContract {
    let mut contract = CtnContract::new("openssl_cert".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "Path to the X.509 certificate file".to_string(),
            example_values: vec![
                "/var/lib/pgsql/16/data/server.crt".to_string(),
                "/etc/pki/tls/certs/ca-bundle.crt".to_string(),
            ],
            validation_notes: Some("Absolute path to PEM or DER certificate file".to_string()),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the certificate file exists and is parseable".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("False if file missing or not a valid certificate".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "subject".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Full subject line from the certificate".to_string(),
            example_values: vec!["CN=localhost".to_string()],
            validation_notes: Some("Raw subject string from openssl x509 -subject".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "issuer".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Full issuer line from the certificate".to_string(),
            example_values: vec!["CN=localhost".to_string()],
            validation_notes: Some("Raw issuer string from openssl x509 -issuer".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "cn".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Common Name extracted from the subject".to_string(),
            example_values: vec!["localhost".to_string()],
            validation_notes: Some(
                "Extracted from subject CN= field. Use for PKI identity matching.".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "not_before".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Certificate validity start date".to_string(),
            example_values: vec!["Apr 10 00:44:04 2026 GMT".to_string()],
            validation_notes: Some("Raw date string from openssl x509 -startdate".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "not_after".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Certificate validity end date".to_string(),
            example_values: vec!["Apr 10 00:44:04 2027 GMT".to_string()],
            validation_notes: Some("Raw date string from openssl x509 -enddate".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "self_signed".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the certificate is self-signed (subject == issuer)".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: true when subject and issuer are identical".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "subject".to_string(),
        "issuer".to_string(),
        "cn".to_string(),
        "not_before".to_string(),
        "not_after".to_string(),
        "self_signed".to_string(),
    ];

    for field in &["found", "subject", "issuer", "cn", "not_before", "not_after", "self_signed"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "openssl_cert".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["openssl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
