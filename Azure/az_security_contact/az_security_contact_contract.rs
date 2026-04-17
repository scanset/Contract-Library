//! Azure Security Contact CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_security_contact;
//  pub use az_security_contact::create_az_security_contact_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_security_contact_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_security_contact".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Security contact name (typically 'default')".to_string(),
            example_values: vec!["default".to_string()],
            validation_notes: Some(
                "Only 'default' is a valid name for security contacts.".to_string(),
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

    // strings
    for (name, ops, desc, example) in [
        ("name", str_eq.clone(), "Contact name", "default"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../securityContacts/default"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Security/securityContacts"),
        ("emails", str_full.clone(), "Notification email addresses", "security@example.com"),
        ("phone", str_full.clone(), "Phone number", "+15551234567"),
        ("alert_notifications_state", str_eq.clone(), "Alert notifications enabled", "On"),
        ("alert_notifications_severity", str_eq.clone(), "Minimum alert severity", "High"),
        ("notifications_by_role_state", str_eq.clone(), "Role-based notifications enabled", "On"),
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
    for (name, desc, example) in [
        ("found", "Whether the security contact was found", "true"),
        ("has_email", "Whether notification email is configured", "true"),
        ("has_phone", "Whether phone number is configured", "true"),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::Boolean,
                allowed_operations: bool_ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    // integers
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "notification_role_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of roles configured for notifications".to_string(),
            example_values: vec!["1".to_string()],
            validation_notes: None,
        });

    // record
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full security contact object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for role array and nested assertions.".to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for (obj, col) in [
        ("name", "name"),
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
        "name", "id", "type", "emails", "phone",
        "has_email", "has_phone",
        "alert_notifications_state", "alert_notifications_severity",
        "notifications_by_role_state", "notification_role_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "emails", "phone",
        "has_email", "has_phone",
        "alert_notifications_state", "alert_notifications_severity",
        "notifications_by_role_state", "notification_role_count",
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
        collector_type: "az_security_contact".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
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
