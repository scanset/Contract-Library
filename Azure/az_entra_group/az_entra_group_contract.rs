//! Azure Entra ID Group CTN Contract + Collector
//!
//! Single call: az ad group show --group <display_name_or_object_id>
//!
//! Key scalars: group_id (object id), display_name, description,
//!   security_enabled, mail_enabled
//! No tags on Entra groups.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_entra_group_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_entra_group".to_string());

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "display_name".to_string(),
            data_type: DataType::String,
            description: "Group display name or object ID".to_string(),
            example_values: vec!["aws-prooflayer-demo-admins".to_string()],
            validation_notes: Some("Passed directly to az ad group show --group".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_eq = vec![Operation::Equals, Operation::NotEqual];
    let str_full = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    for (name, dt, ops, desc, example) in &[
        (
            "found",
            DataType::Boolean,
            bool_ops.clone(),
            "Whether the group was found",
            "true",
        ),
        (
            "group_id",
            DataType::String,
            str_eq.clone(),
            "Group object ID",
            "44444444-4444-4444-4444-444444444444",
        ),
        (
            "display_name",
            DataType::String,
            str_eq.clone(),
            "Group display name",
            "aws-prooflayer-demo-admins",
        ),
        (
            "description",
            DataType::String,
            str_full.clone(),
            "Group description",
            "ProofLayer AWS admins - maps to ProofLayerAdmin permission set",
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: dt.clone(),
                allowed_operations: ops.clone(),
                description: desc.to_string(),
                example_values: vec![example.to_string()],
                validation_notes: None,
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "security_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the group is a security group".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Must be true for use in AWS SSO group assignments".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "mail_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the group is mail-enabled".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full group object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: None,
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("display_name".to_string(), "display_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "group_id".to_string(),
        "display_name".to_string(),
        "description".to_string(),
        "security_enabled".to_string(),
        "mail_enabled".to_string(),
    ];

    for field in &[
        "found",
        "group_id",
        "display_name",
        "description",
        "security_enabled",
        "mail_enabled",
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

    contract.collection_strategy = CollectionStrategy {
        collector_type: "az_entra_group".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "entra_read".to_string()],
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
