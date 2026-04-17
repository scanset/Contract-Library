//! Azure Recovery Services Vault CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_recovery_services_vault;
//  pub use az_recovery_services_vault::create_az_recovery_services_vault_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_recovery_services_vault_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_recovery_services_vault".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Recovery Services vault name".to_string(),
            example_values: vec!["rsv-example-prod".to_string()],
            validation_notes: Some(
                "Passed to az backup vault show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the vault".to_string(),
            example_values: vec!["rg-example-eastus".to_string()],
            validation_notes: None,
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
        ("name", str_full.clone(), "Vault name", "rsv-example-prod"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../vaults/rsv-example-prod"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.RecoveryServices/vaults"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("sku_name", str_eq.clone(), "SKU name", "Standard"),
        ("identity_type", str_eq.clone(), "Managed identity type", "None"),
        ("public_network_access", str_eq.clone(), "Public network access", "Enabled"),
        ("secure_score", str_eq.clone(), "Azure secure score rating", "Minimum"),
        ("bcdr_security_level", str_eq.clone(), "BCDR security level", "Fair"),
        ("storage_redundancy", str_eq.clone(), "Storage redundancy type", "GeoRedundant"),
        ("cross_region_restore", str_eq.clone(), "Cross-region restore state", "Enabled"),
        ("soft_delete_state", str_eq.clone(), "Soft delete state", "Enabled"),
        ("enhanced_security_state", str_eq.clone(), "Enhanced security state", "Enabled"),
        ("immutability_state", str_eq.clone(), "Immutability state", "Unlocked"),
        ("multi_user_authorization", str_eq.clone(), "Multi-user authorization", "Disabled"),
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
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the vault was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    // integers
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "soft_delete_retention_days".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Soft delete retention period in days".to_string(),
            example_values: vec!["14".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Full Recovery Services Vault object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and nested assertions.".to_string(),
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
        "name", "id", "type", "location", "resource_group",
        "provisioning_state", "sku_name", "identity_type",
        "public_network_access", "secure_score", "bcdr_security_level",
        "storage_redundancy", "cross_region_restore",
        "soft_delete_state", "soft_delete_retention_days",
        "enhanced_security_state", "immutability_state",
        "multi_user_authorization",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "sku_name", "identity_type",
        "public_network_access", "secure_score", "bcdr_security_level",
        "storage_redundancy", "cross_region_restore",
        "soft_delete_state", "soft_delete_retention_days",
        "enhanced_security_state", "immutability_state",
        "multi_user_authorization",
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
        collector_type: "az_recovery_services_vault".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
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
