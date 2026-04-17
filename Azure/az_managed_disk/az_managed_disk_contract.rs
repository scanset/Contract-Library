//! Azure Managed Disk CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_managed_disk;
//  pub use az_managed_disk::create_az_managed_disk_contract;
//
///////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_managed_disk_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_managed_disk".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Managed disk name".to_string(),
            example_values: vec!["disk-example-data".to_string()],
            validation_notes: Some(
                "Passed to az disk show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the disk".to_string(),
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
        ("name", str_full.clone(), "Managed disk name", "disk-example-data"),
        ("id", str_full.clone(), "Full ARM resource ID", "/subscriptions/.../disks/disk-example-data"),
        ("type", str_eq.clone(), "ARM resource type", "Microsoft.Compute/disks"),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        ("resource_group", str_full.clone(), "Resource group", "rg-example-eastus"),
        ("provisioning_state", str_eq.clone(), "ARM provisioning state", "Succeeded"),
        ("disk_state", str_eq.clone(), "Disk state (Attached, Unattached, Reserved, etc.)", "Attached"),
        ("sku_name", str_eq.clone(), "SKU name (Premium_LRS, Standard_LRS, etc.)", "Premium_LRS"),
        ("sku_tier", str_eq.clone(), "SKU tier (Premium, Standard, etc.)", "Premium"),
        ("encryption_type", str_eq.clone(), "Encryption type", "EncryptionAtRestWithCustomerKey"),
        ("network_access_policy", str_eq.clone(), "Network access policy", "AllowAll"),
        ("public_network_access", str_eq.clone(), "Public network access", "Enabled"),
        ("os_type", str_eq.clone(), "OS type (Linux, Windows) - absent on data disks", "Linux"),
        ("hyper_v_generation", str_eq.clone(), "Hyper-V generation (V1, V2) - absent on data disks", "V2"),
        ("performance_tier", str_full.clone(), "Performance tier (P3, P6, P10, etc.)", "P6"),
        ("create_option", str_eq.clone(), "Creation option (Empty, FromImage, Copy, etc.)", "Empty"),
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
        ("found", "Whether the managed disk was found", "true", None),
        (
            "is_attached",
            "Whether the disk is attached to a VM",
            "true",
            Some("Derived: true when managedBy field is present."),
        ),
        (
            "has_disk_encryption_set",
            "Whether a disk encryption set is configured",
            "true",
            Some("Derived: true when encryption.diskEncryptionSetId is present."),
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
        ("disk_size_gb", "Disk size in GB", "50", None),
        ("disk_iops_read_write", "Provisioned IOPS for read/write", "240", None),
        ("disk_mbps_read_write", "Provisioned throughput in MBps", "50", None),
        ("zone_count", "Number of availability zones", "1", None),
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
            description: "Full Managed Disk object as RecordData".to_string(),
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
        "provisioning_state", "disk_state", "sku_name", "sku_tier",
        "encryption_type", "network_access_policy", "public_network_access",
        "os_type", "hyper_v_generation", "performance_tier", "create_option",
        "is_attached", "has_disk_encryption_set",
        "disk_size_gb", "disk_iops_read_write", "disk_mbps_read_write",
        "zone_count",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for field in &[
        "found", "name", "id", "type", "location", "resource_group",
        "provisioning_state", "disk_state", "sku_name", "sku_tier",
        "encryption_type", "network_access_policy", "public_network_access",
        "os_type", "hyper_v_generation", "performance_tier", "create_option",
        "is_attached", "has_disk_encryption_set",
        "disk_size_gb", "disk_iops_read_write", "disk_mbps_read_write",
        "zone_count",
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
        collector_type: "az_managed_disk".to_string(),
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
