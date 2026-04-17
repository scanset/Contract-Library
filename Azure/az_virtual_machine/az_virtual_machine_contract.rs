//! Azure Virtual Machine (VM) CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_virtual_machine;
//  pub use az_virtual_machine::create_az_virtual_machine_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates an Azure Virtual Machine
//! via `az vm show --name <name> --resource-group <rg>`. Exposes VM size,
//! OS type, storage profile (disks, encryption), security profile
//! (Trusted Launch, Secure Boot, vTPM, encryption at host), identity,
//! boot diagnostics, extensions (MDE), patching, and image reference.
//! Full VM document available as RecordData for tag-based record_checks.
//! Requires only the `Reader` role.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE vm_baseline
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     os_type string = `Linux`
//!     password_auth_disabled boolean = true
//!     boot_diagnostics_enabled boolean = true
//!     has_managed_identity boolean = true
//!     os_disk_encrypted_with_cmk boolean = true
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_virtual_machine_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_virtual_machine".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "VM name".to_string(),
            example_values: vec!["vm-prooflayer-demo".to_string()],
            validation_notes: Some(
                "Passed to az vm show --name.".to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the VM".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Required by az vm show.".to_string(),
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
        ("name", str_full.clone(), "VM name", "vm-prooflayer-demo"),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../virtualMachines/vm-prooflayer-demo",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type",
            "Microsoft.Compute/virtualMachines",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the VM",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "vm_id",
            str_full.clone(),
            "Azure-assigned unique VM identifier",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        ),
        (
            "vm_size",
            str_eq.clone(),
            "Hardware profile VM size",
            "Standard_D2s_v6",
        ),
        (
            "os_type",
            str_eq.clone(),
            "OS type from OS disk",
            "Linux",
        ),
        (
            "priority",
            str_eq.clone(),
            "VM priority (Regular or Spot)",
            "Regular",
        ),
        (
            "availability_zone",
            str_eq.clone(),
            "First availability zone (if zonal)",
            "1",
        ),
        (
            "os_disk_storage_type",
            str_eq.clone(),
            "OS disk managed disk storage account type",
            "Premium_LRS",
        ),
        (
            "disk_controller_type",
            str_eq.clone(),
            "Disk controller type",
            "NVMe",
        ),
        (
            "image_publisher",
            str_full.clone(),
            "Marketplace image publisher",
            "resf",
        ),
        (
            "image_offer",
            str_full.clone(),
            "Marketplace image offer",
            "rockylinux-x86_64",
        ),
        (
            "image_sku",
            str_full.clone(),
            "Marketplace image SKU",
            "9-base",
        ),
        (
            "image_version",
            str_full.clone(),
            "Exact image version",
            "9.6.20250531",
        ),
        (
            "admin_username",
            str_eq.clone(),
            "OS admin user name",
            "azureuser",
        ),
        (
            "patch_mode",
            str_eq.clone(),
            "OS patch mode",
            "ImageDefault",
        ),
        (
            "identity_type",
            str_eq.clone(),
            "Managed identity type",
            "UserAssigned",
        ),
        (
            "security_type",
            str_eq.clone(),
            "Security type (TrustedLaunch, ConfidentialVM, etc.)",
            "TrustedLaunch",
        ),
        (
            "time_created",
            str_full.clone(),
            "ISO 8601 VM creation timestamp",
            "2026-04-14T15:58:40.9910866+00:00",
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
        ("found", "Whether the VM was found", "true", None),
        (
            "boot_diagnostics_enabled",
            "Whether boot diagnostics is enabled",
            "true",
            None,
        ),
        (
            "has_managed_identity",
            "Whether any managed identity (System or User) is attached",
            "true",
            None,
        ),
        (
            "password_auth_disabled",
            "Whether password authentication is disabled (Linux VMs)",
            "true",
            Some("Only present for Linux VMs. True means SSH-key-only auth."),
        ),
        (
            "vm_agent_provisioned",
            "Whether the VM agent is provisioned",
            "true",
            None,
        ),
        (
            "allow_extension_operations",
            "Whether extension operations are allowed",
            "true",
            None,
        ),
        (
            "os_disk_encrypted_with_cmk",
            "Whether OS disk uses customer-managed key via DES",
            "true",
            Some("True when storageProfile.osDisk.managedDisk.diskEncryptionSet.id is present."),
        ),
        (
            "has_availability_zone",
            "Whether the VM is deployed in a specific availability zone",
            "true",
            None,
        ),
        (
            "secure_boot_enabled",
            "Whether UEFI Secure Boot is enabled (Trusted Launch)",
            "false",
            Some("Defaults false when securityProfile is absent."),
        ),
        (
            "vtpm_enabled",
            "Whether vTPM is enabled (Trusted Launch)",
            "false",
            Some("Defaults false when securityProfile is absent."),
        ),
        (
            "encryption_at_host",
            "Whether encryption at host is enabled",
            "false",
            Some("Defaults false when securityProfile is absent."),
        ),
        (
            "mde_extension_installed",
            "Whether Microsoft Defender for Endpoint extension is installed",
            "true",
            Some("Checks resources[] for an extension with name starting with 'MDE.'."),
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
            "os_disk_size_gb",
            "OS disk size in GB",
            "10",
            None,
        ),
        (
            "data_disk_count",
            "Number of data disks attached",
            "1",
            None,
        ),
        (
            "extension_count",
            "Number of VM extensions installed",
            "1",
            None,
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
            description: "Full VM object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag assertions and nested property checks."
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
        "type".to_string(),
        "location".to_string(),
        "resource_group".to_string(),
        "provisioning_state".to_string(),
        "vm_id".to_string(),
        "vm_size".to_string(),
        "os_type".to_string(),
        "priority".to_string(),
        "availability_zone".to_string(),
        "has_availability_zone".to_string(),
        "os_disk_size_gb".to_string(),
        "os_disk_storage_type".to_string(),
        "os_disk_encrypted_with_cmk".to_string(),
        "data_disk_count".to_string(),
        "disk_controller_type".to_string(),
        "image_publisher".to_string(),
        "image_offer".to_string(),
        "image_sku".to_string(),
        "image_version".to_string(),
        "admin_username".to_string(),
        "password_auth_disabled".to_string(),
        "vm_agent_provisioned".to_string(),
        "allow_extension_operations".to_string(),
        "patch_mode".to_string(),
        "boot_diagnostics_enabled".to_string(),
        "has_managed_identity".to_string(),
        "identity_type".to_string(),
        "secure_boot_enabled".to_string(),
        "vtpm_enabled".to_string(),
        "encryption_at_host".to_string(),
        "security_type".to_string(),
        "extension_count".to_string(),
        "mde_extension_installed".to_string(),
        "time_created".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "location",
        "resource_group",
        "provisioning_state",
        "vm_id",
        "vm_size",
        "os_type",
        "priority",
        "availability_zone",
        "has_availability_zone",
        "os_disk_size_gb",
        "os_disk_storage_type",
        "os_disk_encrypted_with_cmk",
        "data_disk_count",
        "disk_controller_type",
        "image_publisher",
        "image_offer",
        "image_sku",
        "image_version",
        "admin_username",
        "password_auth_disabled",
        "vm_agent_provisioned",
        "allow_extension_operations",
        "patch_mode",
        "boot_diagnostics_enabled",
        "has_managed_identity",
        "identity_type",
        "secure_boot_enabled",
        "vtpm_enabled",
        "encryption_at_host",
        "security_type",
        "extension_count",
        "mde_extension_installed",
        "time_created",
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
        collector_type: "az_virtual_machine".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["az_cli".to_string(), "reader".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(3000),
            memory_usage_mb: Some(4),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
