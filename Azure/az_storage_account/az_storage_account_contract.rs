//! Azure Storage Account CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_storage_account;
//  pub use az_storage_account::create_az_storage_account_contract;
//
///////////////////////////////////////////////////////

//! Read-only, control-plane-only. Validates an Azure Storage Account via
//! `az storage account show --name <name> --resource-group <rg>`. Does NOT
//! enumerate containers, blobs, queues, tables, shares, keys, or SAS tokens.
//! Requires only the `Reader` role at subscription, RG, or account scope.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE storage_hardened
//!     found boolean = true
//!     provisioning_state string = `Succeeded`
//!     enable_https_traffic_only boolean = true
//!     minimum_tls_version string = `TLS1_2`
//!     allow_blob_public_access boolean = false
//!     allow_cross_tenant_replication boolean = false
//!     blob_encryption_enabled boolean = true
//!     file_encryption_enabled boolean = true
//!     record
//!         field tags.Environment string = `demo`
//!         field tags.FedRAMPImpactLevel string = `moderate`
//!     record_end
//! STATE_END
//! ```

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_az_storage_account_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_storage_account".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Storage account name (globally unique, 3-24 lowercase alnum)"
                .to_string(),
            example_values: vec!["stlogsprooflayerdemog71v".to_string()],
            validation_notes: Some(
                "Passed to az storage account show --name. 3-24 chars, lowercase letters and digits \
                 only. Azure does no client-side validation: malformed names return ResourceNotFound \
                 at runtime, same as genuinely missing accounts."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name that owns the account".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Required by az storage account show (unlike az keyvault show, which can resolve by \
                 name alone). Storage account names are globally unique but the CLI demands the RG."
                    .to_string(),
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
        (
            "name",
            str_full.clone(),
            "Storage account name",
            "stlogsprooflayerdemog71v",
        ),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../storageAccounts/stlogsprooflayerdemog71v",
        ),
        (
            "type",
            str_eq.clone(),
            "ARM resource type (always Microsoft.Storage/storageAccounts)",
            "Microsoft.Storage/storageAccounts",
        ),
        (
            "kind",
            str_eq.clone(),
            "Storage kind (StorageV2, Storage, BlobStorage, FileStorage, BlockBlobStorage)",
            "StorageV2",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the account",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "access_tier",
            str_eq.clone(),
            "Blob access tier (Hot, Cool, Premium)",
            "Hot",
        ),
        (
            "sku_name",
            str_eq.clone(),
            "SKU name (e.g. Standard_LRS, Standard_GRS, Premium_LRS)",
            "Standard_LRS",
        ),
        (
            "sku_tier",
            str_eq.clone(),
            "SKU tier (Standard or Premium)",
            "Standard",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "status_of_primary",
            str_eq.clone(),
            "Availability of primary region",
            "available",
        ),
        (
            "primary_location",
            str_eq.clone(),
            "Primary region where the account resides",
            "eastus",
        ),
        (
            "secondary_location",
            str_eq.clone(),
            "Secondary region (empty for LRS, set for GRS/RA-GRS)",
            "westus",
        ),
        (
            "minimum_tls_version",
            str_eq.clone(),
            "Minimum TLS version accepted at the data-plane (TLS1_0, TLS1_1, TLS1_2)",
            "TLS1_2",
        ),
        (
            "public_network_access",
            str_eq.clone(),
            "Whether public internet can reach the account endpoints (Enabled / Disabled)",
            "Disabled",
        ),
        (
            "dns_endpoint_type",
            str_eq.clone(),
            "DNS endpoint type (Standard or AzureDnsZone)",
            "Standard",
        ),
        (
            "encryption_key_source",
            str_eq.clone(),
            "Encryption key source: Microsoft.Storage (platform-managed) or Microsoft.Keyvault (CMK)",
            "Microsoft.Keyvault",
        ),
        (
            "network_default_action",
            str_eq.clone(),
            "Network ACL default action (Allow or Deny)",
            "Deny",
        ),
        (
            "network_bypass",
            str_eq.clone(),
            "Network ACL bypass set (None, Logging, Metrics, AzureServices or comma-joined)",
            "AzureServices",
        ),
        (
            "identity_type",
            str_eq.clone(),
            "Managed identity type (None, SystemAssigned, UserAssigned, SystemAssigned,UserAssigned)",
            "SystemAssigned",
        ),
        (
            "key_creation_time_key1",
            str_eq.clone(),
            "ISO 8601 timestamp when storage key1 was created/rotated",
            "2024-01-15T10:30:00.0000000Z",
        ),
        (
            "key_creation_time_key2",
            str_eq.clone(),
            "ISO 8601 timestamp when storage key2 was created/rotated",
            "2024-01-15T10:30:00.0000000Z",
        ),
        (
            "large_file_shares_state",
            str_eq.clone(),
            "Large file shares state (Enabled or Disabled; null when not applicable)",
            "Disabled",
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

    // boolean compliance switches
    for (name, desc, example, notes) in [
        (
            "found",
            "Whether the storage account was found",
            "true",
            None,
        ),
        (
            "enable_https_traffic_only",
            "Whether only HTTPS is accepted at the data-plane",
            "true",
            Some("Must be true for nearly every compliance baseline (SC-8)."),
        ),
        (
            "allow_blob_public_access",
            "Whether containers may be configured for anonymous public access",
            "false",
            Some("Should be false. Individual containers still need their own access level set."),
        ),
        (
            "allow_shared_key_access",
            "Whether shared-key (account-key) auth is permitted alongside Entra auth",
            "false",
            Some("False = OAuth/Entra-only, which eliminates key-leak attack surface."),
        ),
        (
            "allow_cross_tenant_replication",
            "Whether accounts in other tenants may configure object replication from this account",
            "false",
            Some("Should be false unless you have a documented cross-tenant data-sharing need."),
        ),
        (
            "default_to_oauth_authentication",
            "Whether the portal defaults to OAuth auth instead of shared key when browsing data",
            "true",
            None,
        ),
        (
            "is_hns_enabled",
            "Hierarchical Namespace (Azure Data Lake Storage Gen2)",
            "false",
            None,
        ),
        (
            "is_sftp_enabled",
            "Whether the SFTP endpoint is enabled (HNS-only feature)",
            "false",
            Some("Usually false. Enabling exposes a second data-plane protocol."),
        ),
        (
            "is_local_user_enabled",
            "Whether local SFTP users are provisioned (HNS-only feature)",
            "false",
            None,
        ),
        (
            "enable_nfs_v3",
            "Whether the NFSv3 data-plane protocol is enabled (HNS-only feature)",
            "false",
            None,
        ),
        (
            "cmk_enabled",
            "Derived: true when encryption.keySource == Microsoft.Keyvault",
            "false",
            Some(
                "Mirrors encryption_key_source but as a boolean for simpler policy expressions.",
            ),
        ),
        (
            "require_infrastructure_encryption",
            "Whether double-encryption at the infrastructure layer is required (null-safe: false when null)",
            "false",
            None,
        ),
        (
            "blob_encryption_enabled",
            "Whether service-level encryption is enabled on the blob service",
            "true",
            Some("Platform-managed or CMK; rarely false on new accounts."),
        ),
        (
            "file_encryption_enabled",
            "Whether service-level encryption is enabled on the file service",
            "true",
            None,
        ),
        (
            "queue_encryption_enabled",
            "Whether service-level encryption is enabled on the queue service (null when queues unused)",
            "true",
            None,
        ),
        (
            "table_encryption_enabled",
            "Whether service-level encryption is enabled on the table service (null when tables unused)",
            "true",
            None,
        ),
        (
            "has_network_acls",
            "Derived: true when networkRuleSet.defaultAction == 'Deny'",
            "true",
            Some(
                "Allow + empty rules == wide open. Deny + rules == proper allowlist posture.",
            ),
        ),
        (
            "has_private_endpoints",
            "Derived: true when privateEndpointConnections.len() > 0",
            "true",
            None,
        ),
        (
            "has_managed_identity",
            "Derived: true when identity.type != 'None'",
            "true",
            None,
        ),
        (
            "immutable_storage_enabled",
            "Account-level immutable storage with versioning (WORM). False when null or absent.",
            "false",
            Some("Required for SEC 17a-4 / FedRAMP write-once compliance."),
        ),
        (
            "blob_soft_delete_enabled",
            "Whether blob soft delete is enabled (behavior include_blob_properties true required)",
            "true",
            Some("From az storage account blob-service-properties show. Only populated when behavior include_blob_properties true is set."),
        ),
        (
            "container_soft_delete_enabled",
            "Whether container soft delete is enabled (behavior include_blob_properties true required)",
            "true",
            Some("From az storage account blob-service-properties show. Only populated when behavior include_blob_properties true is set."),
        ),
        (
            "versioning_enabled",
            "Whether blob versioning is enabled (behavior include_blob_properties true required)",
            "true",
            Some("From az storage account blob-service-properties show. Only populated when behavior include_blob_properties true is set."),
        ),
        (
            "change_feed_enabled",
            "Whether change feed is enabled (behavior include_blob_properties true required)",
            "true",
            Some("From az storage account blob-service-properties show. Only populated when behavior include_blob_properties true is set."),
        ),
        (
            "last_access_time_enabled",
            "Whether last access time tracking is enabled (behavior include_blob_properties true required)",
            "false",
            Some("From az storage account blob-service-properties show. Only populated when behavior include_blob_properties true is set."),
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
            "ip_rule_count",
            "Number of IP allowlist rules in networkRuleSet",
            "0",
            None,
        ),
        (
            "vnet_rule_count",
            "Number of virtual-network subnet rules in networkRuleSet",
            "0",
            None,
        ),
        (
            "private_endpoint_count",
            "Number of approved private endpoint connections attached to the account",
            "0",
            Some("0 when privateEndpointConnections is null or empty."),
        ),
        (
            "blob_soft_delete_days",
            "Blob soft delete retention in days (behavior include_blob_properties true required)",
            "7",
            Some("From az storage account blob-service-properties show. Only populated when behavior is set and soft delete is enabled."),
        ),
        (
            "container_soft_delete_days",
            "Container soft delete retention in days (behavior include_blob_properties true required)",
            "7",
            Some("From az storage account blob-service-properties show. Only populated when behavior is set and container soft delete is enabled."),
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
            description: "Full storage account object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and nested-field assertions: \
                 `field tags.Environment string = \\`demo\\`` or \
                 `field networkRuleSet.defaultAction string = \\`Deny\\`` or \
                 `field encryption.keyVaultProperties.keyName string = \\`storage-cmk\\``."
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
        "kind".to_string(),
        "location".to_string(),
        "resource_group".to_string(),
        "access_tier".to_string(),
        "sku_name".to_string(),
        "sku_tier".to_string(),
        "provisioning_state".to_string(),
        "status_of_primary".to_string(),
        "primary_location".to_string(),
        "secondary_location".to_string(),
        "minimum_tls_version".to_string(),
        "public_network_access".to_string(),
        "dns_endpoint_type".to_string(),
        "encryption_key_source".to_string(),
        "network_default_action".to_string(),
        "network_bypass".to_string(),
        "identity_type".to_string(),
        "enable_https_traffic_only".to_string(),
        "allow_blob_public_access".to_string(),
        "allow_shared_key_access".to_string(),
        "allow_cross_tenant_replication".to_string(),
        "default_to_oauth_authentication".to_string(),
        "is_hns_enabled".to_string(),
        "is_sftp_enabled".to_string(),
        "is_local_user_enabled".to_string(),
        "enable_nfs_v3".to_string(),
        "cmk_enabled".to_string(),
        "require_infrastructure_encryption".to_string(),
        "blob_encryption_enabled".to_string(),
        "file_encryption_enabled".to_string(),
        "queue_encryption_enabled".to_string(),
        "table_encryption_enabled".to_string(),
        "has_network_acls".to_string(),
        "has_private_endpoints".to_string(),
        "has_managed_identity".to_string(),
        "immutable_storage_enabled".to_string(),
        "blob_soft_delete_enabled".to_string(),
        "container_soft_delete_enabled".to_string(),
        "versioning_enabled".to_string(),
        "change_feed_enabled".to_string(),
        "last_access_time_enabled".to_string(),
        "ip_rule_count".to_string(),
        "vnet_rule_count".to_string(),
        "private_endpoint_count".to_string(),
        "blob_soft_delete_days".to_string(),
        "container_soft_delete_days".to_string(),
        "key_creation_time_key1".to_string(),
        "key_creation_time_key2".to_string(),
        "large_file_shares_state".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "type",
        "kind",
        "location",
        "resource_group",
        "access_tier",
        "sku_name",
        "sku_tier",
        "provisioning_state",
        "status_of_primary",
        "primary_location",
        "secondary_location",
        "minimum_tls_version",
        "public_network_access",
        "dns_endpoint_type",
        "encryption_key_source",
        "network_default_action",
        "network_bypass",
        "identity_type",
        "enable_https_traffic_only",
        "allow_blob_public_access",
        "allow_shared_key_access",
        "allow_cross_tenant_replication",
        "default_to_oauth_authentication",
        "is_hns_enabled",
        "is_sftp_enabled",
        "is_local_user_enabled",
        "enable_nfs_v3",
        "cmk_enabled",
        "require_infrastructure_encryption",
        "blob_encryption_enabled",
        "file_encryption_enabled",
        "queue_encryption_enabled",
        "table_encryption_enabled",
        "has_network_acls",
        "has_private_endpoints",
        "has_managed_identity",
        "immutable_storage_enabled",
        "blob_soft_delete_enabled",
        "container_soft_delete_enabled",
        "versioning_enabled",
        "change_feed_enabled",
        "last_access_time_enabled",
        "ip_rule_count",
        "vnet_rule_count",
        "private_endpoint_count",
        "blob_soft_delete_days",
        "container_soft_delete_days",
        "key_creation_time_key1",
        "key_creation_time_key2",
        "large_file_shares_state",
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
        collector_type: "az_storage_account".to_string(),
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
