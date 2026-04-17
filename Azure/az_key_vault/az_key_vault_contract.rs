//! Azure Key Vault CTN Contract

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/contracts/mod.rs)
//
//  pub mod az_key_vault;
//  pub use az_key_vault::create_az_key_vault_contract;
//
///////////////////////////////////////////////////////

//! Validates an Azure Key Vault via `az keyvault show --name <name>`.
//! Phase 1 — control-plane only (no data-plane enumeration of keys/secrets/
//! certificates). Data-plane behavior modifiers planned for Phase 2 once the
//! scanning SPN has the `Key Vault Reader` data-plane role.
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE kv_hardened
//!     found boolean = true
//!     enable_rbac_authorization boolean = true
//!     enable_purge_protection boolean = true
//!     enable_soft_delete boolean = true
//!     public_network_access string = `Disabled`
//!     provisioning_state string = `Succeeded`
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

pub fn create_az_key_vault_contract() -> CtnContract {
    let mut contract = CtnContract::new("az_key_vault".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Key Vault name (exact match)".to_string(),
            example_values: vec!["kv-prooflayer-demo-ybuu".to_string()],
            validation_notes: Some(
                "Passed to az keyvault show --name. 3-24 chars, alphanumeric and hyphens."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "resource_group".to_string(),
            data_type: DataType::String,
            description: "Resource group name (optional disambiguation)".to_string(),
            example_values: vec!["rg-prooflayer-demo-eastus".to_string()],
            validation_notes: Some(
                "Passed as --resource-group. Not required; az keyvault show resolves by name \
                 across the caller's accessible subscriptions."
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
            "Key Vault name",
            "kv-prooflayer-demo-ybuu",
        ),
        (
            "id",
            str_full.clone(),
            "Full ARM resource ID",
            "/subscriptions/.../vaults/kv-prooflayer-demo-ybuu",
        ),
        ("location", str_eq.clone(), "Azure region", "eastus"),
        (
            "resource_group",
            str_full.clone(),
            "Resource group that owns the vault",
            "rg-prooflayer-demo-eastus",
        ),
        (
            "vault_uri",
            str_full.clone(),
            "Data-plane URI",
            "https://kv-prooflayer-demo-ybuu.vault.azure.net/",
        ),
        (
            "tenant_id",
            str_eq.clone(),
            "Entra tenant GUID that owns the vault",
            "11111111-1111-1111-1111-111111111111",
        ),
        (
            "sku_family",
            str_eq.clone(),
            "SKU family (A = standard family)",
            "A",
        ),
        (
            "sku_name",
            str_eq.clone(),
            "SKU: standard or premium (premium enables HSM-backed keys)",
            "standard",
        ),
        (
            "provisioning_state",
            str_eq.clone(),
            "ARM provisioning state",
            "Succeeded",
        ),
        (
            "public_network_access",
            str_eq.clone(),
            "Whether the data-plane endpoint is reachable from the public internet",
            "Disabled",
        ),
        (
            "network_acl_default_action",
            str_eq.clone(),
            "properties.networkAcls.defaultAction - `Allow` lets every caller not \
             explicitly denied reach the vault; `Deny` denies every caller not explicitly \
             allowed via ipRules/virtualNetworkRules. Empty string when networkAcls is absent.",
            "Deny",
        ),
        (
            "network_acl_bypass",
            str_eq.clone(),
            "properties.networkAcls.bypass - exemption list for Azure platform callers. \
             `AzureServices` allows trusted Microsoft services through the deny. `None` \
             denies them too. Empty string when networkAcls is absent.",
            "AzureServices",
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
            "Whether the Key Vault was found",
            "true",
            None,
        ),
        (
            "enable_rbac_authorization",
            "Whether the vault uses RBAC (true) or legacy access policies (false)",
            "true",
            Some("RBAC is recommended. Legacy access policies are harder to audit."),
        ),
        (
            "enable_purge_protection",
            "Whether permanent purge of soft-deleted items is blocked",
            "true",
            Some("Once enabled, cannot be disabled. Required for many FedRAMP/CIS profiles."),
        ),
        (
            "enable_soft_delete",
            "Whether soft-delete is enabled (deleted items recoverable for N days)",
            "true",
            Some("Cannot be disabled on new vaults since 2020."),
        ),
        (
            "enabled_for_deployment",
            "Whether ARM templates can retrieve secrets for VM deployment",
            "false",
            Some("Usually false; enabling broadens the attack surface."),
        ),
        (
            "enabled_for_disk_encryption",
            "Whether Azure Disk Encryption can unwrap keys",
            "false",
            None,
        ),
        (
            "enabled_for_template_deployment",
            "Whether ARM templates can retrieve secrets",
            "false",
            None,
        ),
        (
            "has_network_acls",
            "Whether networkAcls is configured (derived: true when properties.networkAcls != null)",
            "false",
            Some(
                "When true, also check `network_acl_default_action` / `network_acl_bypass` / \
                 `network_acl_ip_rule_count` / `network_acl_vnet_rule_count` for the actual \
                 posture. has_network_acls=true but default_action='Allow' is not a hardened \
                 configuration.",
            ),
        ),
        (
            "network_acl_denies_by_default",
            "Derived: true when network_acl_default_action is `Deny`. The canonical \
             compliance bit for vault network exposure - `Deny` means the firewall is \
             enforcing an allowlist rather than a denylist.",
            "true",
            Some(
                "Pair with `public_network_access = 'Disabled'` or with a non-empty \
                 `network_acl_vnet_rule_count` / `network_acl_ip_rule_count` depending on \
                 whether the vault is fully private or access-listed.",
            ),
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
            "soft_delete_retention_days",
            "Number of days soft-deleted items are retained (7-90)",
            "90",
            Some(
                "Field is omitted from collected data when the API returns null (Azure default). \
                 Use `field properties.softDeleteRetentionInDays int = 90` via record_checks if \
                 you need to assert on the null case.",
            ),
        ),
        (
            "access_policy_count",
            "Number of legacy access policy entries (0 when RBAC mode)",
            "0",
            None,
        ),
        (
            "private_endpoint_count",
            "Number of private endpoint connections attached to the vault",
            "1",
            Some("0 when properties.privateEndpointConnections is null or empty."),
        ),
        (
            "network_acl_ip_rule_count",
            "Number of entries in properties.networkAcls.ipRules[] - public IP / CIDR \
             allowlist entries. 0 when networkAcls absent or ipRules empty.",
            "0",
            Some(
                "Nonzero values on a vault with public_network_access='Disabled' indicate \
                 dead config (private endpoint supersedes the firewall). Most hardened \
                 vaults have ip_rule_count=0 and rely on vnet_rule_count or private endpoints.",
            ),
        ),
        (
            "network_acl_vnet_rule_count",
            "Number of entries in properties.networkAcls.virtualNetworkRules[] - subnet \
             allowlist entries. 0 when networkAcls absent or virtualNetworkRules empty.",
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
            description: "Full key vault object as RecordData".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Use record_checks for tag and nested-field assertions: \
                 `field tags.Environment string = \\`demo\\`` or \
                 `field properties.networkAcls.defaultAction string = \\`Deny\\``."
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
        "location".to_string(),
        "resource_group".to_string(),
        "vault_uri".to_string(),
        "tenant_id".to_string(),
        "sku_family".to_string(),
        "sku_name".to_string(),
        "provisioning_state".to_string(),
        "public_network_access".to_string(),
        "network_acl_default_action".to_string(),
        "network_acl_bypass".to_string(),
        "enable_rbac_authorization".to_string(),
        "enable_purge_protection".to_string(),
        "enable_soft_delete".to_string(),
        "enabled_for_deployment".to_string(),
        "enabled_for_disk_encryption".to_string(),
        "enabled_for_template_deployment".to_string(),
        "has_network_acls".to_string(),
        "network_acl_denies_by_default".to_string(),
        "soft_delete_retention_days".to_string(),
        "access_policy_count".to_string(),
        "private_endpoint_count".to_string(),
        "network_acl_ip_rule_count".to_string(),
        "network_acl_vnet_rule_count".to_string(),
    ];

    for field in &[
        "found",
        "name",
        "id",
        "location",
        "resource_group",
        "vault_uri",
        "tenant_id",
        "sku_family",
        "sku_name",
        "provisioning_state",
        "public_network_access",
        "network_acl_default_action",
        "network_acl_bypass",
        "enable_rbac_authorization",
        "enable_purge_protection",
        "enable_soft_delete",
        "enabled_for_deployment",
        "enabled_for_disk_encryption",
        "enabled_for_template_deployment",
        "has_network_acls",
        "network_acl_denies_by_default",
        "soft_delete_retention_days",
        "access_policy_count",
        "private_endpoint_count",
        "network_acl_ip_rule_count",
        "network_acl_vnet_rule_count",
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
        collector_type: "az_key_vault".to_string(),
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
