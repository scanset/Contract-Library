//! AWS SSO Admin Permission Set CTN Contract
//!
//! Validates IAM Identity Center permission set configuration via four calls:
//! 1. sso-admin list-permission-sets        → find ARN by name
//! 2. sso-admin describe-permission-set     → name, description, session duration
//! 3. sso-admin list-managed-policies-in-permission-set → managed policy attachments
//! 4. sso-admin get-inline-policy-for-permission-set    → inline policy (JSON string)
//!
//! Object requires both permission_set_name and instance_arn.
//! InlinePolicy is a JSON-encoded string — parsed and stored under InlinePolicy key.
//! SessionDuration is ISO 8601: "PT2H", "PT4H", "PT8H" — stored as string.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_ssoadmin_permission;
//  pub use aws_ssoadmin_permission::create_aws_ssoadmin_permission_set_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_aws_ssoadmin_permission_set_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_ssoadmin_permission_set".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "permission_set_name".to_string(),
            data_type: DataType::String,
            description: "Permission set name (exact match)".to_string(),
            example_values: vec![
                "ExampleOrgAdmin".to_string(),
                "ExampleOrgReadOnly".to_string(),
            ],
            validation_notes: Some(
                "Used to find the permission set ARN via list-permission-sets + describe loop"
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "instance_arn".to_string(),
            data_type: DataType::String,
            description: "IAM Identity Center instance ARN".to_string(),
            example_values: vec!["arn:aws:sso:::instance/ssoins-722365ac4d8ffe22".to_string()],
            validation_notes: Some(
                "Required for all sso-admin API calls. Use aws sso-admin list-instances to find."
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: None,
        });

    // ========================================================================
    // State requirements
    // ========================================================================

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

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the permission set was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "permission_set_name".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Permission set name".to_string(),
            example_values: vec!["ExampleOrgAdmin".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "permission_set_arn".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Permission set ARN".to_string(),
            example_values: vec![
                "arn:aws:sso:::permissionSet/ssoins-722365ac4d8ffe22/ps-ca776cd98f98270a"
                    .to_string(),
            ],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            allowed_operations: str_full.clone(),
            description: "Permission set description".to_string(),
            example_values: vec!["Full admin access to ExampleOrg infrastructure".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "session_duration".to_string(),
            data_type: DataType::String,
            allowed_operations: str_eq.clone(),
            description: "Session duration in ISO 8601 format".to_string(),
            example_values: vec!["PT2H".to_string(), "PT4H".to_string(), "PT8H".to_string()],
            validation_notes: Some(
                "ISO 8601 duration string — PT2H = 2 hours, PT4H = 4 hours, PT8H = 8 hours"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "managed_policy_count".to_string(),
            data_type: DataType::Int,
            allowed_operations: int_ops.clone(),
            description: "Number of managed policies attached to the permission set".to_string(),
            example_values: vec!["1".to_string(), "0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_inline_policy".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether an inline policy is attached".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some(
                "Derived: true when InlinePolicy field is a non-empty string".to_string(),
            ),
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "record".to_string(),
        data_type: DataType::RecordData,
        allowed_operations: vec![Operation::Equals],
        description: "Merged permission set config + managed policies + parsed inline policy"
            .to_string(),
        example_values: vec!["See record_checks".to_string()],
        validation_notes: Some(
            "Keys: PermissionSet (describe), AttachedManagedPolicies (list-managed-policies), InlinePolicy (parsed from JSON string)".to_string(),
        ),
    });

    // ========================================================================
    // Field mappings
    // ========================================================================

    for field in &["permission_set_name", "instance_arn", "region"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "permission_set_name".to_string(),
        "permission_set_arn".to_string(),
        "description".to_string(),
        "session_duration".to_string(),
        "managed_policy_count".to_string(),
        "has_inline_policy".to_string(),
    ];

    for field in &[
        "found",
        "permission_set_name",
        "permission_set_arn",
        "description",
        "session_duration",
        "managed_policy_count",
        "has_inline_policy",
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

    // ========================================================================
    // Collection strategy
    // ========================================================================

    contract.collection_strategy = CollectionStrategy {
        collector_type: "aws_ssoadmin_permission_set".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "sso_admin_read".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(6000),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
