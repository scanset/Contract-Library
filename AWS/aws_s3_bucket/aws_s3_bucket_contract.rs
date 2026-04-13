//! AWS S3 Bucket CTN Contract
//!
//! Validates AWS S3 bucket configuration via six sequential AWS CLI calls:
//! 1. get-bucket-encryption
//! 2. get-bucket-versioning
//! 3. get-public-access-block
//! 4. get-bucket-lifecycle-configuration
//! 5. get-bucket-policy
//! 6. get-bucket-location
//!
//! Results are merged into scalar fields and a single RecordData object
//! keyed under: Encryption, Versioning, PublicAccessBlock, Lifecycle, Policy, Location
//!
//! ## Example ESP Policy
//!
//! ```esp
//! STATE bucket_hardened
//!     found boolean = true
//!     versioning_status string = `Enabled`
//!     sse_algorithm string = `aws:kms`
//!     bucket_key_enabled boolean = true
//!     block_public_acls boolean = true
//!     ignore_public_acls boolean = true
//!     block_public_policy boolean = true
//!     restrict_public_buckets boolean = true
//!     lifecycle_enabled boolean = true
//!     has_bucket_policy boolean = true
//! STATE_END
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_s3_bucket_contracts;
//  pub use aws_s3_bucket_contracts::create_aws_s3_bucket_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    BehaviorType, CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec,
    PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for aws_s3_bucket CTN type
pub fn create_aws_s3_bucket_contract() -> CtnContract {
    let mut contract = CtnContract::new("aws_s3_bucket".to_string());

    // ========================================================================
    // Object requirements
    // ========================================================================

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "bucket_name".to_string(),
            data_type: DataType::String,
            description: "S3 bucket name (exact match)".to_string(),
            example_values: vec!["example-org-security-findings".to_string()],
            validation_notes: Some("Required; exact bucket name".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            description: "AWS region override".to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some("Uses AWS CLI default if not specified".to_string()),
        });

    // ========================================================================
    // State requirements
    // ========================================================================

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the bucket was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Basic existence check".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "bucket_name".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "Bucket name".to_string(),
            example_values: vec!["example-org-security-findings".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "region".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Bucket region (null LocationConstraint normalized to us-east-1)"
                .to_string(),
            example_values: vec!["us-east-1".to_string()],
            validation_notes: Some(
                "LocationConstraint null (us-east-1) is normalized to the string 'us-east-1'"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "versioning_status".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Versioning status".to_string(),
            example_values: vec!["Enabled".to_string(), "Suspended".to_string()],
            validation_notes: Some(
                "Absent if versioning has never been enabled on the bucket".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "sse_algorithm".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Server-side encryption algorithm".to_string(),
            example_values: vec!["aws:kms".to_string(), "AES256".to_string()],
            validation_notes: Some(
                "Absent if no encryption configuration exists on the bucket".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "kms_master_key_id".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::StartsWith,
            ],
            description: "KMS key ARN used for encryption".to_string(),
            example_values: vec![
                "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    .to_string(),
            ],
            validation_notes: Some("Only present when sse_algorithm is aws:kms".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "bucket_key_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether S3 Bucket Keys are enabled to reduce KMS API calls".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Only present when KMS encryption is configured".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "block_public_acls".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether public ACLs are blocked".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Absent if public access block is not configured on the bucket".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ignore_public_acls".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether public ACLs are ignored".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "block_public_policy".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether public bucket policies are blocked".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "restrict_public_buckets".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether public bucket access is restricted".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "lifecycle_enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether at least one enabled lifecycle rule exists".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived field; false if NoSuchLifecycleConfiguration or no enabled rules"
                    .to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_bucket_policy".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether a bucket policy is attached".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some("Derived field; false if NoSuchBucketPolicy".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "ssl_enforced".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether the bucket policy contains a Deny statement enforcing HTTPS-only access (aws:SecureTransport = false condition). Relevant to KSI-MLA-OSM (AU-9, SC-8).".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived from bucket policy statements. False when no policy exists or no matching Deny statement found.".to_string(),
            ),
        });

    // RecordData for deep inspection
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description:
                "Merged configuration from all API calls as RecordData for record check validation"
                    .to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some(
                "Keys: Encryption, Versioning, PublicAccessBlock, Lifecycle, Policy, Location, Tags (when include_tagging is set)"
                    .to_string(),
            ),
        });

    // Tag key state field — only populated when include_tagging behavior is set
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "tag_key".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
            ],
            description: "Value of a specific tag key. Field name format: tag_key:<TagKey>. Only collected when include_tagging behavior is set.".to_string(),
            example_values: vec![
                "tag_key:Environment → `demo`".to_string(),
                "tag_key:ManagedBy → `terraform`".to_string(),
            ],
            validation_notes: Some(
                "Requires include_tagging behavior. Use field name tag_key:<Key> in STATE block.".to_string(),
            ),
        });

    // ========================================================================
    // Behaviors
    // ========================================================================

    contract.add_supported_behavior(SupportedBehavior {
        name: "include_tagging".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Collect bucket tags via get-bucket-tagging (adds one API call). Exposes tag values as scalar fields (tag_key:<Key>) and under Tags.TagSet.* in RecordData. Off by default.".to_string(),
        example: "behavior include_tagging".to_string(),
    });

    // ========================================================================
    // Field mappings
    // ========================================================================

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("bucket_name".to_string(), "bucket_name".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("region".to_string(), "region".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string(), "resource".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "bucket_name".to_string(),
        "region".to_string(),
        "versioning_status".to_string(),
        "sse_algorithm".to_string(),
        "kms_master_key_id".to_string(),
        "bucket_key_enabled".to_string(),
        "block_public_acls".to_string(),
        "ignore_public_acls".to_string(),
        "block_public_policy".to_string(),
        "restrict_public_buckets".to_string(),
        "lifecycle_enabled".to_string(),
        "has_bucket_policy".to_string(),
        "ssl_enforced".to_string(),
        // tag_key:<Key> fields are dynamic — not listed statically here
    ];

    for field in &[
        "found",
        "bucket_name",
        "region",
        "versioning_status",
        "sse_algorithm",
        "kms_master_key_id",
        "bucket_key_enabled",
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
        "lifecycle_enabled",
        "has_bucket_policy",
        "ssl_enforced",
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
        collector_type: "aws_s3_bucket".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["aws_cli".to_string(), "s3_read".to_string()],
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
