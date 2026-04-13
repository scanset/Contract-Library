//! AWS S3 Bucket Collector
//!
//! Collects S3 bucket configuration via six sequential AWS CLI calls (always),
//! plus an optional seventh call when the `include_tagging` behavior is set:
//!
//! 1. get-bucket-encryption      → sse_algorithm, kms_master_key_id, bucket_key_enabled
//! 2. get-bucket-versioning      → versioning_status
//! 3. get-public-access-block    → block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets
//! 4. get-bucket-lifecycle-configuration → lifecycle_enabled (derived)
//! 5. get-bucket-policy          → has_bucket_policy (derived), policy parsed from JSON string
//! 6. get-bucket-location        → region (null normalized to "us-east-1")
//! 7. get-bucket-tagging         → Tags.* record paths (only when include_tagging behavior is set)
//!
//! All responses are merged into a single RecordData under named keys:
//! Encryption, Versioning, PublicAccessBlock, Lifecycle, Policy, Location, Tags
//!
//! ## RecordData Field Paths
//!
//! ```text
//! Encryption.ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault.SSEAlgorithm → "aws:kms"
//! Encryption.ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled                                → true
//! Versioning.Status                                                                                     → "Enabled"
//! PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls                                      → true
//! PublicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets                                → true
//! Lifecycle.Rules.0.Status                                                                              → "Enabled"
//! Lifecycle.Rules.0.Expiration.Days                                                                     → 2555
//! Policy.Version                                                                                        → "2012-10-17"
//! Policy.Statement.0.Sid                                                                                → "DenyNonSSL"
//! Location.LocationConstraint                                                                           → null (us-east-1)
//!
//! ## Tags (only when include_tagging behavior is set)
//!
//! Tags are stored in two ways:
//!
//! 1. RecordData under Tags key — the raw TagSet array for record checks:
//!    Tags.TagSet.0.Key   → "Name"
//!    Tags.TagSet.0.Value → "example-org-security-findings"
//!
//! 2. Flattened scalar field `tag_key:<key>` for each tag — enables simple state checks:
//!    tag_key:Name        → "example-org-security-findings"
//!    tag_key:Environment → "demo"
//!    tag_key:ManagedBy   → "terraform"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_s3_bucket;
//  pub use aws_s3_bucket::AwsS3BucketCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS S3 bucket configuration
pub struct AwsS3BucketCollector {
    id: String,
}

impl AwsS3BucketCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_s3_bucket_collector".to_string(),
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    /// Returns true if the error string indicates a "not configured" condition
    /// that should be treated as absent fields rather than a collection failure.
    fn is_not_configured_error(err_str: &str) -> bool {
        err_str.contains("ServerSideEncryptionConfigurationNotFoundError")
            || err_str.contains("NoSuchPublicAccessBlockConfiguration")
            || err_str.contains("NoSuchLifecycleConfiguration")
            || err_str.contains("NoSuchBucketPolicy")
    }

    /// Returns true if the error string indicates the bucket itself does not exist.
    fn is_no_such_bucket_error(err_str: &str) -> bool {
        err_str.contains("NoSuchBucket")
    }
}

impl Default for AwsS3BucketCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsS3BucketCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let include_tagging = hints.has_flag("include_tagging");

        let bucket_name = self
            .extract_string_field(object, "bucket_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'bucket_name' is required for aws_s3_bucket".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_s3_bucket".to_string(),
            self.id.clone(),
        );

        // Traceability
        let target = format!("s3:{}", bucket_name);
        let cmd_description = if include_tagging {
            "Query S3 bucket configuration via AWS CLI (7 API calls, include_tagging enabled)"
        } else {
            "Query S3 bucket configuration via AWS CLI (6 API calls)"
        };
        let cmd_string = if include_tagging {
            "aws s3api get-bucket-encryption + get-bucket-versioning + get-public-access-block + get-bucket-lifecycle-configuration + get-bucket-policy + get-bucket-location + get-bucket-tagging"
        } else {
            "aws s3api get-bucket-encryption + get-bucket-versioning + get-public-access-block + get-bucket-lifecycle-configuration + get-bucket-policy + get-bucket-location"
        };
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description(cmd_description)
            .target(&target)
            .command(cmd_string)
            .input("bucket_name", &bucket_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        if include_tagging {
            method_builder = method_builder.input("include_tagging", "true");
        }
        data.set_method(method_builder.build());

        let bucket_args = ["--bucket", bucket_name.as_str()];

        // ====================================================================
        // Accumulators for RecordData merge
        // ====================================================================
        let mut encryption_val = serde_json::json!({});
        let mut versioning_val = serde_json::json!({});
        let mut public_access_val = serde_json::json!({});
        let mut lifecycle_val = serde_json::json!({});
        let mut policy_val = serde_json::json!({});
        let mut location_val = serde_json::json!({});
        let mut tags_val = serde_json::json!({});

        // ====================================================================
        // Command 1: get-bucket-encryption
        // ====================================================================
        match client.execute("s3api", "get-bucket-encryption", &bucket_args) {
            Ok(resp) => {
                encryption_val = resp.clone();

                if let Some(sse_algo) = resp
                    .get("ServerSideEncryptionConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("Rules"))
                    .and_then(|r: &serde_json::Value| r.as_array())
                    .and_then(|a| a.first())
                    .and_then(|rule| rule.get("ApplyServerSideEncryptionByDefault"))
                    .and_then(|d: &serde_json::Value| d.get("SSEAlgorithm"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "sse_algorithm".to_string(),
                        ResolvedValue::String(sse_algo.to_string()),
                    );
                }

                if let Some(kms_key) = resp
                    .get("ServerSideEncryptionConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("Rules"))
                    .and_then(|r: &serde_json::Value| r.as_array())
                    .and_then(|a| a.first())
                    .and_then(|rule| rule.get("ApplyServerSideEncryptionByDefault"))
                    .and_then(|d: &serde_json::Value| d.get("KMSMasterKeyID"))
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "kms_master_key_id".to_string(),
                        ResolvedValue::String(kms_key.to_string()),
                    );
                }

                if let Some(bke) = resp
                    .get("ServerSideEncryptionConfiguration")
                    .and_then(|c: &serde_json::Value| c.get("Rules"))
                    .and_then(|r: &serde_json::Value| r.as_array())
                    .and_then(|a| a.first())
                    .and_then(|rule| rule.get("BucketKeyEnabled"))
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "bucket_key_enabled".to_string(),
                        ResolvedValue::Boolean(bke),
                    );
                }
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_no_such_bucket_error(&err_str) {
                    // Bucket does not exist — set found=false and return early
                    data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                    let empty = RecordData::from_json_value(serde_json::json!({}));
                    data.add_field(
                        "resource".to_string(),
                        ResolvedValue::RecordData(Box::new(empty)),
                    );
                    return Ok(data);
                } else if !Self::is_not_configured_error(&err_str) {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (get-bucket-encryption): {}", e),
                    });
                }
                // Not configured — leave fields absent, continue
            }
        }

        // ====================================================================
        // Command 2: get-bucket-versioning
        // ====================================================================
        match client.execute("s3api", "get-bucket-versioning", &bucket_args) {
            Ok(resp) => {
                versioning_val = resp.clone();

                if let Some(status) = resp
                    .get("Status")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "versioning_status".to_string(),
                        ResolvedValue::String(status.to_string()),
                    );
                }
                // Empty object = versioning never enabled; field absent
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-bucket-versioning): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 3: get-public-access-block
        // ====================================================================
        match client.execute("s3api", "get-public-access-block", &bucket_args) {
            Ok(resp) => {
                public_access_val = resp.clone();

                let pab = resp.get("PublicAccessBlockConfiguration");

                if let Some(v) = pab
                    .and_then(|c: &serde_json::Value| c.get("BlockPublicAcls"))
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("block_public_acls".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = pab
                    .and_then(|c: &serde_json::Value| c.get("IgnorePublicAcls"))
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("ignore_public_acls".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = pab
                    .and_then(|c: &serde_json::Value| c.get("BlockPublicPolicy"))
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field("block_public_policy".to_string(), ResolvedValue::Boolean(v));
                }
                if let Some(v) = pab
                    .and_then(|c: &serde_json::Value| c.get("RestrictPublicBuckets"))
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "restrict_public_buckets".to_string(),
                        ResolvedValue::Boolean(v),
                    );
                }
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if !Self::is_not_configured_error(&err_str) {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (get-public-access-block): {}", e),
                    });
                }
                // Not configured — fields absent
            }
        }

        // ====================================================================
        // Command 4: get-bucket-lifecycle-configuration
        // ====================================================================
        match client.execute("s3api", "get-bucket-lifecycle-configuration", &bucket_args) {
            Ok(resp) => {
                lifecycle_val = resp.clone();

                let has_enabled = resp
                    .get("Rules")
                    .and_then(|r: &serde_json::Value| r.as_array())
                    .map(|rules| {
                        rules.iter().any(|rule| {
                            rule.get("Status")
                                .and_then(|v: &serde_json::Value| v.as_str())
                                == Some("Enabled")
                        })
                    })
                    .unwrap_or(false);

                data.add_field(
                    "lifecycle_enabled".to_string(),
                    ResolvedValue::Boolean(has_enabled),
                );
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_configured_error(&err_str) {
                    data.add_field(
                        "lifecycle_enabled".to_string(),
                        ResolvedValue::Boolean(false),
                    );
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!(
                            "AWS API error (get-bucket-lifecycle-configuration): {}",
                            e
                        ),
                    });
                }
            }
        }

        // ====================================================================
        // Command 5: get-bucket-policy
        // ====================================================================
        match client.execute("s3api", "get-bucket-policy", &bucket_args) {
            Ok(resp) => {
                // The Policy field is a JSON-encoded string — parse it
                if let Some(policy_str) = resp
                    .get("Policy")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    match serde_json::from_str::<serde_json::Value>(policy_str) {
                        Ok(parsed) => {
                            // Derive ssl_enforced: true when a statement exists with
                            // Effect=Deny AND Condition.Bool.aws:SecureTransport=false
                            // This is the standard pattern for enforcing HTTPS-only access (AU-9, SC-8)
                            let ssl_enforced = parsed
                                .get("Statement")
                                .and_then(|s: &serde_json::Value| s.as_array())
                                .map(|statements| {
                                    statements.iter().any(|stmt| {
                                        let is_deny = stmt
                                            .get("Effect")
                                            .and_then(|v: &serde_json::Value| v.as_str())
                                            == Some("Deny");

                                        let has_ssl_condition = stmt
                                            .get("Condition")
                                            .and_then(|c: &serde_json::Value| c.get("Bool"))
                                            .and_then(|b: &serde_json::Value| {
                                                b.get("aws:SecureTransport")
                                            })
                                            .and_then(|v: &serde_json::Value| v.as_str())
                                            .map(|v| v.eq_ignore_ascii_case("false"))
                                            .unwrap_or(false);

                                        is_deny && has_ssl_condition
                                    })
                                })
                                .unwrap_or(false);

                            data.add_field(
                                "ssl_enforced".to_string(),
                                ResolvedValue::Boolean(ssl_enforced),
                            );

                            policy_val = parsed;
                        }
                        Err(e) => {
                            return Err(CollectionError::CollectionFailed {
                                object_id: object.identifier.clone(),
                                reason: format!("Failed to parse bucket policy JSON: {}", e),
                            });
                        }
                    }
                }
                data.add_field(
                    "has_bucket_policy".to_string(),
                    ResolvedValue::Boolean(true),
                );
            }
            Err(e) => {
                let err_str = format!("{}", e);
                if Self::is_not_configured_error(&err_str) {
                    data.add_field(
                        "has_bucket_policy".to_string(),
                        ResolvedValue::Boolean(false),
                    );
                    // No policy means no DenyNonSSL statement — ssl not enforced
                    data.add_field("ssl_enforced".to_string(), ResolvedValue::Boolean(false));
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error (get-bucket-policy): {}", e),
                    });
                }
            }
        }

        // ====================================================================
        // Command 6: get-bucket-location
        // ====================================================================
        match client.execute("s3api", "get-bucket-location", &bucket_args) {
            Ok(resp) => {
                location_val = resp.clone();

                // LocationConstraint is null for us-east-1 — normalize
                let resolved_region = match resp.get("LocationConstraint") {
                    Some(serde_json::Value::Null) | None => "us-east-1".to_string(),
                    Some(serde_json::Value::String(s)) if s.is_empty() => "us-east-1".to_string(),
                    Some(serde_json::Value::String(s)) => s.clone(),
                    _ => "us-east-1".to_string(),
                };

                data.add_field("region".to_string(), ResolvedValue::String(resolved_region));
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error (get-bucket-location): {}", e),
                });
            }
        }

        // ====================================================================
        // Command 7: get-bucket-tagging (only when include_tagging behavior set)
        // ====================================================================
        if include_tagging {
            match client.execute("s3api", "get-bucket-tagging", &bucket_args) {
                Ok(resp) => {
                    tags_val = resp.clone();

                    // Flatten each tag into a scalar field: tag_key:<Key> → Value
                    // This allows simple state checks like:
                    //   tag_key:Environment string = `demo`
                    if let Some(tag_set) = resp
                        .get("TagSet")
                        .and_then(|v: &serde_json::Value| v.as_array())
                    {
                        for tag in tag_set {
                            if let (Some(key), Some(value)) = (
                                tag.get("Key").and_then(|v: &serde_json::Value| v.as_str()),
                                tag.get("Value")
                                    .and_then(|v: &serde_json::Value| v.as_str()),
                            ) {
                                let field_name = format!("tag_key:{}", key);
                                data.add_field(
                                    field_name,
                                    ResolvedValue::String(value.to_string()),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let err_str = format!("{}", e);
                    // NoSuchTagSet means no tags exist — not an error
                    if !err_str.contains("NoSuchTagSet") {
                        return Err(CollectionError::CollectionFailed {
                            object_id: object.identifier.clone(),
                            reason: format!("AWS API error (get-bucket-tagging): {}", e),
                        });
                    }
                }
            }
        }

        // ====================================================================
        // Scalar fields that are always present when found
        // ====================================================================
        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field(
            "bucket_name".to_string(),
            ResolvedValue::String(bucket_name.clone()),
        );

        // ====================================================================
        // Build merged RecordData
        // ====================================================================
        let merged = serde_json::json!({
            "Encryption": encryption_val,
            "Versioning": versioning_val,
            "PublicAccessBlock": public_access_val,
            "Lifecycle": lifecycle_val,
            "Policy": policy_val,
            "Location": location_val,
            "Tags": tags_val,
        });

        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_s3_bucket".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_s3_bucket" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_s3_bucket', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_id() {
        assert_eq!(
            AwsS3BucketCollector::new().collector_id(),
            "aws_s3_bucket_collector"
        );
    }

    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsS3BucketCollector::new().supported_ctn_types(),
            vec!["aws_s3_bucket"]
        );
    }

    #[test]
    fn test_default() {
        let collector = AwsS3BucketCollector::default();
        assert_eq!(collector.collector_id(), "aws_s3_bucket_collector");
    }

    #[test]
    fn test_is_not_configured_error() {
        assert!(AwsS3BucketCollector::is_not_configured_error(
            "NoSuchLifecycleConfiguration"
        ));
        assert!(AwsS3BucketCollector::is_not_configured_error(
            "NoSuchBucketPolicy"
        ));
        assert!(AwsS3BucketCollector::is_not_configured_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        ));
        assert!(AwsS3BucketCollector::is_not_configured_error(
            "NoSuchPublicAccessBlockConfiguration"
        ));
        assert!(!AwsS3BucketCollector::is_not_configured_error(
            "AccessDenied"
        ));
    }

    #[test]
    fn test_is_no_such_bucket_error() {
        assert!(AwsS3BucketCollector::is_no_such_bucket_error(
            "NoSuchBucket"
        ));
        assert!(!AwsS3BucketCollector::is_no_such_bucket_error(
            "NoSuchBucketPolicy"
        ));
    }
}
