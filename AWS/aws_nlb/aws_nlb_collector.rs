//! AWS Network Load Balancer (NLB) Collector
//!
//! Collects NLB configuration from AWS ELBv2 API using the AWS CLI.
//! Returns both scalar summary fields and the full API response as RecordData.
//!
//! ## API Calls
//!
//! 1. `elbv2 describe-load-balancers` - Core LB properties
//! 2. `elbv2 describe-load-balancer-attributes` - Attributes (cross-zone, deletion protection, etc.)
//! 3. `elbv2 describe-listeners` - Listener configurations (protocol, SSL policy)
//! 4. `elbv2 describe-target-groups` - Target group configurations
//!
//! ## RecordData Field Paths
//!
//! ```text
//! LoadBalancerName                       -> "my-nlb"
//! Scheme                                 -> "internal"
//! State.Code                             -> "active"
//! Attributes.load_balancing.cross_zone.enabled -> "true"
//! Listeners.0.Protocol                   -> "TLS"
//! Listeners.0.SslPolicy                  -> "ELBSecurityPolicy-TLS13-1-2-2021-06"
//! ```
//!
//! ## mod.rs additions
//!
//! ```rust
//! pub mod aws_nlb;
//! pub use aws_nlb::AwsNlbCollector;
//! ```

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

/// Collector for AWS Network Load Balancer information
pub struct AwsNlbCollector {
    id: String,
}

impl AwsNlbCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_nlb_collector".to_string(),
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

    /// Look up an attribute value from the Attributes array
    fn get_attribute<'a>(attributes: &'a [serde_json::Value], key: &str) -> Option<&'a str> {
        attributes.iter().find_map(|attr| {
            if attr.get("Key").and_then(|v| v.as_str()) == Some(key) {
                attr.get("Value").and_then(|v| v.as_str())
            } else {
                None
            }
        })
    }
}

impl Default for AwsNlbCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsNlbCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let lb_arn = self.extract_string_field(object, "load_balancer_arn");
        let lb_name = self.extract_string_field(object, "load_balancer_name");
        let region = self.extract_string_field(object, "region");

        if lb_arn.is_none() && lb_name.is_none() {
            return Err(CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Either 'load_balancer_arn' or 'load_balancer_name' must be specified"
                    .to_string(),
            });
        }

        let client = AwsClient::new(region.clone());

        // Build args for describe-load-balancers
        let mut arg_strings: Vec<String> = Vec::new();

        if let Some(ref arn) = lb_arn {
            arg_strings.push("--load-balancer-arns".to_string());
            arg_strings.push(arn.clone());
        } else if let Some(ref name) = lb_name {
            arg_strings.push("--names".to_string());
            arg_strings.push(name.clone());
        }

        let args: Vec<&str> = arg_strings.iter().map(|s| s.as_str()).collect();

        let response = client
            .execute("elbv2", "describe-load-balancers", &args)
            .map_err(|e| {
                let err_str = format!("{}", e);
                if err_str.contains("LoadBalancerNotFound") || err_str.contains("not found") {
                    return CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: "NOT_FOUND".to_string(),
                    };
                }
                CollectionError::CollectionFailed {
                    object_id: object.identifier.clone(),
                    reason: format!("AWS API error: {}", e),
                }
            });

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_nlb".to_string(),
            self.id.clone(),
        );

        // Set collection method
        let target = lb_arn
            .as_ref()
            .map(|a| format!("nlb:{}", a))
            .or_else(|| lb_name.as_ref().map(|n| format!("nlb:name:{}", n)))
            .unwrap_or_else(|| "nlb:unknown".to_string());

        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query NLB configuration via AWS ELBv2 API")
            .target(&target)
            .command("aws elbv2 describe-load-balancers");

        if let Some(ref arn) = lb_arn {
            method_builder = method_builder.input("load_balancer_arn", arn);
        }
        if let Some(ref name) = lb_name {
            method_builder = method_builder.input("load_balancer_name", name);
        }
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }

        data.set_method(method_builder.build());

        // Handle not-found case
        let response = match response {
            Ok(r) => r,
            Err(CollectionError::CollectionFailed { reason, .. }) if reason == "NOT_FOUND" => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty_record = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty_record)),
                );
                return Ok(data);
            }
            Err(e) => return Err(e),
        };

        let load_balancers = response
            .get("LoadBalancers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if load_balancers.is_empty() {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
            return Ok(data);
        }

        // Find the first NLB (type=network)
        let nlb = load_balancers
            .iter()
            .find(|lb| {
                lb.get("Type")
                    .and_then(|v| v.as_str())
                    .is_some_and(|t| t == "network")
            })
            .or(Some(&load_balancers[0]));

        let nlb = match nlb {
            Some(lb) => lb,
            None => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                let empty_record = RecordData::from_json_value(serde_json::json!({}));
                data.add_field(
                    "resource".to_string(),
                    ResolvedValue::RecordData(Box::new(empty_record)),
                );
                return Ok(data);
            }
        };

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        // Extract scalar fields from describe-load-balancers
        if let Some(name) = nlb
            .get("LoadBalancerName")
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "load_balancer_name".to_string(),
                ResolvedValue::String(name.to_string()),
            );
        }

        if let Some(dns) = nlb.get("DNSName").and_then(|v| v.as_str()) {
            data.add_field(
                "dns_name".to_string(),
                ResolvedValue::String(dns.to_string()),
            );
        }

        if let Some(scheme) = nlb.get("Scheme").and_then(|v| v.as_str()) {
            data.add_field(
                "scheme".to_string(),
                ResolvedValue::String(scheme.to_string()),
            );
        }

        if let Some(state_code) = nlb
            .get("State")
            .and_then(|v| v.get("Code"))
            .and_then(|v| v.as_str())
        {
            data.add_field(
                "state".to_string(),
                ResolvedValue::String(state_code.to_string()),
            );
        }

        if let Some(vpc) = nlb.get("VpcId").and_then(|v| v.as_str()) {
            data.add_field(
                "vpc_id".to_string(),
                ResolvedValue::String(vpc.to_string()),
            );
        }

        if let Some(ip_type) = nlb.get("IpAddressType").and_then(|v| v.as_str()) {
            data.add_field(
                "ip_address_type".to_string(),
                ResolvedValue::String(ip_type.to_string()),
            );
        }

        // Get the NLB ARN for subsequent calls
        let nlb_arn = nlb
            .get("LoadBalancerArn")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Build merged record starting with the LB response
        let mut merged = nlb.clone();

        // Call 2: describe-load-balancer-attributes
        if !nlb_arn.is_empty() {
            let attr_args = vec!["--load-balancer-arn", nlb_arn];
            if let Ok(attr_response) =
                client.execute("elbv2", "describe-load-balancer-attributes", &attr_args)
            {
                let attributes = attr_response
                    .get("Attributes")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Deletion protection
                let del_prot = Self::get_attribute(&attributes, "deletion_protection.enabled")
                    .unwrap_or("false")
                    == "true";
                data.add_field(
                    "deletion_protection".to_string(),
                    ResolvedValue::Boolean(del_prot),
                );

                // Cross-zone load balancing
                let cross_zone = Self::get_attribute(
                    &attributes,
                    "load_balancing.cross_zone.enabled",
                )
                .unwrap_or("false")
                    == "true";
                data.add_field(
                    "cross_zone_enabled".to_string(),
                    ResolvedValue::Boolean(cross_zone),
                );

                // Access logging
                let access_log =
                    Self::get_attribute(&attributes, "access_logs.s3.enabled").unwrap_or("false")
                        == "true";
                data.add_field(
                    "access_logging_enabled".to_string(),
                    ResolvedValue::Boolean(access_log),
                );

                if let Some(bucket) =
                    Self::get_attribute(&attributes, "access_logs.s3.bucket")
                {
                    if !bucket.is_empty() {
                        data.add_field(
                            "access_log_s3_bucket".to_string(),
                            ResolvedValue::String(bucket.to_string()),
                        );
                    }
                }

                // Connection logging
                let conn_log = Self::get_attribute(
                    &attributes,
                    "connection_logs.s3.enabled",
                )
                .unwrap_or("false")
                    == "true";
                data.add_field(
                    "connection_logging_enabled".to_string(),
                    ResolvedValue::Boolean(conn_log),
                );

                // Add attributes to merged record as a map
                let attr_map: serde_json::Value = attributes
                    .iter()
                    .filter_map(|a| {
                        let key = a.get("Key").and_then(|v| v.as_str())?;
                        let val = a.get("Value").and_then(|v| v.as_str())?;
                        Some((key.to_string(), serde_json::Value::String(val.to_string())))
                    })
                    .collect::<serde_json::Map<String, serde_json::Value>>()
                    .into();
                merged
                    .as_object_mut()
                    .unwrap()
                    .insert("Attributes".to_string(), attr_map);
            }

            // Call 3: describe-listeners
            let listener_args = vec!["--load-balancer-arn", nlb_arn];
            if let Ok(listener_response) =
                client.execute("elbv2", "describe-listeners", &listener_args)
            {
                let listeners = listener_response
                    .get("Listeners")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                data.add_field(
                    "listener_count".to_string(),
                    ResolvedValue::Integer(listeners.len() as i64),
                );

                let has_tls = listeners.iter().any(|l| {
                    l.get("Protocol")
                        .and_then(|v| v.as_str())
                        .is_some_and(|p| p == "TLS")
                });
                data.add_field(
                    "has_tls_listener".to_string(),
                    ResolvedValue::Boolean(has_tls),
                );

                merged.as_object_mut().unwrap().insert(
                    "Listeners".to_string(),
                    serde_json::Value::Array(listeners),
                );
            }

            // Call 4: describe-target-groups
            let tg_args = vec!["--load-balancer-arn", nlb_arn];
            if let Ok(tg_response) =
                client.execute("elbv2", "describe-target-groups", &tg_args)
            {
                let target_groups = tg_response
                    .get("TargetGroups")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                data.add_field(
                    "target_group_count".to_string(),
                    ResolvedValue::Integer(target_groups.len() as i64),
                );

                merged.as_object_mut().unwrap().insert(
                    "TargetGroups".to_string(),
                    serde_json::Value::Array(target_groups),
                );
            }
        }

        // Store merged record
        let record_data = RecordData::from_json_value(merged);
        data.add_field(
            "resource".to_string(),
            ResolvedValue::RecordData(Box::new(record_data)),
        );

        if load_balancers.len() > 1 {
            log::warn!(
                "Multiple load balancers ({}) matched query for object '{}', using first NLB result",
                load_balancers.len(),
                object.identifier
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_nlb".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_nlb" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_nlb', got '{}'",
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
        let collector = AwsNlbCollector::new();
        assert_eq!(collector.collector_id(), "aws_nlb_collector");
    }

    #[test]
    fn test_supported_ctn_types() {
        let collector = AwsNlbCollector::new();
        assert_eq!(collector.supported_ctn_types(), vec!["aws_nlb"]);
    }

    #[test]
    fn test_default() {
        let collector = AwsNlbCollector::default();
        assert_eq!(collector.collector_id(), "aws_nlb_collector");
    }
}
