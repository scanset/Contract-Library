//! AWS EKS Cluster Collector
//!
//! Collects EKS cluster configuration from AWS CLI.
//! Note: EKS API uses **camelCase** field names.
//!
//! ## RecordData Field Paths
//!
//! ```text
//! name                                          → "scanset"
//! status                                        → "ACTIVE"
//! version                                       → "1.32"
//! roleArn                                       → "arn:aws:iam::123456789012:role/example-cluster-role"
//! resourcesVpcConfig.vpcId                      → "vpc-0fedcba9876543210"
//! resourcesVpcConfig.endpointPublicAccess       → true
//! resourcesVpcConfig.endpointPrivateAccess      → true
//! resourcesVpcConfig.clusterSecurityGroupId     → "sg-0cccccccccccccccc0"
//! resourcesVpcConfig.subnetIds.0                → "subnet-0cccccccccccccccc"
//! resourcesVpcConfig.publicAccessCidrs.0        → "0.0.0.0/0"
//! logging.clusterLogging.0.enabled              → false
//! logging.clusterLogging.0.types.0              → "api"
//! identity.oidc.issuer                          → "https://oidc.eks.us-east-1.amazonaws.com/id/..."
//! accessConfig.authenticationMode               → "API_AND_CONFIG_MAP"
//! ```

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod aws_eks_cluster;
//  pub use aws_eks_cluster::AwsEksClusterCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use crate::contract_kit::commands::aws::AwsClient;

pub struct AwsEksClusterCollector {
    id: String,
}

impl AwsEksClusterCollector {
    pub fn new() -> Self {
        Self {
            id: "aws_eks_cluster_collector".to_string(),
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
}

impl Default for AwsEksClusterCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for AwsEksClusterCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let cluster_name = self
            .extract_string_field(object, "cluster_name")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "'cluster_name' is required for aws_eks_cluster".to_string(),
            })?;

        let region = self.extract_string_field(object, "region");
        let client = AwsClient::new(region.clone());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "aws_eks_cluster".to_string(),
            self.id.clone(),
        );

        let target = format!("eks:{}", cluster_name);
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Query EKS cluster configuration via AWS CLI")
            .target(&target)
            .command("aws eks describe-cluster")
            .input("cluster_name", &cluster_name);
        if let Some(ref r) = region {
            method_builder = method_builder.input("region", r);
        }
        data.set_method(method_builder.build());

        let args = vec!["--name", cluster_name.as_str()];
        let response = client.execute("eks", "describe-cluster", &args);

        let cluster = match response {
            Ok(resp) => resp.get("cluster").cloned(),
            Err(e) => {
                let err_str = format!("{}", e);
                if err_str.contains("ResourceNotFoundException") {
                    None
                } else {
                    return Err(CollectionError::CollectionFailed {
                        object_id: object.identifier.clone(),
                        reason: format!("AWS API error: {}", e),
                    });
                }
            }
        };

        if let Some(cluster) = cluster {
            data.add_field("found".to_string(), ResolvedValue::Boolean(true));

            // String fields
            if let Some(name) = cluster
                .get("name")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "cluster_name".to_string(),
                    ResolvedValue::String(name.to_string()),
                );
            }
            if let Some(status) = cluster
                .get("status")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "status".to_string(),
                    ResolvedValue::String(status.to_string()),
                );
            }
            if let Some(ver) = cluster
                .get("version")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "version".to_string(),
                    ResolvedValue::String(ver.to_string()),
                );
            }
            if let Some(role) = cluster
                .get("roleArn")
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "role_arn".to_string(),
                    ResolvedValue::String(role.to_string()),
                );
            }

            // VPC config
            if let Some(vpc_config) = cluster.get("resourcesVpcConfig") {
                if let Some(vpc_id) = vpc_config
                    .get("vpcId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "vpc_id".to_string(),
                        ResolvedValue::String(vpc_id.to_string()),
                    );
                }
                if let Some(epa) = vpc_config
                    .get("endpointPublicAccess")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "endpoint_public_access".to_string(),
                        ResolvedValue::Boolean(epa),
                    );
                }
                if let Some(epa) = vpc_config
                    .get("endpointPrivateAccess")
                    .and_then(|v: &serde_json::Value| v.as_bool())
                {
                    data.add_field(
                        "endpoint_private_access".to_string(),
                        ResolvedValue::Boolean(epa),
                    );
                }
                if let Some(csg) = vpc_config
                    .get("clusterSecurityGroupId")
                    .and_then(|v: &serde_json::Value| v.as_str())
                {
                    data.add_field(
                        "cluster_security_group_id".to_string(),
                        ResolvedValue::String(csg.to_string()),
                    );
                }
            }

            // Access config
            if let Some(am) = cluster
                .get("accessConfig")
                .and_then(|c: &serde_json::Value| c.get("authenticationMode"))
                .and_then(|v: &serde_json::Value| v.as_str())
            {
                data.add_field(
                    "authentication_mode".to_string(),
                    ResolvedValue::String(am.to_string()),
                );
            }

            let record_data = RecordData::from_json_value(cluster.clone());
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(record_data)),
            );
        } else {
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            let empty_record = RecordData::from_json_value(serde_json::json!({}));
            data.add_field(
                "resource".to_string(),
                ResolvedValue::RecordData(Box::new(empty_record)),
            );
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["aws_eks_cluster".to_string()]
    }
    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "aws_eks_cluster" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'aws_eks_cluster', got '{}'",
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
            AwsEksClusterCollector::new().collector_id(),
            "aws_eks_cluster_collector"
        );
    }
    #[test]
    fn test_supported_ctn_types() {
        assert_eq!(
            AwsEksClusterCollector::new().supported_ctn_types(),
            vec!["aws_eks_cluster"]
        );
    }
}
