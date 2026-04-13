//! Kubernetes Resource CTN Contract
//!
//! Queries Kubernetes API resources via `kubectl get -o json` and validates
//! resource existence, count, and field-level checks via RecordData.
//! Supports filtering by kind, namespace, name, name prefix, and label selector.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod k8s_resource;
//  pub use k8s_resource::create_k8s_resource_contract;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_k8s_resource_contract() -> CtnContract {
    let mut contract = CtnContract::new("k8s_resource".to_string());

    // -- Object requirements ------------------------------------------

    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "kind".to_string(),
            data_type: DataType::String,
            description: "Kubernetes resource kind".to_string(),
            example_values: vec![
                "Pod".to_string(),
                "Namespace".to_string(),
                "Service".to_string(),
                "Node".to_string(),
            ],
            validation_notes: Some(
                "Supported: Pod, Namespace, Service, Deployment, StatefulSet, DaemonSet, \
                 ConfigMap, Secret, Node, PersistentVolume, ClusterRole, ClusterRoleBinding, \
                 NetworkPolicy, Ingress, ValidatingWebhookConfiguration, \
                 MutatingWebhookConfiguration"
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "namespace".to_string(),
            data_type: DataType::String,
            description: "Namespace filter".to_string(),
            example_values: vec!["kube-system".to_string(), "default".to_string()],
            validation_notes: Some(
                "Omit for cluster-scoped resources (Node, Namespace, ClusterRole, etc.)"
                    .to_string(),
            ),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Exact resource name".to_string(),
            example_values: vec!["kube-apiserver-control-plane".to_string()],
            validation_notes: Some("Mutually exclusive with name_prefix and label_selector".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "name_prefix".to_string(),
            data_type: DataType::String,
            description: "Name prefix filter".to_string(),
            example_values: vec!["coredns-".to_string()],
            validation_notes: Some("Client-side filter after list retrieval".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "label_selector".to_string(),
            data_type: DataType::String,
            description: "Kubernetes label selector".to_string(),
            example_values: vec![
                "component=kube-apiserver".to_string(),
                "component=etcd".to_string(),
            ],
            validation_notes: Some("Server-side filter passed to kubectl -l".to_string()),
        });

    // -- State requirements -------------------------------------------

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether any matching resources were found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of matching resources".to_string(),
            example_values: vec!["1".to_string(), "0".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![],
            description: "Resource JSON for field-level validation via record checks".to_string(),
            example_values: vec![],
            validation_notes: Some(
                "Use record checks to validate specific fields in the resource spec"
                    .to_string(),
            ),
        });

    // -- Field mappings -----------------------------------------------

    for field in &["kind", "namespace", "name", "name_prefix", "label_selector"] {
        contract
            .field_mappings
            .collection_mappings
            .object_to_collection
            .insert(field.to_string(), field.to_string());
    }

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["count".to_string(), "record".to_string()];

    for field in &["found", "count", "record"] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    // -- Collection strategy ------------------------------------------

    contract.collection_strategy = CollectionStrategy {
        collector_type: "k8s_resource".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["kubectl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(5),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
