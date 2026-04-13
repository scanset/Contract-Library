//! Kubernetes kubectl command executor.
//!
//! kubectl uses kubeconfig for auth. On kind clusters, the context is set
//! automatically. For production, set KUBECONFIG env var via set_env_from.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions (cross-platform, add to commands/mod.rs)
///
/// pub mod k8s;
//  pub use k8s::create_kubectl_executor;
//
//////////////////////////////////////////////////////

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for kubectl.
///
/// Extends PATH to include common kubectl locations.
/// Maps ESP_KUBECONFIG -> KUBECONFIG for cluster auth.
pub fn create_kubectl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));
    executor.allow_commands(&[
        "kubectl",
        "/usr/local/bin/kubectl",
        "/usr/bin/kubectl",
        "/snap/bin/kubectl",
    ]);

    // Extend PATH for kubectl
    executor.set_env(
        "PATH",
        concat!(
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:",
            "/snap/bin"
        ),
    );

    // Dynamic kubeconfig resolution
    executor.set_env_from("KUBECONFIG", "ESP_KUBECONFIG");

    // HOME is needed for default ~/.kube/config resolution
    executor.set_env_from("HOME", "HOME");

    executor
}
