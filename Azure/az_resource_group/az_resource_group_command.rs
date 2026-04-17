//! Azure Resource Group Command Module
//!
//! Shared Azure CLI command executor factory. One module serves every
//! Azure CTN in this platform — extracted verbatim from
//! `agent/src/contract_kit/commands/az.rs`.

///////////////////////////////////////////////////////
//
//  mod.rs additions (agent/src/contract_kit/commands/mod.rs)
//
//  pub mod az;
//  pub use az::create_az_executor;
//
///////////////////////////////////////////////////////

//! Azure CLI (`az`) command executor.
//!
//! The hardened SystemCommandExecutor clears all inherited env vars via
//! env_clear() before spawning. We re-inject only the Azure credential and
//! context vars that `az` needs, so the CLI picks up whichever auth mode the
//! host is configured for (SPN-with-secret, SPN-with-cert, workload identity,
//! managed identity, or cached `az login`). Unset source vars are silently
//! skipped per `set_env_from` semantics.
//!
//! Supported auth modes (all work through the same passthrough list):
//!
//! | Mode | Required agent env |
//! |------|--------------------|
//! | SPN with client secret       | AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID |
//! | SPN with client certificate  | AZURE_CLIENT_ID, AZURE_CLIENT_CERTIFICATE_PATH, AZURE_TENANT_ID |
//! | Workload identity (federated)| AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE |
//! | Managed Identity             | (none — IDENTITY_ENDPOINT injected by Azure when VM has MI) |
//! | Cached `az login`            | HOME (or AZURE_CONFIG_DIR) — tokens from ~/.azure/ |
//!
//! Subscription selection: set AZURE_SUBSCRIPTION_ID on the agent, or let the
//! cached-config default win. Individual calls may still override via
//! `--subscription <id>` in args.

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for `az`.
///
/// Whitelists the `az` binary (plus common absolute paths) and forwards the
/// full set of Azure CLI credential env vars from the agent's environment.
pub fn create_az_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));

    executor.allow_commands(&[
        "az",
        "/usr/bin/az",
        "/usr/local/bin/az",
        "/opt/homebrew/bin/az",
    ]);

    executor.set_env(
        "PATH",
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
    );

    // SPN with client secret
    executor.set_env_from("AZURE_CLIENT_ID", "AZURE_CLIENT_ID");
    executor.set_env_from("AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET");
    executor.set_env_from("AZURE_TENANT_ID", "AZURE_TENANT_ID");

    // Subscription pin
    executor.set_env_from("AZURE_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID");

    // SPN with client certificate
    executor.set_env_from(
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_CLIENT_CERTIFICATE_PATH",
    );
    executor.set_env_from(
        "AZURE_CLIENT_CERTIFICATE_PASSWORD",
        "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    );

    // Workload identity / federated OIDC
    executor.set_env_from("AZURE_FEDERATED_TOKEN_FILE", "AZURE_FEDERATED_TOKEN_FILE");
    executor.set_env_from("AZURE_AUTHORITY_HOST", "AZURE_AUTHORITY_HOST");

    // Managed Identity (Azure-injected on VMs with MI assigned)
    executor.set_env_from("IDENTITY_ENDPOINT", "IDENTITY_ENDPOINT");
    executor.set_env_from("IDENTITY_HEADER", "IDENTITY_HEADER");
    executor.set_env_from("MSI_ENDPOINT", "MSI_ENDPOINT");
    executor.set_env_from("MSI_SECRET", "MSI_SECRET");

    // Cached `az login` — HOME for ~/.azure/ fallback, or explicit override
    executor.set_env_from("HOME", "HOME");
    executor.set_env_from("AZURE_CONFIG_DIR", "AZURE_CONFIG_DIR");

    // Python locale — az is a Python app and emits warnings without these
    executor.set_env_from("LANG", "LANG");
    executor.set_env_from("LC_ALL", "LC_ALL");

    executor
}
