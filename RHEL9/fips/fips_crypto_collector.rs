//! FIPS Mode + Crypto Policy Collectors
//!
//! FipsModeCollector: checks FIPS mode via `fips-mode-setup --check`
//! and /proc/sys/crypto/fips_enabled.
//!
//! CryptoPolicyCollector: validates system-wide crypto policy via
//! update-crypto-policies --check and symlink inspection.
//!
//! STIG: SV-258230 (FIPS mode), SV-258236 (crypto policy)

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod fips_crypto;
//  pub use fips_crypto::CryptoPolicyCollector;
//  pub use fips_crypto::FipsModeCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::ExecutableObject;
use std::fs;
use std::path::Path;
use std::time::Duration;

// =============================================================================
// FIPS Mode Collector
// =============================================================================

#[derive(Clone)]
pub struct FipsModeCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl FipsModeCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }
}

impl CtnDataCollector for FipsModeCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "fips_mode".to_string(),
            self.id.clone(),
        );

        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::Command)
                .description("Check FIPS mode via fips-mode-setup --check")
                .target("fips-mode-setup")
                .command("fips-mode-setup --check")
                .build(),
        );

        match self.executor.execute(
            "fips-mode-setup",
            &["--check"],
            Some(Duration::from_secs(10)),
        ) {
            Err(_) => {
                data.add_field("tool_available".to_string(), ResolvedValue::Boolean(false));
                data.add_field("enabled".to_string(), ResolvedValue::Boolean(false));
            }
            Ok(output) => {
                data.add_field("tool_available".to_string(), ResolvedValue::Boolean(true));
                let stdout = output.stdout.trim().to_string();
                data.add_field(
                    "status_output".to_string(),
                    ResolvedValue::String(stdout.clone()),
                );
                let enabled = stdout.contains("FIPS mode is enabled");
                data.add_field("enabled".to_string(), ResolvedValue::Boolean(enabled));
            }
        }

        let kernel_fips = fs::read_to_string("/proc/sys/crypto/fips_enabled")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        data.add_field(
            "kernel_fips_enabled".to_string(),
            ResolvedValue::Boolean(kernel_fips),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["fips_mode".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "fips_mode" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'fips_mode', got '{}'",
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

// =============================================================================
// Crypto Policy Collector
// =============================================================================

#[derive(Clone)]
pub struct CryptoPolicyCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl CryptoPolicyCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
        }
    }

    fn validate_backend_symlinks(policy: &str) -> bool {
        let backends_dir = Path::new("/etc/crypto-policies/back-ends");
        if !backends_dir.exists() {
            return false;
        }

        let expected_prefix = format!("/usr/share/crypto-policies/{}/", policy);

        match fs::read_dir(backends_dir) {
            Err(_) => false,
            Ok(entries) => {
                let mut found_any = false;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "config").unwrap_or(false) {
                        if let Ok(target) = fs::read_link(&path) {
                            found_any = true;
                            let target_str = target.to_string_lossy();
                            if !target_str.starts_with(&expected_prefix) {
                                // nss.config is a regular file, not a symlink — skip
                                if path.file_name().map(|n| n == "nss.config").unwrap_or(false) {
                                    continue;
                                }
                                return false;
                            }
                        }
                    }
                }
                found_any
            }
        }
    }

    fn read_current_policy() -> Option<String> {
        fs::read_to_string("/etc/crypto-policies/state/current")
            .map(|s| s.trim().to_string())
            .ok()
    }
}

impl CtnDataCollector for CryptoPolicyCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "crypto_policy".to_string(),
            self.id.clone(),
        );

        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::Command)
                .description("Check system-wide crypto policy via update-crypto-policies --check")
                .target("update-crypto-policies")
                .command("update-crypto-policies --check")
                .build(),
        );

        if let Some(policy) = Self::read_current_policy() {
            data.add_field(
                "current_policy".to_string(),
                ResolvedValue::String(policy.clone()),
            );
            let backends_ok = Self::validate_backend_symlinks(&policy);
            data.add_field(
                "backends_point_to_policy".to_string(),
                ResolvedValue::Boolean(backends_ok),
            );
        }

        match self.executor.execute(
            "update-crypto-policies",
            &["--check"],
            Some(Duration::from_secs(10)),
        ) {
            Err(_) => {
                data.add_field("tool_available".to_string(), ResolvedValue::Boolean(false));
                data.add_field("policy_matches".to_string(), ResolvedValue::Boolean(false));
            }
            Ok(output) => {
                data.add_field("tool_available".to_string(), ResolvedValue::Boolean(true));
                let stdout = output.stdout.trim().to_string();
                data.add_field(
                    "check_output".to_string(),
                    ResolvedValue::String(stdout.clone()),
                );
                let matches = stdout
                    .lines()
                    .last()
                    .map(|l| l.trim() == "PASS")
                    .unwrap_or(false);
                data.add_field(
                    "policy_matches".to_string(),
                    ResolvedValue::Boolean(matches),
                );
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["crypto_policy".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "crypto_policy" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'crypto_policy', got '{}'",
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
