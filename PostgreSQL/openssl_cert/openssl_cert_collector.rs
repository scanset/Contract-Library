//! OpenSSL Certificate Collector
//!
//! Inspects X.509 certificates via `openssl x509 -noout -subject -issuer -dates`.
//! Parses key=value output into structured fields including derived CN and
//! self_signed boolean.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod openssl_cert;
//  pub use openssl_cert::OpensslCertCollector;
//
//////////////////////////////////////////////////////

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::time::Duration;

#[derive(Clone)]
pub struct OpensslCertCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl OpensslCertCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        Self {
            id: id.into(),
            executor,
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

    /// Parse openssl x509 output lines into key=value pairs
    /// Input format:
    ///   subject=CN=localhost
    ///   issuer=CN=localhost
    ///   notBefore=Apr 10 00:44:04 2026 GMT
    ///   notAfter=Apr 10 00:44:04 2027 GMT
    fn parse_x509_output(&self, raw: &str) -> std::collections::HashMap<String, String> {
        let mut fields = std::collections::HashMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if let Some(idx) = line.find('=') {
                let key = line[..idx].trim().to_string();
                let value = line[idx + 1..].trim().to_string();
                fields.insert(key, value);
            }
        }
        fields
    }

    /// Extract CN from a subject/issuer string like "CN=localhost" or
    /// "C=US, ST=CA, O=Org, CN=myhost.example.com"
    fn extract_cn(&self, subject: &str) -> Option<String> {
        for part in subject.split(',') {
            let part = part.trim();
            if part.starts_with("CN=") || part.starts_with("CN =") {
                return Some(part.splitn(2, '=').nth(1)?.trim().to_string());
            }
        }
        // Simple case: subject is just "CN=value"
        if subject.starts_with("CN=") {
            return Some(subject[3..].trim().to_string());
        }
        None
    }
}

impl CtnDataCollector for OpensslCertCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let path = self
            .extract_string_field(object, "path")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'path'".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "openssl_cert".to_string(),
            self.id.clone(),
        );

        let command_str = format!("openssl x509 -noout -subject -issuer -dates -in {}", path);

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Inspect X.509 certificate via openssl")
            .target(&path)
            .command(&command_str)
            .input("path", &path)
            .build();
        data.set_method(method);

        let args = vec![
            "x509", "-noout", "-subject", "-issuer", "-dates", "-in", path.as_str(),
        ];

        let output = self
            .executor
            .execute("openssl", &args, Some(Duration::from_secs(10)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute openssl: {}", e),
            })?;

        if output.exit_code != 0 {
            // Certificate file missing or not parseable
            data.add_field("found".to_string(), ResolvedValue::Boolean(false));
            return Ok(data);
        }

        let fields = self.parse_x509_output(&output.stdout);

        data.add_field("found".to_string(), ResolvedValue::Boolean(true));

        if let Some(subject) = fields.get("subject") {
            data.add_field("subject".to_string(), ResolvedValue::String(subject.clone()));

            // Derive CN from subject
            if let Some(cn) = self.extract_cn(subject) {
                data.add_field("cn".to_string(), ResolvedValue::String(cn));
            }
        }

        if let Some(issuer) = fields.get("issuer") {
            data.add_field("issuer".to_string(), ResolvedValue::String(issuer.clone()));
        }

        if let Some(not_before) = fields.get("notBefore") {
            data.add_field("not_before".to_string(), ResolvedValue::String(not_before.clone()));
        }

        if let Some(not_after) = fields.get("notAfter") {
            data.add_field("not_after".to_string(), ResolvedValue::String(not_after.clone()));
        }

        // Derive self_signed: subject == issuer
        let is_self_signed = match (fields.get("subject"), fields.get("issuer")) {
            (Some(s), Some(i)) => s == i,
            _ => false,
        };
        data.add_field("self_signed".to_string(), ResolvedValue::Boolean(is_self_signed));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["openssl_cert".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "openssl_cert" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'openssl_cert', got '{}'",
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
