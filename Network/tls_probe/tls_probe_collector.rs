//! TLS Probe Collector
//!
//! Connects to host:port via `openssl s_client -connect <host>:<port>`
//! and parses the TLS handshake output for protocol version, cipher suite,
//! certificate details, and verification result.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod tls_probe;
//  pub use tls_probe::TlsProbeCollector;
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
pub struct TlsProbeCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl TlsProbeCollector {
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

    /// Parse openssl s_client output for TLS connection details.
    ///
    /// Key lines to extract:
    ///   Protocol  : TLSv1.3
    ///   Cipher    : TLS_AES_256_GCM_SHA384
    ///   subject=CN=localhost
    ///   issuer=CN=localhost
    ///   notAfter=Apr 10 00:44:04 2027 GMT
    ///   Verify return code: 0 (ok)
    ///   OR: Verify return code: 18 (self-signed certificate)
    fn parse_s_client_output(
        &self,
        stdout: &str,
        stderr: &str,
    ) -> (bool, std::collections::HashMap<String, String>) {
        let mut fields = std::collections::HashMap::new();
        let combined = format!("{}\n{}", stdout, stderr);

        let mut connected = false;

        for line in combined.lines() {
            let trimmed = line.trim();

            // Protocol
            if trimmed.starts_with("Protocol") && trimmed.contains(':') {
                let val = trimmed.split(':').nth(1).unwrap_or("").trim();
                if !val.is_empty() {
                    fields.insert("protocol".to_string(), val.to_string());
                    connected = true;
                }
            }

            // Cipher
            if trimmed.starts_with("Cipher") && trimmed.contains(':') && !trimmed.contains("Cipher is") {
                let val = trimmed.split(':').nth(1).unwrap_or("").trim();
                if !val.is_empty() && val != "(NONE)" && val != "0000" {
                    fields.insert("cipher".to_string(), val.to_string());
                }
            }

            // Subject - full mode: "subject=CN=localhost"
            if trimmed.starts_with("subject=") {
                let val = trimmed.strip_prefix("subject=").unwrap_or("").trim();
                fields.insert("cert_subject".to_string(), val.to_string());
            }

            // Subject - brief mode: "Peer certificate: CN=localhost"
            if trimmed.starts_with("Peer certificate:") {
                let val = trimmed.strip_prefix("Peer certificate:").unwrap_or("").trim();
                if !val.is_empty() {
                    fields.entry("cert_subject".to_string()).or_insert_with(|| val.to_string());
                }
            }

            // Issuer - full mode: "issuer=CN=localhost"
            if trimmed.starts_with("issuer=") {
                let val = trimmed.strip_prefix("issuer=").unwrap_or("").trim();
                fields.insert("cert_issuer".to_string(), val.to_string());
            }

            // Not After
            if trimmed.starts_with("notAfter=") {
                let val = trimmed.strip_prefix("notAfter=").unwrap_or("").trim();
                fields.insert("cert_not_after".to_string(), val.to_string());
            }

            // Verify return code - full mode: "Verify return code: 18 (self-signed certificate)"
            if trimmed.starts_with("Verify return code:") {
                let val = trimmed
                    .strip_prefix("Verify return code:")
                    .unwrap_or("")
                    .trim();
                if let Some(start) = val.find('(') {
                    if let Some(end) = val.find(')') {
                        let desc = &val[start + 1..end];
                        fields.insert("verify_result".to_string(), desc.to_string());
                    }
                }
            }

            // Verify error - brief/stderr: "verify error:num=18:self-signed certificate"
            if trimmed.starts_with("verify error:") {
                // Extract "self-signed certificate" from "verify error:num=18:self-signed certificate"
                let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    fields.insert("verify_result".to_string(), parts[2].to_string());
                }
            }

            // Check for successful connection
            if trimmed.contains("SSL handshake has read") || trimmed.contains("CONNECTION ESTABLISHED") {
                connected = true;
            }
        }

        (connected, fields)
    }
}

impl CtnDataCollector for TlsProbeCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let host = self
            .extract_string_field(object, "host")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'host'".to_string(),
            })?;

        let port = self
            .extract_string_field(object, "port")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'port'".to_string(),
            })?;

        let servername = self
            .extract_string_field(object, "servername")
            .unwrap_or_else(|| host.clone());

        // Optional STARTTLS protocol (postgres, smtp, ftp, imap, etc.)
        let starttls = self.extract_string_field(object, "starttls");

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "tls_probe".to_string(),
            self.id.clone(),
        );

        let connect_str = format!("{}:{}", host, port);
        let starttls_flag = match &starttls {
            Some(proto) => format!(" -starttls {}", proto),
            None => String::new(),
        };
        let command_str = format!(
            "openssl s_client -connect {} -servername {}{} -brief",
            connect_str, servername, starttls_flag
        );

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("TLS handshake probe via openssl s_client")
            .target(&connect_str)
            .command(&command_str)
            .input("host", &host)
            .input("port", &port)
            .build();
        data.set_method(method);

        // Run openssl directly - no shell wrapper needed.
        // SystemCommandExecutor sets stdin to Stdio::null(), so s_client
        // won't hang waiting for input. -brief auto-prints and exits.
        let mut args: Vec<String> = vec![
            "s_client".to_string(),
            "-connect".to_string(),
            connect_str.clone(),
            "-servername".to_string(),
            servername,
            "-brief".to_string(),
        ];
        if let Some(proto) = &starttls {
            args.push("-starttls".to_string());
            args.push(proto.clone());
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self
            .executor
            .execute("openssl", &arg_refs, Some(Duration::from_secs(10)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute openssl s_client: {}", e),
            })?;

        let (connected, fields) = self.parse_s_client_output(&output.stdout, &output.stderr);

        data.add_field("connected".to_string(), ResolvedValue::Boolean(connected));

        if connected {
            for (key, val) in &fields {
                data.add_field(key.clone(), ResolvedValue::String(val.clone()));
            }

            // Derive self_signed from:
            // 1. subject == issuer (when both are available)
            // 2. verify_result contains "self-signed" (from verify error output)
            let is_self_signed = match (fields.get("cert_subject"), fields.get("cert_issuer")) {
                (Some(s), Some(i)) => s == i,
                _ => {
                    // Fall back to checking verify_result
                    fields
                        .get("verify_result")
                        .map(|v| v.contains("self-signed"))
                        .unwrap_or(false)
                }
            };
            data.add_field("self_signed".to_string(), ResolvedValue::Boolean(is_self_signed));
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["tls_probe".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "tls_probe" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'tls_probe', got '{}'",
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
