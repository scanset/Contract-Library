//! HTTP Probe Collector
//!
//! Makes HTTP requests via `curl` and parses the response.
//! Uses -sS -D - (dump headers to stdout) -o (body to temp) or
//! -w (write-out format) for structured output.

///////////////////////////////////////////////////////
///
///
/// mod.rs additions
///
/// pub mod http_probe;
//  pub use http_probe::HttpProbeCollector;
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
pub struct HttpProbeCollector {
    id: String,
    executor: SystemCommandExecutor,
}

impl HttpProbeCollector {
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

    /// Parse curl output using write-out format.
    /// We use: curl -sS -w '\n%{http_code}\n%{http_version}\n%{redirect_url}' -D - -o /dev/null
    /// This gives us headers on stdout, then the write-out values on separate lines.
    fn parse_curl_output(
        &self,
        stdout: &str,
    ) -> (bool, String, String, String, String) {
        let lines: Vec<&str> = stdout.lines().collect();

        // Find the ESP_PROBE_END sentinel and read backwards from it.
        // Expected order before sentinel: status_code, http_version, redirect_url
        let sentinel_idx = lines.iter().rposition(|l| l.trim() == "ESP_PROBE_END");

        let end = match sentinel_idx {
            Some(idx) => idx,
            None => {
                // No sentinel found - can't parse
                return (false, String::new(), String::new(), String::new(), String::new());
            }
        };

        // The 3 lines before the sentinel are: status_code, http_version, redirect_url
        if end < 3 {
            return (false, String::new(), String::new(), String::new(), String::new());
        }

        let redirect_url = lines[end - 1].trim().to_string();
        let http_version = lines[end - 2].trim().to_string();
        let status_code = lines[end - 3].trim().to_string();

        // Headers are everything before the write-out block
        // The write-out starts with a leading newline, so skip the empty line too
        let header_end = if end >= 4 { end - 4 } else { 0 };
        let headers = lines[..=header_end].join("\n");

        let connected = !status_code.is_empty() && status_code != "000";

        // Map curl http_version to protocol string
        let protocol = match http_version.as_str() {
            "2" => "HTTP/2".to_string(),
            "1.1" => "HTTP/1.1".to_string(),
            "1.0" => "HTTP/1.0".to_string(),
            "3" => "HTTP/3".to_string(),
            other => format!("HTTP/{}", other),
        };

        (connected, status_code, protocol, headers, redirect_url)
    }
}

impl CtnDataCollector for HttpProbeCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let url = self
            .extract_string_field(object, "url")
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing required field 'url'".to_string(),
            })?;

        let method = self
            .extract_string_field(object, "method")
            .unwrap_or_else(|| "GET".to_string());

        let insecure = self
            .extract_string_field(object, "insecure")
            .map(|v| v == "true")
            .unwrap_or(false);

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "http_probe".to_string(),
            self.id.clone(),
        );

        let command_str = format!("curl -sS -X {} {} {}", method, if insecure { "-k" } else { "" }, url);

        let method_input = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("HTTP request probe via curl")
            .target(&url)
            .command(&command_str)
            .input("url", &url)
            .input("method", &method)
            .build();
        data.set_method(method_input);

        // Build curl args directly - no shell wrapper needed.
        // -I = HEAD request (returns headers only)
        // -w = write-out format. Must use real newlines, not \n escapes,
        // because curl only interprets \n when passed via shell, not via argv.
        // Sentinel-delimited: ESP_PROBE_END anchors parsing from the bottom
        let write_out = "\n%{http_code}\n%{http_version}\n%{redirect_url}\nESP_PROBE_END";
        let mut args: Vec<String> = vec![
            "-sS".to_string(),
            "-I".to_string(),
            "--max-time".to_string(),
            "10".to_string(),
            "-w".to_string(),
            write_out.to_string(),
        ];

        if insecure {
            args.push("-k".to_string());
        }

        args.push(url);

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = self
            .executor
            .execute("curl", &arg_refs, Some(Duration::from_secs(15)))
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to execute curl: {}", e),
            })?;

        let (connected, status_code, protocol, headers, redirect_url) =
            self.parse_curl_output(&output.stdout);

        data.add_field("connected".to_string(), ResolvedValue::Boolean(connected));

        if connected {
            data.add_field("status_code".to_string(), ResolvedValue::String(status_code));
            data.add_field("protocol".to_string(), ResolvedValue::String(protocol));
            data.add_field("headers".to_string(), ResolvedValue::String(headers));
            if !redirect_url.is_empty() {
                data.add_field("redirect_url".to_string(), ResolvedValue::String(redirect_url));
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["http_probe".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "http_probe" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'http_probe', got '{}'",
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
