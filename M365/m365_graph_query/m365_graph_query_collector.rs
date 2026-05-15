//! Microsoft Graph (M365 / Entra ID) collector — bulk identity + compliance inventory.
//!
//! Single CTN that GETs an arbitrary Graph path under
//! `https://graph.microsoft.com/v1.0` and returns the result rows as
//! `RecordData`. Replaces a per-resource-type fanout that would otherwise
//! require N collectors for users / groups / devices / conditional-access
//! / Intune / Purview / SharePoint / Teams.
//!
//! ## Auth
//!
//! Two OAuth flows supported, selected by env-var presence:
//!
//! 1. **App-only (client_credentials)** — Reads `AZURE_TENANT_ID`,
//!    `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` from the process env
//!    (set by `inventory::resolver::build_env` for any `azure_spn`
//!    credential). The app registration must grant the requested Graph
//!    APPLICATION permissions (`User.Read.All`, `Group.Read.All`, etc.)
//!    with admin consent. Covers ~75% of M365 surface (Entra + MIP +
//!    Intune + SharePoint + Teams).
//!
//! 2. **Delegated (refresh_token)** — Reads `M365_DELEGATED_TENANT_ID`,
//!    `M365_DELEGATED_CLIENT_ID`, `M365_DELEGATED_REFRESH_TOKEN` from
//!    the process env (set by `inventory::resolver::build_env` for any
//!    `m365_delegated_refresh` credential). The refresh_token gets
//!    exchanged for a short-lived access_token + a ROTATED refresh_token;
//!    the rotated token is surfaced as the `_rotated_refresh_token` field
//!    on the CollectedData output so the discoverer can persist it back
//!    to the credentials table. Covers the Exchange-backed compliance
//!    surface (retention labels, DLP, audit logs, eDiscovery) that
//!    app-only can't reach on Business Premium / Purview Suite for BP.
//!
//! Token scope for both flows is `https://graph.microsoft.com/.default`.
//! If the delegated env vars are set, they take precedence (the discoverer
//! arranges exactly one set per credential kind so this is just defensive).
//!
//! ## Pagination
//!
//! Graph uses `@odata.nextLink` (a fully-formed absolute URL) for paging.
//! We follow the chain until exhausted or the `MAX_ROWS` safety cap kicks
//! in. Page size is controlled by `$top`; Graph caps it per resource type
//! (commonly 999 for users/groups). The collector follows `@odata.nextLink`
//! transparently so callers don't need to think about page boundaries.
//!
//! ## Inputs (from the OBJECT block)
//!
//! - `path`      — Graph path, with or without a leading slash. Required.
//!                 Examples: `/users`, `users`, `groups`,
//!                 `identity/conditionalAccess/policies`,
//!                 `deviceManagement/managedDevices`.
//! - `select`    — optional `$select` clause (comma-separated field list).
//! - `filter`    — optional `$filter` clause (OData filter expression).
//! - `expand`    — optional `$expand` clause.
//! - `top`       — optional integer page size for `$top`. Defaults to
//!                 999 if unset (Graph clamps to its per-resource max).
//!
//! ## Outputs (in `CollectedData`)
//!
//! - `found`     — boolean, always true on success.
//! - `row_count` — integer.
//! - `rows`      — `RecordData` (JSON array of objects from Graph).

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{
    CollectedData, CollectionError, CtnContract, CtnDataCollector, SystemCommandExecutor,
};
use execution_engine::types::common::{RecordData, ResolvedValue};
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const AAD_BASE: &str = "https://login.microsoftonline.com";
const GRAPH_HOST: &str = "https://graph.microsoft.com";
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// Supported Graph API versions. Default is `v1.0`. Use `beta` for
/// resources that haven't graduated yet (e.g. Purview sensitivity
/// labels at `/informationProtection/policy/labels`).
const DEFAULT_API_VERSION: &str = "v1.0";

/// Hard cap on rows per single CTN invocation. Graph has no protocol
/// max; we set this to keep a runaway query from filling memory.
/// 100k rows is well above any realistic small/medium tenant.
const MAX_ROWS: usize = 100_000;

/// Default page size when caller doesn't specify `top`. Graph clamps
/// each resource type to its own max (users/groups commonly 999); we
/// request the upper end and let the server trim.
const DEFAULT_TOP: u32 = 999;

#[derive(Clone)]
pub struct M365GraphQueryCollector {
    id: String,
    _executor: SystemCommandExecutor,
    http: reqwest::blocking::Client,
    token_cache: Arc<Mutex<Option<CachedToken>>>,
    /// Across-sweep rotated refresh-token state. Populated the first
    /// time the delegated flow runs in this collector instance's life;
    /// every CollectedData output emits it as `_rotated_refresh_token`
    /// so the discoverer (post-sweep) can pick any result and persist.
    /// `None` means we're in app-only mode or haven't run yet.
    rotated_refresh: Arc<Mutex<Option<String>>>,
}

#[derive(Clone)]
struct CachedToken {
    bearer: String,
    expires_at: Instant,
    /// Identity of the auth context that minted this bearer. Used to
    /// detect "cache hit but for a different credential" — the
    /// collector is a singleton, so successive sweeps with different
    /// credentials share the same cache, and without this guard the
    /// first sweep's token leaks into the second sweep's calls. Most
    /// commonly observed when an app-only discovery runs after a
    /// delegated discovery and gets back 403s because the cached
    /// delegated token doesn't carry the app-permission scopes.
    auth_key: String,
}

/// Auth flow selector — derived from process env at each invocation.
enum AuthContext {
    AppOnly {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    Delegated {
        tenant_id: String,
        client_id: String,
        refresh_token: String,
    },
}

impl AuthContext {
    /// Stable identifier for this auth context. Used to key the bearer
    /// cache so successive sweeps with different credentials don't
    /// collide. Does NOT include the secret/refresh_token itself —
    /// that's secret material and unnecessary for uniqueness within
    /// a single scanner install (same tenant+client → same identity).
    fn cache_key(&self) -> String {
        match self {
            Self::AppOnly { tenant_id, client_id, .. } => {
                format!("app:{tenant_id}:{client_id}")
            }
            Self::Delegated { tenant_id, client_id, .. } => {
                format!("delegated:{tenant_id}:{client_id}")
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct AadTokenResponse {
    access_token: String,
    expires_in: u64,
    /// Only populated by the refresh_token flow when `offline_access` is
    /// in the request scope. Microsoft rotates the refresh_token on
    /// every grant; this is the new one to persist back.
    #[serde(default)]
    refresh_token: Option<String>,
}

/// Graph collection response shape. We only need `value` (the row array)
/// and `@odata.nextLink` (pagination). Other top-level fields are ignored.
#[derive(serde::Deserialize)]
struct GraphCollectionResponse {
    #[serde(default)]
    value: Vec<serde_json::Value>,
    #[serde(rename = "@odata.nextLink", default)]
    next_link: Option<String>,
}

impl M365GraphQueryCollector {
    pub fn new(id: impl Into<String>, executor: SystemCommandExecutor) -> Self {
        // The Purview beta endpoint
        // (/informationProtection/policy/labels) hard-requires a
        // User-Agent header — returns 400 "Value cannot be null
        // (Parameter 'User-Agent')" when missing. Other Graph endpoints
        // accept anonymous requests but it's polite to identify
        // ourselves anyway, and setting it once on the client covers
        // every request including the AAD token exchange.
        let http = reqwest::blocking::Client::builder()
            .use_native_tls()
            .user_agent("esp-agent/1.0 (m365_graph_query)")
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| {
                // Fallback path also sets UA — keep parity with the
                // primary builder for the same Purview-beta reason.
                reqwest::blocking::Client::builder()
                    .user_agent("esp-agent/1.0 (m365_graph_query)")
                    .build()
                    .unwrap_or_default()
            });
        Self {
            id: id.into(),
            _executor: executor,
            http,
            token_cache: Arc::new(Mutex::new(None)),
            rotated_refresh: Arc::new(Mutex::new(None)),
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

    fn extract_int_field(&self, object: &ExecutableObject, field_name: &str) -> Option<i64> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::Integer(i) = value {
                        return Some(*i);
                    }
                }
            }
        }
        None
    }

    /// Pick auth context from process env. Delegated (refresh_token) wins
    /// if its env block is present — the discoverer sets exactly one set
    /// per credential kind, so the precedence only matters as a defensive
    /// fallback against env-block leakage between invocations.
    fn auth_context_from_env() -> Result<AuthContext, String> {
        // Delegated path first.
        if let Ok(rt) = std::env::var("M365_DELEGATED_REFRESH_TOKEN") {
            if !rt.is_empty() {
                let tenant_id = std::env::var("M365_DELEGATED_TENANT_ID").map_err(|_| {
                    "M365_DELEGATED_REFRESH_TOKEN set but M365_DELEGATED_TENANT_ID missing"
                        .to_string()
                })?;
                let client_id = std::env::var("M365_DELEGATED_CLIENT_ID").map_err(|_| {
                    "M365_DELEGATED_REFRESH_TOKEN set but M365_DELEGATED_CLIENT_ID missing"
                        .to_string()
                })?;
                if tenant_id.is_empty() || client_id.is_empty() {
                    return Err(
                        "M365_DELEGATED_{TENANT_ID,CLIENT_ID} must be non-empty when refresh token set"
                            .to_string(),
                    );
                }
                return Ok(AuthContext::Delegated {
                    tenant_id,
                    client_id,
                    refresh_token: rt,
                });
            }
        }
        // App-only fallback.
        let tenant = std::env::var("AZURE_TENANT_ID")
            .map_err(|_| "AZURE_TENANT_ID not set (and no M365_DELEGATED_REFRESH_TOKEN)".to_string())?;
        let client_id = std::env::var("AZURE_CLIENT_ID")
            .map_err(|_| "AZURE_CLIENT_ID not set".to_string())?;
        let client_secret = std::env::var("AZURE_CLIENT_SECRET")
            .map_err(|_| "AZURE_CLIENT_SECRET not set".to_string())?;
        if tenant.is_empty() || client_id.is_empty() || client_secret.is_empty() {
            return Err(
                "AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET must all be non-empty"
                    .to_string(),
            );
        }
        Ok(AuthContext::AppOnly {
            tenant_id: tenant,
            client_id,
            client_secret,
        })
    }

    /// Get a Graph bearer, fetching fresh if cache is empty, near expiry,
    /// OR was minted for a different auth context. The auth_key check is
    /// what prevents a delegated token from leaking into a subsequent
    /// app-only sweep (and vice versa) — both flows go through this
    /// singleton collector, and without the key the second sweep would
    /// get a stale token with the wrong scopes.
    ///
    /// For the delegated flow, the captured rotated refresh_token lives
    /// in the separate `rotated_refresh` cell — caller surfaces it on
    /// the CollectedData result.
    fn bearer_token(&self, auth: &AuthContext) -> Result<String, String> {
        let want_key = auth.cache_key();
        {
            let cache = self
                .token_cache
                .lock()
                .map_err(|_| "token cache poisoned".to_string())?;
            if let Some(c) = cache.as_ref() {
                if c.auth_key == want_key && c.expires_at > Instant::now() {
                    return Ok(c.bearer.clone());
                }
            }
        }
        // Cache miss for this auth context. Clear the rotated-refresh
        // cell too — it's only populated by the delegated flow, and a
        // stale value from a previous credential's sweep would leak
        // into the current sweep's output otherwise.
        if let Ok(mut cell) = self.rotated_refresh.lock() {
            *cell = None;
        }
        let fresh = self.fetch_token(auth)?;
        let bearer = fresh.bearer.clone();
        let mut cache = self
            .token_cache
            .lock()
            .map_err(|_| "token cache poisoned".to_string())?;
        *cache = Some(fresh);
        Ok(bearer)
    }

    fn fetch_token(&self, auth: &AuthContext) -> Result<CachedToken, String> {
        let auth_key = auth.cache_key();
        let mut token = match auth {
            AuthContext::AppOnly {
                tenant_id,
                client_id,
                client_secret,
            } => self.fetch_token_client_credentials(tenant_id, client_id, client_secret)?,
            AuthContext::Delegated {
                tenant_id,
                client_id,
                refresh_token,
            } => self.fetch_token_refresh(tenant_id, client_id, refresh_token)?,
        };
        token.auth_key = auth_key;
        Ok(token)
    }

    fn fetch_token_client_credentials(
        &self,
        tenant: &str,
        client_id: &str,
        secret: &str,
    ) -> Result<CachedToken, String> {
        let url = format!("{AAD_BASE}/{tenant}/oauth2/v2.0/token");
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("client_id", client_id),
                ("client_secret", secret),
                ("grant_type", "client_credentials"),
                ("scope", GRAPH_SCOPE),
            ])
            .send()
            .map_err(|e| format!("AAD token request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("AAD token request: {} {}", status, body.trim()));
        }

        let body: AadTokenResponse = resp
            .json()
            .map_err(|e| format!("AAD token response parse: {e}"))?;

        // auth_key is stamped by the caller (fetch_token) — we don't
        // know it at this level.
        Ok(CachedToken {
            bearer: body.access_token,
            expires_at: Instant::now() + Duration::from_secs(body.expires_in.saturating_sub(60)),
            auth_key: String::new(),
        })
    }

    /// Refresh-token grant. Captures the rotated refresh_token into the
    /// shared `rotated_refresh` cell so the caller can emit it on the
    /// result. Microsoft's token endpoint returns a new refresh_token on
    /// every successful grant; if we don't persist it, the old one
    /// continues to work until it expires (~90 days), but using the most
    /// recent rotation is the documented best practice.
    fn fetch_token_refresh(
        &self,
        tenant: &str,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<CachedToken, String> {
        let url = format!("{AAD_BASE}/{tenant}/oauth2/v2.0/token");
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("client_id", client_id),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                // Asking for `.default` plus `offline_access` re-issues a
                // refresh_token in the response. Without offline_access,
                // we'd get an access_token only and lose the rotation chain.
                ("scope", "https://graph.microsoft.com/.default offline_access"),
            ])
            .send()
            .map_err(|e| format!("AAD refresh-token request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("AAD refresh-token request: {} {}", status, body.trim()));
        }

        let body: AadTokenResponse = resp
            .json()
            .map_err(|e| format!("AAD refresh-token response parse: {e}"))?;

        // Capture the rotated refresh_token for the caller to persist.
        // If the server didn't return one (unexpected — offline_access
        // should always trigger rotation), keep the stored cell as-is.
        if let Some(new_rt) = body.refresh_token {
            if !new_rt.is_empty() {
                if let Ok(mut cell) = self.rotated_refresh.lock() {
                    *cell = Some(new_rt);
                }
            }
        }

        Ok(CachedToken {
            bearer: body.access_token,
            expires_at: Instant::now() + Duration::from_secs(body.expires_in.saturating_sub(60)),
            auth_key: String::new(),
        })
    }

    /// Build a tuple list of `$`-prefixed OData query params for the
    /// initial request. reqwest applies percent-encoding when these
    /// are passed via `.query(&...)`.
    fn build_initial_params(
        &self,
        select: Option<&str>,
        filter: Option<&str>,
        expand: Option<&str>,
        top: u32,
    ) -> Vec<(String, String)> {
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(s) = select {
            params.push(("$select".to_string(), s.to_string()));
        }
        if let Some(f) = filter {
            params.push(("$filter".to_string(), f.to_string()));
        }
        if let Some(e) = expand {
            params.push(("$expand".to_string(), e.to_string()));
        }
        // `top == 0` is the documented sentinel for "do not send $top".
        // A handful of Graph endpoints reject any $top value at all —
        // e.g. /identity/conditionalAccess/authenticationContextClassReferences
        // returns 400 "Query option 'Top' is not allowed". Those endpoints
        // are always small enough that paging is unnecessary anyway.
        if top > 0 {
            params.push(("$top".to_string(), top.to_string()));
        }
        params
    }

    fn build_initial_url(&self, path: &str, api_version: &str) -> String {
        let v = if api_version.is_empty() {
            DEFAULT_API_VERSION
        } else {
            api_version
        };
        format!("{GRAPH_HOST}/{}/{}", v, path.trim_start_matches('/'))
    }

    /// Loop following `@odata.nextLink` until exhausted or `MAX_ROWS` hit.
    /// Initial request applies the `$`-prefixed OData params; nextLink
    /// URLs already contain everything needed and are followed verbatim.
    fn run_query(
        &self,
        initial_url: &str,
        initial_params: &[(String, String)],
        bearer: &str,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mut all_rows: Vec<serde_json::Value> = Vec::new();
        let mut next_url: Option<String> = Some(initial_url.to_string());
        let mut first_request = true;

        while let Some(url) = next_url.take() {
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(bearer)
                .header("ConsistencyLevel", "eventual");
            if first_request {
                req = req.query(initial_params);
                first_request = false;
            }

            let resp = req
                .send()
                .map_err(|e| format!("Graph request failed: {e}"))?;

            let status = resp.status();
            if !status.is_success() {
                let txt = resp.text().unwrap_or_default();
                return Err(format!("Graph: {status} {}", txt.trim()));
            }

            let parsed: GraphCollectionResponse = resp
                .json()
                .map_err(|e| format!("Graph response parse: {e}"))?;

            all_rows.extend(parsed.value);

            if all_rows.len() >= MAX_ROWS {
                tracing::warn!(
                    cap = MAX_ROWS,
                    "Graph result truncated at safety cap; refine the query or paginate from the caller"
                );
                break;
            }

            if let Some(link) = parsed.next_link {
                if !link.is_empty() {
                    next_url = Some(link);
                }
            }
        }

        Ok(all_rows)
    }
}

impl CtnDataCollector for M365GraphQueryCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let path = self
            .extract_string_field(object, "path")
            .ok_or_else(|| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: "OBJECT must declare `path` (Graph collection path, e.g. `/users`)"
                    .to_string(),
            })?;
        let select = self.extract_string_field(object, "select");
        let filter = self.extract_string_field(object, "filter");
        let expand = self.extract_string_field(object, "expand");
        // `top == 0` is preserved as a sentinel meaning "skip $top entirely"
        // (see build_initial_params for the rejection list); otherwise clamp
        // to the [1, 999] Graph-supported window.
        let top: u32 = self
            .extract_int_field(object, "top")
            .map(|v| v.clamp(0, 999) as u32)
            .unwrap_or(DEFAULT_TOP);
        // Optional Graph API version: `v1.0` (default) or `beta`. Used
        // for Purview / Information Protection endpoints that haven't
        // graduated yet (e.g. /informationProtection/policy/labels).
        let api_version = self
            .extract_string_field(object, "api_version")
            .unwrap_or_else(|| DEFAULT_API_VERSION.to_string());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "m365_graph_query".to_string(),
            self.id.clone(),
        );

        let target = format!("graph:{}/{}", api_version, path.trim_start_matches('/'));
        let mut method_builder = CollectionMethod::builder()
            .method_type(CollectionMethodType::ApiCall)
            .description("Microsoft Graph collection GET")
            .target(&target)
            .command(&format!(
                "GET {GRAPH_HOST}/{}/{}",
                api_version,
                path.trim_start_matches('/'),
            ));
        method_builder = method_builder.input("path", &path);
        method_builder = method_builder.input("api_version", &api_version);
        if let Some(ref s) = select {
            method_builder = method_builder.input("select", s);
        }
        if let Some(ref f) = filter {
            method_builder = method_builder.input("filter", f);
        }
        if let Some(ref e) = expand {
            method_builder = method_builder.input("expand", e);
        }
        method_builder = method_builder.input("top", &top.to_string());
        data.set_method(method_builder.build());

        let auth = Self::auth_context_from_env().map_err(|e| {
            CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: e,
            }
        })?;

        let bearer = self
            .bearer_token(&auth)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: e,
            })?;

        // For the delegated flow, surface the rotated refresh_token on
        // every output so the discoverer can extract it from any path's
        // result and persist back to inventory.credentials. The field
        // is underscore-prefixed to mark it as a control field rather
        // than row data.
        //
        // For app-only this cell stays None and no field is emitted.
        if let Ok(cell) = self.rotated_refresh.lock() {
            if let Some(rt) = cell.as_ref() {
                data.add_field(
                    "_rotated_refresh_token".to_string(),
                    ResolvedValue::String(rt.clone()),
                );
            }
        }

        let initial_url = self.build_initial_url(&path, &api_version);
        let initial_params = self.build_initial_params(
            select.as_deref(),
            filter.as_deref(),
            expand.as_deref(),
            top,
        );

        let rows = self
            .run_query(&initial_url, &initial_params, &bearer)
            .map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: e,
            })?;

        let count = rows.len() as i64;
        data.add_field("found".to_string(), ResolvedValue::Boolean(true));
        data.add_field("row_count".to_string(), ResolvedValue::Integer(count));
        let rows_record = RecordData::from_json_value(serde_json::Value::Array(rows));
        data.add_field(
            "rows".to_string(),
            ResolvedValue::RecordData(Box::new(rows_record)),
        );

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["m365_graph_query".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "m365_graph_query" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "M365GraphQueryCollector handles only `m365_graph_query`, got `{}`",
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
