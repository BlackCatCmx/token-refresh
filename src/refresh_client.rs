use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::config::{AppConfig, parse_duration_str};
use crate::proxy::ProxySelector;

pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

pub struct RefreshClient {
    proxy_selector: ProxySelector,
    clients: Mutex<HashMap<ClientKey, reqwest::Client>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClientKey {
    timeout: Duration,
    proxy: Option<String>,
}

impl Default for RefreshClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshClient {
    pub fn new() -> Self {
        Self {
            proxy_selector: ProxySelector::new(),
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub async fn refresh(
        &self,
        config: &AppConfig,
        refresh_token: &str,
        user_agent: &str,
    ) -> std::result::Result<RefreshResponsePayload, RefreshFailure> {
        let client = self
            .client_for(config)
            .map_err(|err| RefreshFailure::transient("client_build_failed", err.to_string()))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "originator",
            HeaderValue::from_str(config.request_identity.originator.trim())
                .map_err(|err| RefreshFailure::transient("invalid_originator", err.to_string()))?,
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_str(user_agent.trim())
                .map_err(|err| RefreshFailure::transient("invalid_user_agent", err.to_string()))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let response = client
            .post(TOKEN_URL)
            .headers(headers)
            .json(&RefreshRequestBody {
                client_id: CLIENT_ID,
                grant_type: "refresh_token",
                refresh_token,
            })
            .send()
            .await
            .map_err(classify_transport_error)?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| RefreshFailure::transient("response_read_failed", err.to_string()))?;
        if !status.is_success() {
            return Err(classify_http_error(status.as_u16(), &body));
        }
        serde_json::from_str::<RefreshResponsePayload>(&body)
            .map_err(|err| RefreshFailure::transient("invalid_refresh_response", err.to_string()))
    }

    fn client_for(&self, config: &AppConfig) -> Result<reqwest::Client> {
        let timeout = parse_duration_str(&config.network.timeout)?;
        let proxy = self.proxy_selector.select_proxy(&config.proxy)?;
        let key = ClientKey {
            timeout,
            proxy: proxy.clone(),
        };

        let mut guard = self
            .clients
            .lock()
            .map_err(|_| anyhow::anyhow!("refresh client cache lock poisoned"))?;
        if let Some(existing) = guard.get(&key) {
            return Ok(existing.clone());
        }

        let mut builder = reqwest::Client::builder().timeout(timeout);
        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(&proxy)
                    .with_context(|| format!("invalid proxy configuration: {proxy}"))?,
            );
        }
        let client = builder.build().context("failed to build HTTP client")?;
        guard.insert(key, client.clone());
        Ok(client)
    }
}

impl std::fmt::Debug for RefreshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep Debug output stable and avoid dumping internal reqwest client details.
        f.debug_struct("RefreshClient")
            .field("proxy_selector", &self.proxy_selector)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize)]
struct RefreshRequestBody<'a> {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: &'a str,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RefreshResponsePayload {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct RefreshFailure {
    pub code: String,
    pub reason: String,
    pub count_towards_abnormal: bool,
}

impl RefreshFailure {
    pub fn transient(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            count_towards_abnormal: false,
        }
    }

    pub fn deterministic(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            count_towards_abnormal: true,
        }
    }
}

fn classify_transport_error(error: reqwest::Error) -> RefreshFailure {
    if error.is_timeout() {
        return RefreshFailure::transient("network_timeout", error.to_string());
    }
    if error.is_connect() {
        return RefreshFailure::transient("network_connect_failed", error.to_string());
    }
    RefreshFailure::transient("network_error", error.to_string())
}

fn classify_http_error(status: u16, body: &str) -> RefreshFailure {
    let error_body = serde_json::from_str::<RefreshResponsePayload>(body).ok();
    let parsed_code = error_body
        .as_ref()
        .and_then(|payload| payload.error.clone())
        .or_else(|| find_known_error_code(body));
    let parsed_reason = error_body
        .as_ref()
        .and_then(|payload| payload.error_description.clone())
        .unwrap_or_else(|| body.trim().to_string());
    if let Some(code) = parsed_code {
        if matches!(
            code.as_str(),
            "refresh_token_expired" | "refresh_token_reused" | "refresh_token_invalidated"
        ) {
            return RefreshFailure::deterministic(code, parsed_reason);
        }
        return RefreshFailure::transient(code, parsed_reason);
    }
    if status >= 500 {
        return RefreshFailure::transient(format!("upstream_http_{status}"), parsed_reason);
    }
    RefreshFailure::transient(format!("http_{status}"), parsed_reason)
}

fn find_known_error_code(body: &str) -> Option<String> {
    [
        "refresh_token_expired",
        "refresh_token_reused",
        "refresh_token_invalidated",
    ]
    .into_iter()
    .find(|needle| body.contains(needle))
    .map(str::to_string)
}
