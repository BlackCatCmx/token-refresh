use std::collections::HashMap;
use std::error::Error as StdError;
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

#[derive(Clone, Debug)]
enum ProxyDirective {
    UseConfig,
    ForceNone,
    Force(String),
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

    pub(crate) fn reserve_proxy_index_from_list(
        &self,
        mode: &str,
        proxies: &[String],
    ) -> Result<Option<usize>> {
        self.proxy_selector
            .reserve_proxy_index_from_list(mode, proxies)
    }

    pub async fn refresh(
        &self,
        config: &AppConfig,
        refresh_token: &str,
        user_agent: &str,
    ) -> std::result::Result<RefreshSuccess, RefreshFailure> {
        self.refresh_with_proxy_directive(
            config,
            refresh_token,
            user_agent,
            ProxyDirective::UseConfig,
        )
        .await
    }

    pub(crate) async fn refresh_with_proxy(
        &self,
        config: &AppConfig,
        refresh_token: &str,
        user_agent: &str,
        proxy: Option<&str>,
    ) -> std::result::Result<RefreshSuccess, RefreshFailure> {
        let directive = match proxy {
            Some(value) => ProxyDirective::Force(value.to_string()),
            None => ProxyDirective::ForceNone,
        };
        self.refresh_with_proxy_directive(config, refresh_token, user_agent, directive)
            .await
    }

    async fn refresh_with_proxy_directive(
        &self,
        config: &AppConfig,
        refresh_token: &str,
        user_agent: &str,
        directive: ProxyDirective,
    ) -> std::result::Result<RefreshSuccess, RefreshFailure> {
        let (client, proxy_used) = self
            .client_for(config, directive)
            .map_err(|err| RefreshFailure::transient("client_build_failed", err.to_string()))?;
        let proxy_host = proxy_used.as_deref().and_then(proxy_host_label);
        let proxy_label = proxy_route_label(proxy_host.as_deref());
        let mut headers = HeaderMap::new();
        headers.insert(
            "originator",
            HeaderValue::from_str(config.request_identity.originator.trim()).map_err(|err| {
                RefreshFailure::transient("invalid_originator", err.to_string())
                    .with_proxy_host(proxy_host.clone())
            })?,
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_str(user_agent.trim()).map_err(|err| {
                RefreshFailure::transient("invalid_user_agent", err.to_string())
                    .with_proxy_host(proxy_host.clone())
            })?,
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
            .map_err(|err| classify_transport_error(err, proxy_host.clone()))?;
        let status = response.status();
        let body = response.text().await.map_err(|err| {
            RefreshFailure::transient("response_read_failed", err.to_string())
                .with_proxy_host(proxy_host.clone())
        })?;
        if !status.is_success() {
            return Err(classify_http_error(status.as_u16(), &body).with_proxy_host(proxy_host));
        }
        let payload = serde_json::from_str::<RefreshResponsePayload>(&body).map_err(|err| {
            RefreshFailure::transient("invalid_refresh_response", err.to_string())
                .with_proxy_host(proxy_host)
        })?;
        Ok(RefreshSuccess {
            payload,
            proxy_label,
        })
    }

    fn client_for(
        &self,
        config: &AppConfig,
        directive: ProxyDirective,
    ) -> Result<(reqwest::Client, Option<String>)> {
        let timeout = parse_duration_str(&config.network.timeout)?;
        let proxy = match directive {
            ProxyDirective::UseConfig => self.proxy_selector.select_proxy(&config.proxy)?,
            ProxyDirective::ForceNone => None,
            ProxyDirective::Force(value) => Some(value),
        };
        let key = ClientKey {
            timeout,
            proxy: proxy.clone(),
        };

        let mut guard = self
            .clients
            .lock()
            .map_err(|_| anyhow::anyhow!("refresh client cache lock poisoned"))?;
        if let Some(existing) = guard.get(&key) {
            return Ok((existing.clone(), proxy));
        }

        let mut builder = reqwest::Client::builder().timeout(timeout);
        if let Some(proxy) = proxy.clone() {
            builder = builder.proxy(
                reqwest::Proxy::all(&proxy)
                    .with_context(|| format!("invalid proxy configuration: {proxy}"))?,
            );
        } else {
            builder = builder.no_proxy();
        }
        let client = builder.build().context("failed to build HTTP client")?;
        guard.insert(key, client.clone());
        Ok((client, proxy))
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

#[derive(Clone, Debug)]
pub struct RefreshSuccess {
    pub payload: RefreshResponsePayload,
    pub proxy_label: String,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct RefreshFailure {
    pub code: String,
    pub reason: String,
    pub count_towards_abnormal: bool,
    pub proxy_host: Option<String>,
    pub proxy_label: Option<String>,
}

impl RefreshFailure {
    pub fn transient(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            count_towards_abnormal: false,
            proxy_host: None,
            proxy_label: None,
        }
    }

    pub fn deterministic(code: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
            count_towards_abnormal: true,
            proxy_host: None,
            proxy_label: None,
        }
    }

    pub fn with_proxy_host(mut self, proxy_host: Option<String>) -> Self {
        self.proxy_label = Some(proxy_route_label(proxy_host.as_deref()));
        self.proxy_host = proxy_host;
        self
    }
}

fn proxy_host_label(proxy: &str) -> Option<String> {
    let url = reqwest::Url::parse(proxy).ok()?;
    let host = url.host_str()?;
    let port = url.port()?;
    Some(format!("{host}:{port}"))
}

fn proxy_route_label(proxy_host: Option<&str>) -> String {
    proxy_host.unwrap_or("direct").to_string()
}

fn classify_transport_error(error: reqwest::Error, proxy_host: Option<String>) -> RefreshFailure {
    let reason = error.to_string();
    if error.is_timeout() {
        return RefreshFailure::transient("network_timeout", reason).with_proxy_host(proxy_host);
    }
    if proxy_host.is_some() && is_socks_transport_error(&error) {
        return RefreshFailure::transient("socks_proxy_error", reason).with_proxy_host(proxy_host);
    }
    if error.is_connect() {
        return RefreshFailure::transient("network_connect_failed", reason)
            .with_proxy_host(proxy_host);
    }
    RefreshFailure::transient("network_error", reason).with_proxy_host(proxy_host)
}

fn is_socks_transport_error(error: &reqwest::Error) -> bool {
    let mut current: &(dyn StdError + 'static) = error;
    loop {
        if is_socks_error_text(&current.to_string()) {
            return true;
        }
        let Some(source) = current.source() else {
            return false;
        };
        current = source;
    }
}

fn is_socks_error_text(value: &str) -> bool {
    value.to_ascii_lowercase().contains("socks")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::{Mutex as StdMutex, OnceLock};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    fn proxy_env_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    struct EnvGuard {
        values: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, Option<String>)]) -> Self {
            let mut values = Vec::with_capacity(vars.len());
            for (key, value) in vars {
                values.push((*key, env::var(key).ok()));
                match value {
                    Some(value) => unsafe { env::set_var(key, value) },
                    None => unsafe { env::remove_var(key) },
                }
            }
            Self { values }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.values.drain(..).rev() {
                match value {
                    Some(value) => unsafe { env::set_var(key, value) },
                    None => unsafe { env::remove_var(key) },
                }
            }
        }
    }

    fn test_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.network.timeout = "100ms".to_string();
        config.proxy.mode = "fixed".to_string();
        config.proxy.list = String::new();
        config
    }

    async fn request_uses_proxy(config: &AppConfig, directive: ProxyDirective) -> bool {
        let _env_lock = proxy_env_lock().lock().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let _env_guard = EnvGuard::set(&[
            ("HTTPS_PROXY", Some(proxy_url)),
            ("https_proxy", None),
            ("ALL_PROXY", None),
            ("all_proxy", None),
            ("NO_PROXY", None),
            ("no_proxy", None),
        ]);
        let client = RefreshClient::new()
            .client_for(config, directive)
            .unwrap()
            .0;

        let request = async move {
            let _ = client.get("https://example.invalid/").send().await;
        };
        let accept = async move {
            timeout(Duration::from_millis(250), listener.accept())
                .await
                .is_ok()
        };
        let (_, reached_proxy) = tokio::join!(request, accept);
        reached_proxy
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_proxy_config_disables_system_proxy() {
        let config = test_config();
        assert!(!request_uses_proxy(&config, ProxyDirective::UseConfig).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn force_none_disables_system_proxy() {
        let config = test_config();
        assert!(!request_uses_proxy(&config, ProxyDirective::ForceNone).await);
    }

    #[test]
    fn proxy_route_label_uses_direct_when_proxy_is_missing() {
        assert_eq!(proxy_route_label(None), "direct");
        assert_eq!(
            proxy_route_label(Some("127.0.0.1:10808")),
            "127.0.0.1:10808"
        );
    }

    #[test]
    fn with_proxy_host_sets_proxy_label() {
        let direct = RefreshFailure::transient("code", "reason").with_proxy_host(None);
        assert_eq!(direct.proxy_label.as_deref(), Some("direct"));

        let proxied = RefreshFailure::transient("code", "reason")
            .with_proxy_host(Some("127.0.0.1:10808".to_string()));
        assert_eq!(proxied.proxy_label.as_deref(), Some("127.0.0.1:10808"));
    }

    #[test]
    fn socks_error_text_matches_only_socks_messages() {
        assert!(is_socks_error_text("SOCKS server rejected hostname"));
        assert!(is_socks_error_text("proxy socks protocol error"));
        assert!(!is_socks_error_text("tls handshake failed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classify_transport_error_detects_reqwest_socks_source_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_host = listener.local_addr().unwrap().to_string();
        let proxy_url = format!("socks5h://{proxy_host}");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
            .build()
            .unwrap();

        let request = async move { client.get("https://example.invalid/").send().await };
        let fake_proxy = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            let _ = stream.read(&mut greeting).await.unwrap();
            stream.write_all(&[0x04, 0x00]).await.unwrap();
        };
        let (result, _) = tokio::join!(request, fake_proxy);
        let error = result.unwrap_err();
        let failure = classify_transport_error(error, Some(proxy_host));

        assert_eq!(failure.code, "socks_proxy_error");
    }
}
