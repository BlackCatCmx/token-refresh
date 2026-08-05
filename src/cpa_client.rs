use anyhow::{Context, Result, bail};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use std::time::Duration;

use crate::cpa_config::strip_bearer_prefix;

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct CpaAuthEntry {
    pub name: String,
    pub email: Option<String>,
    pub plan_type: Option<String>,
    pub status: String,
    pub status_message: String,
    pub disabled: bool,
    pub unavailable: bool,
    pub source: String,
    pub runtime_only: bool,
    pub next_retry_after: Option<String>,
}

pub struct CpaClient {
    base_url: String,
    management_key: String,
    http: reqwest::Client,
}

impl CpaClient {
    pub fn new(base_url: &str, management_key: &str) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let management_key = strip_bearer_prefix(management_key);
        if base_url.is_empty() {
            bail!("CPA Base URL 不能为空");
        }
        if management_key.trim().is_empty() {
            bail!("CPA 管理 Key 不能为空");
        }
        let http = build_http_client(DEFAULT_HTTP_TIMEOUT)?;
        Ok(Self {
            base_url,
            management_key,
            http,
        })
    }

    pub async fn list_codex_files(&self) -> Result<Vec<CpaAuthEntry>> {
        let response = self
            .request(reqwest::Method::GET, "/v0/management/auth-files")
            .send()
            .await
            .context("failed to request CPA auth file list")?
            .error_for_status()
            .context("CPA auth file list request failed")?;
        let payload = response
            .json::<ListAuthFilesResponse>()
            .await
            .context("failed to decode CPA auth file list")?;
        Ok(payload
            .files
            .into_iter()
            .filter_map(|entry| entry.into_codex_entry())
            .collect())
    }

    pub async fn test_connection(&self) -> Result<reqwest::StatusCode> {
        let response = self
            .request(reqwest::Method::GET, "/v0/management/auth-files")
            .send()
            .await
            .context("failed to request CPA auth file list")?;
        Ok(response.status())
    }

    pub async fn download_file(&self, name: &str) -> Result<Vec<u8>> {
        let response = self
            .request(reqwest::Method::GET, "/v0/management/auth-files/download")
            .query(&[("name", name)])
            .send()
            .await
            .with_context(|| format!("failed to download CPA auth file {name}"))?
            .error_for_status()
            .with_context(|| format!("CPA auth file download failed for {name}"))?;
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("failed to read CPA auth file body for {name}"))?;
        Ok(bytes.to_vec())
    }

    pub async fn delete_file(&self, name: &str) -> Result<()> {
        self.request(reqwest::Method::DELETE, "/v0/management/auth-files")
            .query(&[("name", name)])
            .send()
            .await
            .with_context(|| format!("failed to delete CPA auth file {name}"))?
            .error_for_status()
            .with_context(|| format!("CPA auth file delete failed for {name}"))?;
        Ok(())
    }

    pub async fn upload_file(&self, name: &str, data: &[u8]) -> Result<()> {
        self.request(reqwest::Method::POST, "/v0/management/auth-files")
            .query(&[("name", name)])
            .header(CONTENT_TYPE, "application/json")
            .body(data.to_vec())
            .send()
            .await
            .with_context(|| format!("failed to upload CPA auth file {name}"))?
            .error_for_status()
            .with_context(|| format!("CPA auth file upload failed for {name}"))?;
        Ok(())
    }

    pub async fn set_disabled(&self, name: &str, disabled: bool) -> Result<()> {
        self.request(reqwest::Method::PATCH, "/v0/management/auth-files/status")
            .json(&serde_json::json!({
                "name": name,
                "disabled": disabled
            }))
            .send()
            .await
            .with_context(|| format!("failed to update CPA auth file status for {name}"))?
            .error_for_status()
            .with_context(|| format!("CPA auth file status update failed for {name}"))?;
        Ok(())
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base_url, path))
            .header(AUTHORIZATION, format!("Bearer {}", self.management_key))
    }
}

fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to create CPA HTTP client")
}

#[derive(Debug, Deserialize)]
struct ListAuthFilesResponse {
    #[serde(default)]
    files: Vec<RawAuthFileEntry>,
}

#[derive(Debug, Deserialize)]
struct RawAuthFileEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    id_token: Option<RawIdTokenClaims>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    status_message: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    unavailable: bool,
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    runtime_only: bool,
    #[serde(default)]
    next_retry_after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawIdTokenClaims {
    #[serde(default)]
    plan_type: Option<String>,
}

impl RawAuthFileEntry {
    fn into_codex_entry(self) -> Option<CpaAuthEntry> {
        let provider = if self.provider.trim().is_empty() {
            self.r#type.trim()
        } else {
            self.provider.trim()
        };
        if !provider.eq_ignore_ascii_case("codex") {
            return None;
        }
        if !self.source.trim().eq_ignore_ascii_case("file") || self.runtime_only {
            return None;
        }
        let name = self.name.trim();
        if name.is_empty() || !name.to_ascii_lowercase().ends_with(".json") {
            return None;
        }
        Some(CpaAuthEntry {
            name: name.to_string(),
            email: normalize_optional_string(self.email),
            plan_type: self
                .id_token
                .and_then(|claims| normalize_optional_string(claims.plan_type)),
            status: self.status.trim().to_string(),
            status_message: self.status_message.trim().to_string(),
            disabled: self.disabled,
            unavailable: self.unavailable,
            source: self.source.trim().to_string(),
            runtime_only: self.runtime_only,
            next_retry_after: normalize_optional_string(self.next_retry_after),
        })
    }
}

fn default_source() -> String {
    "file".to_string()
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, Instant, sleep};

    #[test]
    fn parses_plan_type_from_cpa_id_token_claims() {
        let payload: ListAuthFilesResponse = serde_json::from_value(serde_json::json!({
            "files": [{
                "name": "free.json",
                "provider": "codex",
                "source": "file",
                "id_token": { "plan_type": " Free " }
            }]
        }))
        .unwrap();

        let entry = payload
            .files
            .into_iter()
            .next()
            .unwrap()
            .into_codex_entry()
            .unwrap();

        assert_eq!(entry.plan_type.as_deref(), Some("Free"));
    }

    #[tokio::test]
    async fn list_codex_files_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            sleep(Duration::from_secs(3600)).await;
        });
        let client = CpaClient {
            base_url: format!("http://{addr}"),
            management_key: "secret".to_string(),
            http: build_http_client(Duration::from_millis(50)).unwrap(),
        };

        let started = Instant::now();
        let err = client.list_codex_files().await.unwrap_err();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(20));
        assert!(elapsed < Duration::from_secs(1));
        assert!(format!("{err:#}").contains("failed to request CPA auth file list"));

        server.abort();
    }

    #[tokio::test]
    async fn test_connection_returns_remote_status_without_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let client = CpaClient {
            base_url: format!("http://{addr}"),
            management_key: "secret".to_string(),
            http: build_http_client(Duration::from_secs(1)).unwrap(),
        };

        let status = client.test_connection().await.unwrap();
        assert_eq!(status.as_u16(), 401);

        server.await.unwrap();
    }
}
