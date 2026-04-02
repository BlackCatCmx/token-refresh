use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use cookie::{Cookie, SameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::TcpListener;

use crate::api;
use crate::config::{ConfigManager, ConfigPaths, parse_byte_size_str};
use crate::credential_store::CredentialStore;
use crate::lockfile::ServiceLock;
use crate::logging::LogManager;
use crate::recovery;
use crate::scheduler::SchedulerHandle;
use crate::status::CredentialStatusStore;
use crate::transaction::RefreshTransaction;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AppState {
    pub config_manager: ConfigManager,
    pub store: Arc<CredentialStore>,
    pub status_store: Arc<CredentialStatusStore>,
    pub logger: Arc<LogManager>,
    pub scheduler: SchedulerHandle,
    pub transaction: Arc<RefreshTransaction>,
    pub session_manager: SessionManager,
    pub _service_lock: Arc<ServiceLock>,
}

#[derive(Clone)]
pub struct SessionManager {
    cookie_name: &'static str,
    expected_value: String,
}

impl SessionManager {
    pub fn new(password: &str) -> Result<Self> {
        let mut mac =
            HmacSha256::new_from_slice(password.as_bytes()).context("invalid HMAC key")?;
        mac.update(password.as_bytes());
        let expected_value = hex_encode(&mac.finalize().into_bytes());
        Ok(Self {
            cookie_name: "codex_refresh_session",
            expected_value,
        })
    }

    pub fn is_authenticated(&self, headers: &HeaderMap) -> bool {
        let cookies = headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        Cookie::split_parse(cookies).flatten().any(|cookie| {
            cookie.name() == self.cookie_name && cookie.value() == self.expected_value
        })
    }

    pub fn login_cookie(&self) -> Result<String> {
        Ok(
            Cookie::build((self.cookie_name, self.expected_value.clone()))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .build()
                .to_string(),
        )
    }

    pub fn logout_cookie(&self) -> Result<String> {
        Ok(Cookie::build((self.cookie_name, ""))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .build()
            .to_string())
    }
}

pub async fn serve(config_paths: ConfigPaths) -> Result<()> {
    let config_manager = ConfigManager::load(config_paths).await?;
    let config = config_manager.effective_config().await;
    std::fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("failed to create {}", config.state_dir.display()))?;
    let service_lock = Arc::new(ServiceLock::acquire(
        &config.state_dir.join("service.lock"),
    )?);
    let logger = Arc::new(LogManager::new(
        &config.state_dir,
        parse_byte_size_str(&config.logging.max_file_size)?,
        &config.log_level,
    )?);
    let _ = logger.runtime("info", "service starting");
    let _ = logger.runtime(
        "info",
        format!(
            "service config state_dir={} credentials_dir={} abnormal_dir={} log_level={} web_enabled={} listen={}",
            config.state_dir.display(),
            config.credentials_dir.display(),
            config.abnormal_credentials_dir.display(),
            config.log_level.trim(),
            config.web.enabled,
            config.web.listen.trim()
        ),
    );
    let store = Arc::new(CredentialStore::new(&config, Some(logger.clone()))?);
    recovery::recover_all(
        &[
            store.normal_dir().to_path_buf(),
            store.abnormal_dir().to_path_buf(),
        ],
        &logger,
    )?;
    let status_store = Arc::new(CredentialStatusStore::load(
        config.state_dir.join("credential_status.json"),
    )?);
    let transaction = Arc::new(RefreshTransaction::new(
        store.clone(),
        status_store.clone(),
        logger.clone(),
    ));
    let scheduler = SchedulerHandle::new();
    let session_manager = SessionManager::new(&config_manager.web_password().await)?;

    if !config.web.enabled {
        let _ = logger.runtime("info", "web interface disabled; scheduler-only mode active");
        scheduler.spawn_background(config_manager.clone(), store, transaction, logger);
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let listener = TcpListener::bind(config.web.listen.trim())
        .await
        .with_context(|| format!("failed to bind {}", config.web.listen))?;
    let _ = logger.runtime(
        "info",
        format!("web interface listening on {}", config.web.listen.trim()),
    );

    let state = Arc::new(AppState {
        config_manager: config_manager.clone(),
        store: store.clone(),
        status_store: status_store.clone(),
        logger: logger.clone(),
        scheduler: scheduler.clone(),
        transaction: transaction.clone(),
        session_manager,
        _service_lock: service_lock,
    });
    scheduler.spawn_background(config_manager, store, transaction, logger);

    let app = api::router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

pub fn login_page() -> &'static str {
    include_str!("../static/login.html")
}

pub fn dashboard_page() -> &'static str {
    include_str!("../static/dashboard.html")
}

pub fn app_css() -> &'static str {
    include_str!("../static/app.css")
}

pub fn login_js() -> &'static str {
    include_str!("../static/login.js")
}

pub fn dashboard_js() -> &'static str {
    include_str!("../static/dashboard.js")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}
