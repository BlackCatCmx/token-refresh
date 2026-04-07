use std::sync::Arc;

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use cookie::{Cookie, SameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::TcpListener;

use crate::api;
use crate::backup::BackupCoordinator;
use crate::config::{ConfigManager, ConfigPaths, parse_byte_size_str};
use crate::credential_store::CredentialStore;
use crate::lockfile::ServiceLock;
use crate::logging::LogManager;
use crate::recovery;
use crate::scheduler::SchedulerHandle;
use crate::status::CredentialStatusStore;
use crate::transaction::RefreshTransaction;
use crate::write_coordinator::WriteCoordinator;

type HmacSha256 = Hmac<Sha256>;
const SESSION_COOKIE_LIFETIME_DAYS: i64 = 3650;

#[derive(Clone)]
pub struct AppState {
    pub config_manager: ConfigManager,
    pub store: Arc<CredentialStore>,
    pub status_store: Arc<CredentialStatusStore>,
    pub logger: Arc<LogManager>,
    pub scheduler: SchedulerHandle,
    pub transaction: Arc<RefreshTransaction>,
    pub backup: Arc<BackupCoordinator>,
    pub write_coordinator: Arc<WriteCoordinator>,
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
        let max_age = cookie::time::Duration::days(SESSION_COOKIE_LIFETIME_DAYS);
        let expires_at = cookie::time::OffsetDateTime::now_utc() + max_age;
        Ok(
            Cookie::build((self.cookie_name, self.expected_value.clone()))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .max_age(max_age)
                .expires(expires_at)
                .build()
                .to_string(),
        )
    }

    pub fn logout_cookie(&self) -> Result<String> {
        let removed_at = cookie::time::OffsetDateTime::UNIX_EPOCH;
        Ok(Cookie::build((self.cookie_name, ""))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .expires(removed_at)
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
    let write_coordinator = Arc::new(WriteCoordinator::new());
    let transaction = Arc::new(RefreshTransaction::new(
        store.clone(),
        status_store.clone(),
        logger.clone(),
        write_coordinator.clone(),
    ));
    let scheduler = SchedulerHandle::load(config.state_dir.join("scheduler_state.json"))?;
    let backup = Arc::new(BackupCoordinator::new(
        config_manager.clone(),
        store.clone(),
        status_store.clone(),
        scheduler.clone(),
        logger.clone(),
        write_coordinator.clone(),
    ));
    let session_manager = SessionManager::new(&config_manager.web_password().await)?;
    backup.spawn_background();

    if !config.web.enabled {
        let _ = logger.runtime("info", "web interface disabled; scheduler-only mode active");
        scheduler.spawn_background(
            config_manager.clone(),
            store,
            status_store,
            transaction,
            Some(backup),
            logger,
        );
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
        backup: backup.clone(),
        write_coordinator,
        session_manager,
        _service_lock: service_lock,
    });
    scheduler.spawn_background(
        config_manager,
        store,
        status_store,
        transaction,
        Some(backup),
        logger,
    );

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

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, header};

    use super::*;

    #[test]
    fn login_cookie_is_persistent_and_authenticates_requests() {
        let session = SessionManager::new("secret").unwrap();
        let set_cookie = session.login_cookie().unwrap();
        let parsed = Cookie::parse(set_cookie).unwrap();

        assert_eq!(parsed.name(), "codex_refresh_session");
        assert_eq!(parsed.value(), session.expected_value);
        assert_eq!(
            parsed.max_age(),
            Some(cookie::time::Duration::days(SESSION_COOKIE_LIFETIME_DAYS))
        );
        assert!(parsed.expires().is_some());
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Lax));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{}={}", parsed.name(), parsed.value())
                .parse()
                .unwrap(),
        );
        assert!(session.is_authenticated(&headers));
    }

    #[test]
    fn logout_cookie_clears_session() {
        let session = SessionManager::new("secret").unwrap();
        let set_cookie = session.logout_cookie().unwrap();
        let parsed = Cookie::parse(set_cookie).unwrap();

        assert_eq!(parsed.name(), "codex_refresh_session");
        assert_eq!(parsed.value(), "");
        assert_eq!(parsed.max_age(), Some(cookie::time::Duration::seconds(0)));
        assert!(parsed.expires().is_some());
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Lax));
    }
}
