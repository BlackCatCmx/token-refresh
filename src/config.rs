use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fsutil;
use crate::originator;
use crate::user_agent;

#[derive(Clone, Debug)]
pub struct ConfigPaths {
    pub cli_config_path: Option<PathBuf>,
}

impl ConfigPaths {
    pub fn from_cli(cli_config_path: Option<PathBuf>) -> Self {
        Self { cli_config_path }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_credentials_dir")]
    pub credentials_dir: PathBuf,
    #[serde(default = "default_abnormal_credentials_dir")]
    pub abnormal_credentials_dir: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub request_identity: RequestIdentityConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub credential_management: CredentialManagementConfig,
    #[serde(default)]
    pub refresh: RefreshConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub web: WebConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            credentials_dir: default_credentials_dir(),
            abnormal_credentials_dir: default_abnormal_credentials_dir(),
            state_dir: default_state_dir(),
            log_level: default_log_level(),
            logging: LoggingConfig::default(),
            request_identity: RequestIdentityConfig::default(),
            proxy: ProxyConfig::default(),
            credential_management: CredentialManagementConfig::default(),
            refresh: RefreshConfig::default(),
            network: NetworkConfig::default(),
            web: WebConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_max_file_size")]
    pub max_file_size: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            max_file_size: default_max_file_size(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestIdentityConfig {
    #[serde(default = "default_originator")]
    pub originator: String,
    #[serde(default = "default_user_agent_mode")]
    pub user_agent_mode: String,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub user_agent_rules: user_agent::UserAgentRulesConfig,
}

impl Default for RequestIdentityConfig {
    fn default() -> Self {
        Self {
            originator: default_originator(),
            user_agent_mode: default_user_agent_mode(),
            user_agent: default_user_agent(),
            user_agent_rules: user_agent::UserAgentRulesConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_mode")]
    pub mode: String,
    #[serde(default)]
    pub list: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: default_proxy_mode(),
            list: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialManagementConfig {
    #[serde(default = "default_abnormal_threshold")]
    pub abnormal_threshold: u32,
}

impl Default for CredentialManagementConfig {
    fn default() -> Self {
        Self {
            abnormal_threshold: default_abnormal_threshold(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshConfig {
    #[serde(default = "default_lead_time")]
    pub lead_time: String,
    #[serde(default = "default_min_sleep")]
    pub min_sleep: String,
    #[serde(default = "default_max_sleep")]
    pub max_sleep: String,
    #[serde(default = "default_inter_refresh_delay_min")]
    pub inter_refresh_delay_min: String,
    #[serde(default = "default_inter_refresh_delay_max")]
    pub inter_refresh_delay_max: String,
    #[serde(default = "default_failure_backoff")]
    pub failure_backoff: String,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            lead_time: default_lead_time(),
            min_sleep: default_min_sleep(),
            max_sleep: default_max_sleep(),
            inter_refresh_delay_min: default_inter_refresh_delay_min(),
            inter_refresh_delay_max: default_inter_refresh_delay_max(),
            failure_backoff: default_failure_backoff(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_enabled")]
    pub enabled: bool,
    #[serde(default = "default_web_listen")]
    pub listen: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: default_web_enabled(),
            listen: default_web_listen(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableSettings {
    pub log_level: String,
    pub logging: LoggingConfig,
    pub request_identity: RequestIdentityConfig,
    pub proxy: ProxyConfig,
    pub credential_management: CredentialManagementConfig,
    pub refresh: EditableRefreshConfig,
    pub network: NetworkConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableRefreshConfig {
    pub lead_time: String,
    pub inter_refresh_delay_min: String,
    pub inter_refresh_delay_max: String,
    pub failure_backoff: String,
}

impl From<&AppConfig> for EditableSettings {
    fn from(value: &AppConfig) -> Self {
        Self {
            log_level: value.log_level.clone(),
            logging: value.logging.clone(),
            request_identity: value.request_identity.clone(),
            proxy: value.proxy.clone(),
            credential_management: value.credential_management.clone(),
            refresh: EditableRefreshConfig {
                lead_time: value.refresh.lead_time.clone(),
                inter_refresh_delay_min: value.refresh.inter_refresh_delay_min.clone(),
                inter_refresh_delay_max: value.refresh.inter_refresh_delay_max.clone(),
                failure_backoff: value.refresh.failure_backoff.clone(),
            },
            network: value.network.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoadedConfig {
    pub persisted_config: AppConfig,
    pub effective_config: AppConfig,
    pub config_path: PathBuf,
    pub locked_fields: BTreeSet<String>,
    pub web_password: String,
}

#[derive(Clone, Debug)]
pub struct ConfigManager {
    inner: Arc<RwLock<LoadedConfig>>,
}

impl ConfigManager {
    pub async fn load(paths: ConfigPaths) -> Result<Self> {
        let config_path = resolve_config_path(paths);
        let persisted_config = load_config_file(&config_path)?;
        let (effective_config, locked_fields) = apply_env_overrides(persisted_config.clone())?;
        validate_config(&effective_config)?;
        let web_password = env::var("WEB_PASSWORD")
            .context("WEB_PASSWORD is required")?
            .trim()
            .to_string();
        if web_password.is_empty() {
            bail!("WEB_PASSWORD is required");
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(LoadedConfig {
                persisted_config,
                effective_config,
                config_path,
                locked_fields,
                web_password,
            })),
        })
    }

    pub async fn effective_config(&self) -> AppConfig {
        self.inner.read().await.effective_config.clone()
    }

    pub async fn editable_settings(&self) -> EditableSettings {
        let guard = self.inner.read().await;
        EditableSettings::from(&guard.effective_config)
    }

    pub async fn locked_fields(&self) -> BTreeSet<String> {
        self.inner.read().await.locked_fields.clone()
    }

    pub async fn config_path(&self) -> PathBuf {
        self.inner.read().await.config_path.clone()
    }

    pub async fn web_password(&self) -> String {
        self.inner.read().await.web_password.clone()
    }

    pub async fn header_preview(&self) -> Result<BTreeMap<String, String>> {
        let guard = self.inner.read().await;
        header_preview(&guard.effective_config)
    }

    pub async fn random_header_preview(&self) -> Result<BTreeMap<String, String>> {
        let guard = self.inner.read().await;
        random_header_preview(&guard.effective_config)
    }

    pub async fn update_settings(&self, settings: EditableSettings) -> Result<AppConfig> {
        let mut guard = self.inner.write().await;
        reject_locked_field_updates(&guard.locked_fields, &settings, &guard.effective_config)?;
        let mut updated = guard.persisted_config.clone();
        apply_editable_settings(&mut updated, settings);
        validate_config(&updated)?;
        fsutil::atomic_write_bytes(
            &guard.config_path,
            serde_yaml::to_string(&updated)
                .context("failed to serialize config")?
                .as_bytes(),
        )?;
        let (effective_config, locked_fields) = apply_env_overrides(updated.clone())?;
        validate_config(&effective_config)?;
        guard.persisted_config = updated;
        guard.effective_config = effective_config.clone();
        guard.locked_fields = locked_fields;
        Ok(effective_config)
    }
}

pub fn header_preview(config: &AppConfig) -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "User-Agent".to_string(),
            user_agent::preview_value(
                &config.request_identity.originator,
                &config.request_identity.user_agent_mode,
                &config.request_identity.user_agent,
                &config.request_identity.user_agent_rules,
            ),
        ),
        (
            "originator".to_string(),
            config.request_identity.originator.clone(),
        ),
    ]))
}

pub fn random_header_preview(config: &AppConfig) -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "User-Agent".to_string(),
            user_agent::random_preview_value(
                &config.request_identity.originator,
                &config.request_identity.user_agent_mode,
                &config.request_identity.user_agent,
                &config.request_identity.user_agent_rules,
            )?,
        ),
        (
            "originator".to_string(),
            config.request_identity.originator.clone(),
        ),
    ]))
}

pub fn validate_config(config: &AppConfig) -> Result<()> {
    let level = config.log_level.trim().to_ascii_lowercase();
    if !matches!(level.as_str(), "info" | "warn" | "error") {
        bail!("invalid log_level: {}", config.log_level);
    }
    originator::validate(config.request_identity.originator.trim())?;
    user_agent::validate_settings(
        &config.request_identity.originator,
        &config.request_identity.user_agent_mode,
        &config.request_identity.user_agent,
        &config.request_identity.user_agent_rules,
    )?;
    if config.credential_management.abnormal_threshold == 0 {
        bail!("credential_management.abnormal_threshold must be >= 1");
    }
    parse_duration_str(&config.refresh.lead_time)?;
    parse_duration_str(&config.refresh.min_sleep)?;
    parse_duration_str(&config.refresh.max_sleep)?;
    let min_delay = parse_duration_str(&config.refresh.inter_refresh_delay_min)?;
    let max_delay = parse_duration_str(&config.refresh.inter_refresh_delay_max)?;
    if min_delay > max_delay {
        bail!("refresh.inter_refresh_delay_min must be <= refresh.inter_refresh_delay_max");
    }
    parse_duration_str(&config.refresh.failure_backoff)?;
    parse_duration_str(&config.network.timeout)?;
    parse_byte_size_str(&config.logging.max_file_size)?;
    validate_proxy_mode(config.proxy.mode.trim())?;
    crate::proxy::validate_proxy_list(&config.proxy.list)?;
    SocketAddr::from_str(config.web.listen.trim())
        .with_context(|| format!("invalid web.listen: {}", config.web.listen))?;
    Ok(())
}

pub fn parse_duration_str(value: &str) -> Result<Duration> {
    humantime::parse_duration(value.trim())
        .with_context(|| format!("invalid duration value: {value}"))
}

pub fn parse_byte_size_str(value: &str) -> Result<u64> {
    let raw = value.trim();
    if raw.is_empty() {
        bail!("byte size cannot be empty");
    }
    let upper = raw.to_ascii_uppercase();
    let units = [
        ("GIB", 1024_u64.pow(3)),
        ("MIB", 1024_u64.pow(2)),
        ("KIB", 1024_u64),
        ("GB", 1000_u64.pow(3)),
        ("MB", 1000_u64.pow(2)),
        ("KB", 1000_u64),
        ("B", 1_u64),
    ];
    for (suffix, multiplier) in units {
        if let Some(number) = upper.strip_suffix(suffix) {
            let parsed = number
                .trim()
                .parse::<u64>()
                .with_context(|| format!("invalid byte size value: {value}"))?;
            return Ok(parsed.saturating_mul(multiplier));
        }
    }
    raw.parse::<u64>()
        .with_context(|| format!("invalid byte size value: {value}"))
}

fn resolve_config_path(paths: ConfigPaths) -> PathBuf {
    if let Some(path) = paths.cli_config_path {
        return path;
    }
    let legacy = PathBuf::from("./config.yaml");
    if legacy.exists() {
        return legacy;
    }
    default_config_path()
}

fn load_config_file(path: &PathBuf) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))
}

fn apply_env_overrides(mut config: AppConfig) -> Result<(AppConfig, BTreeSet<String>)> {
    let mut locked = BTreeSet::new();
    if let Ok(value) = env::var("LOG_LEVEL") {
        config.log_level = value;
        locked.insert("log_level".to_string());
    }
    if let Ok(port) = env::var("PORT") {
        let trimmed = port.trim();
        if !trimmed.is_empty() {
            config.web.listen = format!("0.0.0.0:{trimmed}");
            locked.insert("web.listen".to_string());
        }
    }
    Ok((config, locked))
}

fn reject_locked_field_updates(
    locked_fields: &BTreeSet<String>,
    incoming: &EditableSettings,
    current: &AppConfig,
) -> Result<()> {
    let current_settings = EditableSettings::from(current);
    let changed_fields = diff_editable_settings(&current_settings, incoming);
    let violations: Vec<&String> = changed_fields
        .iter()
        .filter(|field| locked_fields.contains(field.as_str()))
        .collect();
    if !violations.is_empty() {
        bail!(
            "some fields are controlled by environment variables: {}",
            violations
                .iter()
                .map(|field| field.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn diff_editable_settings(current: &EditableSettings, incoming: &EditableSettings) -> Vec<String> {
    let mut changed = Vec::new();
    if current.log_level != incoming.log_level {
        changed.push("log_level".to_string());
    }
    if current.logging.max_file_size != incoming.logging.max_file_size {
        changed.push("logging.max_file_size".to_string());
    }
    if current.request_identity.originator != incoming.request_identity.originator {
        changed.push("request_identity.originator".to_string());
    }
    if current.request_identity.user_agent_mode != incoming.request_identity.user_agent_mode {
        changed.push("request_identity.user_agent_mode".to_string());
    }
    if current.request_identity.user_agent != incoming.request_identity.user_agent {
        changed.push("request_identity.user_agent".to_string());
    }
    if current.request_identity.user_agent_rules != incoming.request_identity.user_agent_rules {
        changed.push("request_identity.user_agent_rules".to_string());
    }
    if current.proxy.mode != incoming.proxy.mode {
        changed.push("proxy.mode".to_string());
    }
    if current.proxy.list != incoming.proxy.list {
        changed.push("proxy.list".to_string());
    }
    if current.credential_management.abnormal_threshold
        != incoming.credential_management.abnormal_threshold
    {
        changed.push("credential_management.abnormal_threshold".to_string());
    }
    if current.refresh.lead_time != incoming.refresh.lead_time {
        changed.push("refresh.lead_time".to_string());
    }
    if current.refresh.inter_refresh_delay_min != incoming.refresh.inter_refresh_delay_min {
        changed.push("refresh.inter_refresh_delay_min".to_string());
    }
    if current.refresh.inter_refresh_delay_max != incoming.refresh.inter_refresh_delay_max {
        changed.push("refresh.inter_refresh_delay_max".to_string());
    }
    if current.refresh.failure_backoff != incoming.refresh.failure_backoff {
        changed.push("refresh.failure_backoff".to_string());
    }
    if current.network.timeout != incoming.network.timeout {
        changed.push("network.timeout".to_string());
    }
    changed
}

fn apply_editable_settings(config: &mut AppConfig, settings: EditableSettings) {
    config.log_level = settings.log_level;
    config.logging = settings.logging;
    config.request_identity = settings.request_identity;
    config.proxy = settings.proxy;
    config.credential_management = settings.credential_management;
    config.refresh.lead_time = settings.refresh.lead_time;
    config.refresh.inter_refresh_delay_min = settings.refresh.inter_refresh_delay_min;
    config.refresh.inter_refresh_delay_max = settings.refresh.inter_refresh_delay_max;
    config.refresh.failure_backoff = settings.refresh.failure_backoff;
    config.network = settings.network;
}

fn validate_proxy_mode(value: &str) -> Result<()> {
    if matches!(value, "fixed" | "round_robin") {
        Ok(())
    } else {
        bail!("proxy.mode must be fixed or round_robin")
    }
}

fn default_credentials_dir() -> PathBuf {
    storage_path("./credentials", &["credentials"])
}

fn default_abnormal_credentials_dir() -> PathBuf {
    storage_path("./credentials_abnormal", &["credentials_abnormal"])
}

fn default_state_dir() -> PathBuf {
    storage_path("./state", &["state"])
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_max_file_size() -> String {
    "1MiB".to_string()
}

fn default_originator() -> String {
    originator::DEFAULT_ORIGINATOR.to_string()
}

fn default_user_agent() -> String {
    user_agent::DEFAULT_USER_AGENT.to_string()
}

fn default_user_agent_mode() -> String {
    user_agent::DEFAULT_USER_AGENT_MODE.to_string()
}

fn default_proxy_mode() -> String {
    "fixed".to_string()
}

fn default_abnormal_threshold() -> u32 {
    1
}

fn default_lead_time() -> String {
    "24h".to_string()
}

fn default_min_sleep() -> String {
    "60s".to_string()
}

fn default_max_sleep() -> String {
    "10m".to_string()
}

fn default_inter_refresh_delay_min() -> String {
    "30s".to_string()
}

fn default_inter_refresh_delay_max() -> String {
    "90s".to_string()
}

fn default_failure_backoff() -> String {
    "15m".to_string()
}

fn default_timeout() -> String {
    "30s".to_string()
}

fn default_web_enabled() -> bool {
    true
}

fn default_web_listen() -> String {
    "0.0.0.0:9876".to_string()
}

fn default_config_path() -> PathBuf {
    storage_path("./state/config.yaml", &["state", "config.yaml"])
}

fn storage_path(local: &str, data_segments: &[&str]) -> PathBuf {
    storage_path_with_root(preferred_data_root(), local, data_segments)
}

fn storage_path_with_root(root: Option<PathBuf>, local: &str, data_segments: &[&str]) -> PathBuf {
    match root {
        Some(path) => data_segments
            .iter()
            .fold(path, |current, segment| current.join(segment)),
        None => PathBuf::from(local),
    }
}

fn preferred_data_root() -> Option<PathBuf> {
    let root = PathBuf::from("/data");
    root.is_dir().then_some(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_path_uses_data_root_when_available() {
        let resolved = storage_path_with_root(
            Some(PathBuf::from("/data")),
            "./state/config.yaml",
            &["state", "config.yaml"],
        );
        assert_eq!(
            resolved,
            PathBuf::from("/data").join("state").join("config.yaml")
        );
    }

    #[test]
    fn storage_path_falls_back_to_local_relative_path() {
        let resolved =
            storage_path_with_root(None, "./state/config.yaml", &["state", "config.yaml"]);
        assert_eq!(resolved, PathBuf::from("./state/config.yaml"));
    }

    #[test]
    fn validate_config_rejects_removed_log_levels() {
        let mut config = AppConfig::default();
        config.log_level = "debug".to_string();
        assert!(validate_config(&config).is_err());

        config.log_level = "trace".to_string();
        assert!(validate_config(&config).is_err());
    }
}
