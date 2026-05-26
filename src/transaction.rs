use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::config::{AppConfig, parse_duration_str};
use crate::credential::CodexCredentialFile;
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::jwt;
use crate::logging::LogManager;
use crate::memdiag::{self, MemSample};
use crate::recovery;
use crate::refresh_client::{
    RefreshClient, RefreshFailure, RefreshResponsePayload, RefreshSuccess,
};
use crate::status::CredentialStatusStore;
use crate::write_coordinator::WriteCoordinator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTrigger {
    Manual,
    ManualBatch,
    Scheduler,
}

impl RefreshTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::ManualBatch => "manual_batch",
            Self::Scheduler => "scheduler",
        }
    }
}

#[derive(Debug)]
pub struct RefreshTransaction {
    store: Arc<CredentialStore>,
    status_store: Arc<CredentialStatusStore>,
    logger: Arc<LogManager>,
    write_coordinator: Arc<WriteCoordinator>,
    client: RefreshClient,
}

#[derive(Clone, Debug)]
pub struct RefreshOutcome {
    pub success: bool,
    pub zone: CredentialZone,
    pub key: String,
    pub message: String,
    pub failure_code: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct RefreshMemContext {
    started_at: Instant,
    before: MemSample,
}

impl RefreshTransaction {
    pub fn new(
        store: Arc<CredentialStore>,
        status_store: Arc<CredentialStatusStore>,
        logger: Arc<LogManager>,
        write_coordinator: Arc<WriteCoordinator>,
    ) -> Self {
        Self {
            store,
            status_store,
            logger,
            write_coordinator,
            client: RefreshClient::new(),
        }
    }

    pub async fn refresh_one(
        &self,
        config: &AppConfig,
        zone: CredentialZone,
        key: &str,
        trigger: RefreshTrigger,
    ) -> Result<RefreshOutcome> {
        let _activity_guard = self.write_coordinator.lock_activity().await;
        let generation = self.write_coordinator.generation();
        self.write_coordinator.ensure_writes_allowed()?;
        let entry = self.store.read_entry(zone, key)?;
        if let Some(parse_error) = entry.parse_error {
            return self
                .handle_failure(
                    config,
                    zone,
                    key,
                    trigger,
                    generation,
                    RefreshFailure::deterministic("invalid_json", parse_error),
                )
                .await;
        }
        let mut credential = entry
            .credential
            .context("credential entry unexpectedly missing parsed credential")?;
        if !credential.is_codex() {
            return self
                .handle_failure(
                    config,
                    zone,
                    key,
                    trigger,
                    generation,
                    RefreshFailure::transient(
                        "unsupported_provider",
                        "credential type is not codex",
                    ),
                )
                .await;
        }
        if credential.refresh_token.trim().is_empty() {
            return self
                .handle_failure(
                    config,
                    zone,
                    key,
                    trigger,
                    generation,
                    RefreshFailure::deterministic(
                        "missing_refresh_token",
                        "credential is missing refresh_token",
                    ),
                )
                .await;
        }

        let mem_context = RefreshMemContext {
            started_at: Instant::now(),
            before: memdiag::sample_full(),
        };
        self.logger.runtime(
            "info",
            format!(
                "refresh starting for {} in {} via {} (expires_at={}, last_refresh={}, proxy_mode={}, timeout={}, rss_before_kb={}, cg_before_kb={}, gap_before_kb={}, cg_anon_kb={}, cg_file_kb={}, cg_shmem_kb={}, cg_file_mapped_kb={}, cg_active_file_kb={}, cg_inactive_file_kb={}, cg_pgfault={}, cg_pgmajfault={}, cg_workingset_refault_file={}, cg_workingset_activate_file={})",
                key,
                zone.as_str(),
                trigger.as_str(),
                credential.expired.as_deref().unwrap_or("-"),
                credential.last_refresh.as_deref().unwrap_or("-"),
                config.proxy.mode.trim(),
                config.network.timeout.trim(),
                mem_context.before.fmt_rss(),
                mem_context.before.fmt_cg(),
                mem_context.before.fmt_gap(),
                mem_context.before.fmt_anon(),
                mem_context.before.fmt_file(),
                mem_context.before.fmt_shmem(),
                mem_context.before.fmt_file_mapped(),
                mem_context.before.fmt_active_file(),
                mem_context.before.fmt_inactive_file(),
                mem_context.before.fmt_pgfault(),
                mem_context.before.fmt_pgmajfault(),
                mem_context.before.fmt_workingset_refault_file(),
                mem_context.before.fmt_workingset_activate_file(),
            ),
        )?;

        let request_user_agent =
            match crate::user_agent::normalize_optional(credential.normalized_user_agent()) {
                Ok(Some(value)) => value,
                Ok(None) => crate::user_agent::DEFAULT_USER_AGENT.to_string(),
                Err(err) => {
                    return self
                        .handle_failure(
                            config,
                            zone,
                            key,
                            trigger,
                            generation,
                            RefreshFailure::deterministic("invalid_user_agent", err.to_string()),
                        )
                        .await;
                }
            };

        let refresh_result = match self
            .refresh_with_proxy_fallback(
                config,
                credential.refresh_token.trim(),
                &request_user_agent,
                key,
            )
            .await
        {
            Ok(value) => value,
            Err(err) => {
                let _ = self.log_refresh_mem_finish(
                    key,
                    trigger,
                    zone.as_str(),
                    zone.as_str(),
                    "error",
                    &mem_context,
                );
                return Err(err);
            }
        };
        let outcome = match refresh_result {
            Ok(payload) => {
                self.handle_success(
                    config,
                    zone,
                    key,
                    trigger,
                    generation,
                    &mut credential,
                    payload,
                )
                .await
            }
            Err(error) => {
                self.handle_failure(config, zone, key, trigger, generation, error)
                    .await
            }
        };
        let (outcome_label, final_zone) = match &outcome {
            Ok(result) => (
                if result.success { "success" } else { "failure" },
                result.zone.as_str(),
            ),
            Err(_) => ("error", zone.as_str()),
        };
        let _ = self.log_refresh_mem_finish(
            key,
            trigger,
            zone.as_str(),
            final_zone,
            outcome_label,
            &mem_context,
        );
        outcome
    }

    async fn handle_success(
        &self,
        _config: &AppConfig,
        zone: CredentialZone,
        key: &str,
        trigger: RefreshTrigger,
        generation: u64,
        credential: &mut CodexCredentialFile,
        success: RefreshSuccess,
    ) -> Result<RefreshOutcome> {
        let previous_refresh_token = credential.refresh_token.clone();
        let proxy_label = success.proxy_label;
        merge_refresh_response(credential, success.payload)?;
        credential.provider_type = "codex".to_string();
        credential.set_last_refresh_now();
        {
            let _commit_guard = self.write_coordinator.lock_commit().await;
            self.write_coordinator
                .ensure_generation_current(generation)?;
            let target_path = self.store.key_to_path(zone, key)?;
            recovery::write_recovery(&target_path, credential)?;
            self.store.write_credential(zone, key, credential)?;
            if let Err(err) = recovery::delete_recovery(&target_path) {
                let _ = self.logger.runtime(
                    "warn",
                    format!(
                        "credential {} refreshed but recovery cleanup failed: {err:#}",
                        key
                    ),
                );
            }
            self.status_store.record_success(key, zone.as_str())?;
        }
        self.logger.audit(format!(
            "refresh_success trigger={} zone={} key={}",
            trigger.as_str(),
            zone.as_str(),
            key
        ))?;
        self.logger.runtime(
            "info",
            format!(
                "refresh succeeded for {} in {} via {} (expires_at={}, proxy={}, refresh_token_rotated={})",
                key,
                zone.as_str(),
                trigger.as_str(),
                credential.expired.as_deref().unwrap_or("-"),
                proxy_label,
                credential.refresh_token != previous_refresh_token
            ),
        )?;
        Ok(RefreshOutcome {
            success: true,
            zone,
            key: key.to_string(),
            message: "refresh succeeded".to_string(),
            failure_code: None,
        })
    }

    async fn refresh_with_proxy_fallback(
        &self,
        config: &AppConfig,
        refresh_token: &str,
        user_agent: &str,
        key: &str,
    ) -> Result<std::result::Result<RefreshSuccess, RefreshFailure>> {
        let primary_proxies = match crate::proxy::validate_proxy_list(&config.proxy.list) {
            Ok(value) => value,
            Err(err) => {
                return Ok(Err(RefreshFailure::transient(
                    "invalid_proxy_list",
                    err.to_string(),
                )));
            }
        };
        let backup_proxies = match crate::proxy::validate_proxy_list(&config.proxy.backup_list) {
            Ok(value) => value,
            Err(err) => {
                return Ok(Err(RefreshFailure::transient(
                    "invalid_backup_proxy_list",
                    err.to_string(),
                )));
            }
        };

        let mode = config.proxy.mode.trim();
        let primary_start_index = if mode == "round_robin" && !primary_proxies.is_empty() {
            self.client
                .reserve_proxy_index_from_list(mode, &primary_proxies)?
        } else {
            None
        };
        let attempt_sequence = match build_proxy_attempt_sequence(
            mode,
            &primary_proxies,
            &backup_proxies,
            primary_start_index,
        ) {
            Ok(value) => value,
            Err(err) => {
                return Ok(Err(RefreshFailure::transient(
                    "invalid_proxy_mode",
                    err.to_string(),
                )));
            }
        };

        for (index, attempt) in attempt_sequence.iter().enumerate() {
            let attempt_result = match attempt {
                ProxyAttempt::Primary(proxy) | ProxyAttempt::Backup(proxy) => {
                    self.client
                        .refresh_with_proxy(config, refresh_token, user_agent, Some(proxy))
                        .await
                }
                ProxyAttempt::Direct => {
                    self.client
                        .refresh_with_proxy(config, refresh_token, user_agent, None)
                        .await
                }
            };
            match attempt_result {
                Ok(payload) => return Ok(Ok(payload)),
                Err(error) if should_fallback_to_next_proxy(&error) => {
                    let Some(next_attempt) = attempt_sequence.get(index + 1) else {
                        return Ok(Err(error));
                    };
                    if let Err(err) = log_proxy_fallback_transition(
                        self.logger.as_ref(),
                        key,
                        attempt,
                        next_attempt,
                        error.proxy_host.as_deref(),
                    ) {
                        return Ok(Err(RefreshFailure::transient(
                            "internal_error",
                            err.to_string(),
                        )));
                    }
                    continue;
                }
                Err(error) => return Ok(Err(error)),
            }
        }

        Ok(Err(RefreshFailure::transient(
            "internal_error",
            "proxy attempt sequence did not terminate with Direct",
        )))
    }

    async fn handle_failure(
        &self,
        config: &AppConfig,
        zone: CredentialZone,
        key: &str,
        trigger: RefreshTrigger,
        generation: u64,
        error: RefreshFailure,
    ) -> Result<RefreshOutcome> {
        let (failure_count, moved, final_zone) = {
            let _commit_guard = self.write_coordinator.lock_commit().await;
            self.write_coordinator
                .ensure_generation_current(generation)?;
            let current_failures = self
                .status_store
                .get(key)?
                .map(|record| record.consecutive_failure_count)
                .unwrap_or(0);
            let failure_count = if error.count_towards_abnormal {
                current_failures.saturating_add(1)
            } else {
                current_failures
            };
            let should_move = zone == CredentialZone::Normal
                && error.count_towards_abnormal
                && failure_count >= config.credential_management.abnormal_threshold;
            let moved = if should_move {
                match self.store.move_between_zones(
                    CredentialZone::Normal,
                    CredentialZone::Abnormal,
                    key,
                ) {
                    Ok(()) => true,
                    Err(move_error) => {
                        self.logger.runtime(
                            "error",
                            format!("failed to move {} to abnormal zone: {move_error:#}", key),
                        )?;
                        false
                    }
                }
            } else {
                false
            };
            let final_zone = if moved {
                CredentialZone::Abnormal
            } else {
                zone
            };
            self.status_store.record_failure(
                key,
                zone.as_str(),
                error.count_towards_abnormal,
                moved,
                error.code.clone(),
                error.reason.clone(),
            )?;
            (failure_count, moved, final_zone)
        };
        self.logger.audit(format!(
            "refresh_failed trigger={} zone={} key={} code={} moved_to_abnormal={}",
            trigger.as_str(),
            zone.as_str(),
            key,
            error.code,
            moved
        ))?;
        self.logger.runtime(
            "warn",
            format!(
                "refresh failed for {} in {} via {} (code={}, proxy={}, failure_count={}, count_towards_abnormal={}, moved_to_abnormal={}, final_zone={}): {}",
                key,
                zone.as_str(),
                trigger.as_str(),
                error.code,
                proxy_attempt_label(error.proxy_label.as_deref()),
                failure_count,
                error.count_towards_abnormal,
                moved,
                final_zone.as_str(),
                error
            ),
        )?;
        Ok(RefreshOutcome {
            success: false,
            zone: final_zone,
            key: key.to_string(),
            message: error.reason.clone(),
            failure_code: Some(error.code),
        })
    }

    fn log_refresh_mem_finish(
        &self,
        key: &str,
        trigger: RefreshTrigger,
        zone_before: &str,
        zone_after: &str,
        outcome: &str,
        mem_context: &RefreshMemContext,
    ) -> Result<()> {
        let mem_after = memdiag::sample_full();
        self.logger.runtime(
            "info",
            format!(
                "refresh metrics trigger={} outcome={} key={} zone_before={} zone_after={} elapsed_ms={} rss_before_kb={} cg_before_kb={} gap_before_kb={} cg_anon_before_kb={} cg_file_before_kb={} cg_shmem_before_kb={} cg_file_mapped_before_kb={} cg_active_file_before_kb={} cg_inactive_file_before_kb={} rss_after_kb={} cg_after_kb={} gap_after_kb={} cg_anon_after_kb={} cg_file_after_kb={} cg_shmem_after_kb={} cg_file_mapped_after_kb={} cg_active_file_after_kb={} cg_inactive_file_after_kb={} pgfault_delta={} pgmajfault_delta={} workingset_refault_file_delta={} workingset_activate_file_delta={}",
                trigger.as_str(),
                outcome,
                key,
                zone_before,
                zone_after,
                mem_context.started_at.elapsed().as_millis(),
                mem_context.before.fmt_rss(),
                mem_context.before.fmt_cg(),
                mem_context.before.fmt_gap(),
                mem_context.before.fmt_anon(),
                mem_context.before.fmt_file(),
                mem_context.before.fmt_shmem(),
                mem_context.before.fmt_file_mapped(),
                mem_context.before.fmt_active_file(),
                mem_context.before.fmt_inactive_file(),
                mem_after.fmt_rss(),
                mem_after.fmt_cg(),
                mem_after.fmt_gap(),
                mem_after.fmt_anon(),
                mem_after.fmt_file(),
                mem_after.fmt_shmem(),
                mem_after.fmt_file_mapped(),
                mem_after.fmt_active_file(),
                mem_after.fmt_inactive_file(),
                memdiag::format_counter_delta(memdiag::counter_delta(
                    mem_context.before.cg_pgfault,
                    mem_after.cg_pgfault,
                )),
                memdiag::format_counter_delta(memdiag::counter_delta(
                    mem_context.before.cg_pgmajfault,
                    mem_after.cg_pgmajfault,
                )),
                memdiag::format_counter_delta(memdiag::counter_delta(
                    mem_context.before.cg_workingset_refault_file,
                    mem_after.cg_workingset_refault_file,
                )),
                memdiag::format_counter_delta(memdiag::counter_delta(
                    mem_context.before.cg_workingset_activate_file,
                    mem_after.cg_workingset_activate_file,
                )),
            ),
        )
    }
}

fn should_fallback_to_next_proxy(error: &RefreshFailure) -> bool {
    error.proxy_host.is_some()
        && matches!(
            error.code.as_str(),
            "network_connect_failed" | "network_timeout" | "socks_proxy_error"
        )
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProxyAttempt {
    Primary(String),
    Backup(String),
    Direct,
}

fn build_proxy_attempt_sequence(
    mode: &str,
    primary_proxies: &[String],
    backup_proxies: &[String],
    primary_start_index: Option<usize>,
) -> Result<Vec<ProxyAttempt>> {
    let mut attempts = Vec::new();
    // Each configured proxy tries remote DNS first, then local DNS for proxies without SOCKS5H support.
    match mode {
        "fixed" => {
            if let Some(proxy) = primary_proxies.first() {
                push_proxy_attempt_pair(&mut attempts, proxy, ProxyAttempt::Primary)?;
            }
        }
        "round_robin" => {
            if !primary_proxies.is_empty() {
                let start_index =
                    primary_start_index.expect("invariant: round_robin primary index is reserved");
                for offset in 0..primary_proxies.len() {
                    let proxy = &primary_proxies[(start_index + offset) % primary_proxies.len()];
                    push_proxy_attempt_pair(&mut attempts, proxy, ProxyAttempt::Primary)?;
                }
            }
        }
        other => anyhow::bail!("unsupported proxy mode: {other}"),
    }
    for proxy in backup_proxies {
        push_proxy_attempt_pair(&mut attempts, proxy, ProxyAttempt::Backup)?;
    }
    attempts.push(ProxyAttempt::Direct);
    Ok(attempts)
}

fn push_proxy_attempt_pair(
    attempts: &mut Vec<ProxyAttempt>,
    proxy: &str,
    wrap: fn(String) -> ProxyAttempt,
) -> Result<()> {
    let remote_proxy = crate::proxy::to_remote_dns_proxy(proxy)?;
    attempts.push(wrap(remote_proxy.clone()));
    let local_proxy = crate::proxy::to_local_dns_proxy(&remote_proxy)?;
    if local_proxy != remote_proxy {
        attempts.push(wrap(local_proxy));
    }
    Ok(())
}

fn log_proxy_fallback_transition(
    logger: &LogManager,
    key: &str,
    current: &ProxyAttempt,
    next: &ProxyAttempt,
    proxy_host: Option<&str>,
) -> Result<()> {
    let failed_proxy = proxy_host.unwrap_or("-");
    let next_proxy = proxy_attempt_route_label(next);
    let message = if is_remote_to_local_dns_fallback(current, next) {
        format!(
            "SOCKS5H 代理请求失败，准备使用同一代理的 SOCKS5 模式 (key={}, failed_proxy={}, next_proxy={})",
            key, failed_proxy, next_proxy
        )
    } else {
        match (current, next) {
            (ProxyAttempt::Primary(_), ProxyAttempt::Primary(_)) => {
                format!(
                    "主代理请求失败，准备切换下一条主代理 (key={}, failed_proxy={}, next_proxy={})",
                    key, failed_proxy, next_proxy
                )
            }
            (ProxyAttempt::Primary(_), ProxyAttempt::Backup(_)) => {
                format!(
                    "主代理请求失败，准备切换到备用代理 (key={}, failed_proxy={}, next_proxy={})",
                    key, failed_proxy, next_proxy
                )
            }
            (ProxyAttempt::Primary(_), ProxyAttempt::Direct) => {
                format!(
                    "主代理请求失败，准备回退到直连 (key={}, failed_proxy={}, next=direct)",
                    key, failed_proxy
                )
            }
            (ProxyAttempt::Backup(_), ProxyAttempt::Backup(_)) => {
                format!(
                    "备用代理请求失败，准备切换下一条备用代理 (key={}, failed_proxy={}, next_proxy={})",
                    key, failed_proxy, next_proxy
                )
            }
            (ProxyAttempt::Backup(_), ProxyAttempt::Direct) => {
                format!(
                    "备用代理请求失败，准备回退到直连 (key={}, failed_proxy={}, next=direct)",
                    key, failed_proxy
                )
            }
            (ProxyAttempt::Direct, _) | (ProxyAttempt::Backup(_), ProxyAttempt::Primary(_)) => {
                anyhow::bail!(
                    "unexpected proxy fallback transition: {:?} -> {:?}",
                    current,
                    next
                )
            }
        }
    };
    runtime_warn_best_effort(logger, message);
    Ok(())
}

fn is_remote_to_local_dns_fallback(current: &ProxyAttempt, next: &ProxyAttempt) -> bool {
    let Some(current_proxy) = proxy_attempt_proxy(current) else {
        return false;
    };
    let Some(next_proxy) = proxy_attempt_proxy(next) else {
        return false;
    };
    let Ok(current_url) = reqwest::Url::parse(current_proxy) else {
        return false;
    };
    let Ok(next_url) = reqwest::Url::parse(next_proxy) else {
        return false;
    };

    current_url.scheme() == "socks5h"
        && next_url.scheme() == "socks5"
        && current_url.host_str() == next_url.host_str()
        && current_url.port() == next_url.port()
        && current_url.username() == next_url.username()
        && current_url.password() == next_url.password()
}

fn proxy_attempt_proxy(attempt: &ProxyAttempt) -> Option<&str> {
    match attempt {
        ProxyAttempt::Primary(proxy) | ProxyAttempt::Backup(proxy) => Some(proxy),
        ProxyAttempt::Direct => None,
    }
}

fn proxy_attempt_route_label(attempt: &ProxyAttempt) -> String {
    match attempt {
        ProxyAttempt::Primary(proxy) | ProxyAttempt::Backup(proxy) => reqwest::Url::parse(proxy)
            .ok()
            .and_then(|url| Some(format!("{}:{}", url.host_str()?, url.port()?)))
            .unwrap_or_else(|| proxy.clone()),
        ProxyAttempt::Direct => "direct".to_string(),
    }
}

fn runtime_warn_best_effort(logger: &LogManager, message: impl AsRef<str>) {
    let _ = logger.runtime("warn", message);
}

fn proxy_attempt_label(proxy_label: Option<&str>) -> &str {
    proxy_label.unwrap_or("not_attempted")
}

fn merge_refresh_response(
    credential: &mut CodexCredentialFile,
    payload: RefreshResponsePayload,
) -> Result<()> {
    if let Some(access_token) = payload
        .access_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        credential.access_token = access_token.clone();
        if let Ok(expiration) = jwt::decode_expiration(&access_token) {
            credential.set_expired_at(expiration);
        }
    }
    if let Some(refresh_token) = payload
        .refresh_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        credential.refresh_token = refresh_token;
    }
    if let Some(id_token) = payload
        .id_token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        credential.id_token = id_token.clone();
        let _ = credential.apply_id_token_metadata(&id_token);
    }
    if let Some(expires_in) = payload.expires_in.filter(|value| *value > 0) {
        let expires_at = Utc::now() + ChronoDuration::seconds(expires_in);
        credential.set_expired_at(expires_at);
    } else if credential.expired.is_none() && !credential.access_token.is_empty() {
        if let Ok(expiration) = jwt::decode_expiration(&credential.access_token) {
            credential.set_expired_at(expiration);
        }
    }
    Ok(())
}

pub fn due_at(
    config: &AppConfig,
    credential: &CodexCredentialFile,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>> {
    let refresh_interval = parse_duration_str(&config.refresh.interval)?;
    let lead_time = parse_duration_str(&config.refresh.lead_time)?;
    Ok(credential.due_at(lead_time, refresh_interval, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use base64::Engine;
    use serde_json::json;

    fn fake_jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!("{header}.{payload}.sig")
    }

    fn test_config_with_temp_dirs(root: &std::path::Path) -> AppConfig {
        let mut config = AppConfig::default();
        config.credentials_dir = root.join("credentials");
        config.abnormal_credentials_dir = root.join("credentials_abnormal");
        config.state_dir = root.join("state");
        config
    }

    fn test_transaction(root: &std::path::Path) -> RefreshTransaction {
        let config = test_config_with_temp_dirs(root);
        let logger = Arc::new(LogManager::new(root, 1024, "info").unwrap());
        let store = Arc::new(CredentialStore::new(&config, Some(logger.clone())).unwrap());
        let status_store =
            Arc::new(CredentialStatusStore::load(config.state_dir.join("status.json")).unwrap());
        let write_coordinator = Arc::new(WriteCoordinator::new());
        RefreshTransaction::new(store, status_store, logger, write_coordinator)
    }

    #[test]
    fn merge_keeps_old_id_token_when_response_omits_it() {
        let mut credential = CodexCredentialFile {
            id_token: "old-id".to_string(),
            access_token: fake_jwt(json!({ "exp": Utc::now().timestamp() + 3600 })),
            refresh_token: "old-refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        merge_refresh_response(
            &mut credential,
            RefreshResponsePayload {
                access_token: Some(fake_jwt(json!({ "exp": Utc::now().timestamp() + 7200 }))),
                refresh_token: Some("new-refresh".to_string()),
                id_token: None,
                expires_in: None,
                ..RefreshResponsePayload::default()
            },
        )
        .unwrap();
        assert_eq!(credential.id_token, "old-id");
        assert_eq!(credential.refresh_token, "new-refresh");
    }

    #[test]
    fn merge_updates_email_and_account_from_new_id_token() {
        let mut credential = CodexCredentialFile {
            id_token: "old-id".to_string(),
            access_token: fake_jwt(json!({ "exp": Utc::now().timestamp() + 3600 })),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        let new_id = fake_jwt(json!({
            "email": "new@example.com",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acc-123",
                "chatgpt_plan_type": "plus",
                "user_id": "user-1"
            }
        }));
        merge_refresh_response(
            &mut credential,
            RefreshResponsePayload {
                id_token: Some(new_id.clone()),
                access_token: Some(fake_jwt(json!({ "exp": Utc::now().timestamp() + 7200 }))),
                ..RefreshResponsePayload::default()
            },
        )
        .unwrap();
        assert_eq!(credential.id_token, new_id);
        assert_eq!(credential.email.as_deref(), Some("new@example.com"));
        assert_eq!(credential.account_id.as_deref(), Some("acc-123"));
    }

    #[test]
    fn due_at_uses_refresh_interval_when_earlier_than_expiry_window() {
        let now = Utc::now();
        let mut config = AppConfig::default();
        config.refresh.interval = "6h".to_string();
        config.refresh.lead_time = "24h".to_string();
        let credential = CodexCredentialFile {
            access_token: fake_jwt(json!({ "exp": (now + ChronoDuration::hours(72)).timestamp() })),
            last_refresh: Some((now - ChronoDuration::hours(7)).to_rfc3339()),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };

        let due = due_at(&config, &credential, now).unwrap().unwrap();

        assert!(due <= now);
    }

    #[test]
    fn due_at_defaults_to_immediate_refresh_when_last_refresh_missing() {
        let now = Utc::now();
        let mut config = AppConfig::default();
        config.refresh.interval = "6h".to_string();
        config.refresh.lead_time = "24h".to_string();
        let credential = CodexCredentialFile {
            access_token: fake_jwt(
                json!({ "exp": (now + ChronoDuration::hours(240)).timestamp() }),
            ),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };

        let due = due_at(&config, &credential, now).unwrap().unwrap();

        assert!(due <= now);
    }

    #[test]
    fn runtime_warn_best_effort_ignores_logging_failures() {
        let temp = tempfile::tempdir().unwrap();
        let logger = LogManager::new(temp.path(), 1024, "info").unwrap();
        let runtime_log = temp.path().join("logs/runtime.log");
        std::fs::remove_file(&runtime_log).unwrap();
        std::fs::create_dir(&runtime_log).unwrap();

        runtime_warn_best_effort(&logger, "proxy fallback warning");
    }

    #[test]
    fn proxy_attempt_label_defaults_to_not_attempted() {
        assert_eq!(proxy_attempt_label(None), "not_attempted");
        assert_eq!(proxy_attempt_label(Some("direct")), "direct");
        assert_eq!(
            proxy_attempt_label(Some("127.0.0.1:10808")),
            "127.0.0.1:10808"
        );
    }

    #[test]
    fn build_proxy_attempt_sequence_uses_backup_after_fixed_proxy() {
        let attempts = build_proxy_attempt_sequence(
            "fixed",
            &[
                "socks5://127.0.0.1:10808".to_string(),
                "socks5://127.0.0.1:10809".to_string(),
            ],
            &[
                "socks5://127.0.0.1:10818".to_string(),
                "socks5://127.0.0.1:10819".to_string(),
            ],
            None,
        )
        .unwrap();

        assert_eq!(
            attempts,
            vec![
                ProxyAttempt::Primary("socks5h://127.0.0.1:10808".to_string()),
                ProxyAttempt::Primary("socks5://127.0.0.1:10808".to_string()),
                ProxyAttempt::Backup("socks5h://127.0.0.1:10818".to_string()),
                ProxyAttempt::Backup("socks5://127.0.0.1:10818".to_string()),
                ProxyAttempt::Backup("socks5h://127.0.0.1:10819".to_string()),
                ProxyAttempt::Backup("socks5://127.0.0.1:10819".to_string()),
                ProxyAttempt::Direct,
            ]
        );
    }

    #[test]
    fn build_proxy_attempt_sequence_round_robin_keeps_backup_after_primary_cycle() {
        let attempts = build_proxy_attempt_sequence(
            "round_robin",
            &[
                "socks5://127.0.0.1:10808".to_string(),
                "socks5://127.0.0.1:10809".to_string(),
                "socks5://127.0.0.1:10810".to_string(),
            ],
            &["socks5://127.0.0.1:10818".to_string()],
            Some(1),
        )
        .unwrap();

        assert_eq!(
            attempts,
            vec![
                ProxyAttempt::Primary("socks5h://127.0.0.1:10809".to_string()),
                ProxyAttempt::Primary("socks5://127.0.0.1:10809".to_string()),
                ProxyAttempt::Primary("socks5h://127.0.0.1:10810".to_string()),
                ProxyAttempt::Primary("socks5://127.0.0.1:10810".to_string()),
                ProxyAttempt::Primary("socks5h://127.0.0.1:10808".to_string()),
                ProxyAttempt::Primary("socks5://127.0.0.1:10808".to_string()),
                ProxyAttempt::Backup("socks5h://127.0.0.1:10818".to_string()),
                ProxyAttempt::Backup("socks5://127.0.0.1:10818".to_string()),
                ProxyAttempt::Direct,
            ]
        );
    }

    #[test]
    fn build_proxy_attempt_sequence_uses_backup_when_primary_is_empty() {
        let attempts = build_proxy_attempt_sequence(
            "fixed",
            &[],
            &[
                "socks5://127.0.0.1:10818".to_string(),
                "socks5://127.0.0.1:10819".to_string(),
            ],
            None,
        )
        .unwrap();

        assert_eq!(
            attempts,
            vec![
                ProxyAttempt::Backup("socks5h://127.0.0.1:10818".to_string()),
                ProxyAttempt::Backup("socks5://127.0.0.1:10818".to_string()),
                ProxyAttempt::Backup("socks5h://127.0.0.1:10819".to_string()),
                ProxyAttempt::Backup("socks5://127.0.0.1:10819".to_string()),
                ProxyAttempt::Direct,
            ]
        );
    }

    #[test]
    fn build_proxy_attempt_sequence_rejects_unknown_mode() {
        let error = build_proxy_attempt_sequence("random", &[], &[], None).unwrap_err();

        assert!(error.to_string().contains("unsupported proxy mode"));
    }

    #[test]
    fn should_fallback_to_next_proxy_when_proxy_times_out() {
        let error = RefreshFailure::transient("network_timeout", "timeout")
            .with_proxy_host(Some("127.0.0.1:10808".to_string()));

        assert!(should_fallback_to_next_proxy(&error));
    }

    #[test]
    fn should_not_fallback_to_next_proxy_when_direct_times_out() {
        let error = RefreshFailure::transient("network_timeout", "timeout").with_proxy_host(None);

        assert!(!should_fallback_to_next_proxy(&error));
    }

    #[test]
    fn should_fallback_to_next_proxy_when_proxy_returns_socks_error() {
        let error = RefreshFailure::transient("socks_proxy_error", "socks protocol error")
            .with_proxy_host(Some("127.0.0.1:10808".to_string()));

        assert!(should_fallback_to_next_proxy(&error));
    }

    #[test]
    fn should_not_fallback_to_next_proxy_when_proxy_returns_generic_network_error() {
        let error = RefreshFailure::transient("network_error", "tls handshake failed")
            .with_proxy_host(Some("127.0.0.1:10808".to_string()));

        assert!(!should_fallback_to_next_proxy(&error));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refresh_with_proxy_fallback_rejects_unknown_mode() {
        let temp = tempfile::tempdir().unwrap();
        let transaction = test_transaction(temp.path());
        let mut config = test_config_with_temp_dirs(temp.path());
        config.proxy.mode = "random".to_string();
        config.proxy.list = "socks5://127.0.0.1:10808".to_string();

        let result = transaction
            .refresh_with_proxy_fallback(&config, "refresh-token", "user-agent", "demo.json")
            .await
            .unwrap();
        let error = result.unwrap_err();

        assert_eq!(error.code, "invalid_proxy_mode");
        assert!(error.reason.contains("unsupported proxy mode"));
    }

    #[test]
    fn log_proxy_fallback_transition_rejects_impossible_transition() {
        let temp = tempfile::tempdir().unwrap();
        let logger = LogManager::new(temp.path(), 1024, "info").unwrap();

        let error = log_proxy_fallback_transition(
            &logger,
            "demo.json",
            &ProxyAttempt::Backup("socks5://127.0.0.1:10818".to_string()),
            &ProxyAttempt::Primary("socks5://127.0.0.1:10808".to_string()),
            Some("127.0.0.1:10818"),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unexpected proxy fallback transition")
        );
    }

    #[test]
    fn log_proxy_fallback_transition_logs_failed_and_next_proxy() {
        let temp = tempfile::tempdir().unwrap();
        let logger = LogManager::new(temp.path(), 4096, "info").unwrap();

        log_proxy_fallback_transition(
            &logger,
            "demo.json",
            &ProxyAttempt::Primary("socks5://127.0.0.1:10808".to_string()),
            &ProxyAttempt::Backup("socks5://127.0.0.1:10818".to_string()),
            Some("127.0.0.1:10808"),
        )
        .unwrap();

        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        assert!(content.contains("主代理请求失败，准备切换到备用代理"));
        assert!(content.contains("failed_proxy=127.0.0.1:10808"));
        assert!(content.contains("next_proxy=127.0.0.1:10818"));
    }

    #[test]
    fn log_proxy_fallback_transition_logs_socks5h_to_socks5() {
        let temp = tempfile::tempdir().unwrap();
        let logger = LogManager::new(temp.path(), 4096, "info").unwrap();

        log_proxy_fallback_transition(
            &logger,
            "demo.json",
            &ProxyAttempt::Primary("socks5h://127.0.0.1:10808".to_string()),
            &ProxyAttempt::Primary("socks5://127.0.0.1:10808".to_string()),
            Some("127.0.0.1:10808"),
        )
        .unwrap();

        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        assert!(content.contains("SOCKS5H 代理请求失败，准备使用同一代理的 SOCKS5 模式"));
        assert!(content.contains("failed_proxy=127.0.0.1:10808"));
        assert!(content.contains("next_proxy=127.0.0.1:10808"));
    }
}
