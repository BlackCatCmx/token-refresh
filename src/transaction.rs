use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::config::{AppConfig, parse_duration_str};
use crate::credential::CodexCredentialFile;
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::jwt;
use crate::logging::LogManager;
use crate::recovery;
use crate::refresh_client::{RefreshClient, RefreshFailure, RefreshResponsePayload};
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
        let generation = self.write_coordinator.generation();
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

        self.logger.runtime(
            "info",
            format!(
                "refresh starting for {} in {} via {} (expires_at={}, last_refresh={}, proxy_mode={}, timeout={})",
                key,
                zone.as_str(),
                trigger.as_str(),
                credential.expired.as_deref().unwrap_or("-"),
                credential.last_refresh.as_deref().unwrap_or("-"),
                config.proxy.mode.trim(),
                config.network.timeout.trim()
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

        match self
            .client
            .refresh(config, credential.refresh_token.trim(), &request_user_agent)
            .await
        {
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
        }
    }

    async fn handle_success(
        &self,
        _config: &AppConfig,
        zone: CredentialZone,
        key: &str,
        trigger: RefreshTrigger,
        generation: u64,
        credential: &mut CodexCredentialFile,
        payload: RefreshResponsePayload,
    ) -> Result<RefreshOutcome> {
        let previous_refresh_token = credential.refresh_token.clone();
        merge_refresh_response(credential, payload)?;
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
                "refresh succeeded for {} in {} via {} (expires_at={}, refresh_token_rotated={})",
                key,
                zone.as_str(),
                trigger.as_str(),
                credential.expired.as_deref().unwrap_or("-"),
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
                "refresh failed for {} in {} via {} (code={}, failure_count={}, count_towards_abnormal={}, moved_to_abnormal={}, final_zone={}): {}",
                key,
                zone.as_str(),
                trigger.as_str(),
                error.code,
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
    use base64::Engine;
    use serde_json::json;

    fn fake_jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!("{header}.{payload}.sig")
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
}
