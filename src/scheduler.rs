use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::Rng;
use tokio::sync::{Notify, RwLock};

use crate::config::{ConfigManager, parse_duration_str};
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::logging::LogManager;
use crate::transaction::{RefreshOutcome, RefreshTransaction, due_at};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SchedulerStatus {
    pub enabled: bool,
    pub current_key: Option<String>,
    pub last_cycle_at: Option<String>,
    pub next_wake_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct SchedulerHandle {
    enabled: Arc<AtomicBool>,
    notify: Arc<Notify>,
    status: Arc<RwLock<SchedulerStatus>>,
    backoff_until: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

struct SchedulerRuntime {
    config_manager: ConfigManager,
    store: Arc<CredentialStore>,
    transaction: Arc<RefreshTransaction>,
    logger: Arc<LogManager>,
    enabled: Arc<AtomicBool>,
    notify: Arc<Notify>,
    status: Arc<RwLock<SchedulerStatus>>,
    backoff_until: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl SchedulerHandle {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
            notify: Arc::new(Notify::new()),
            status: Arc::new(RwLock::new(SchedulerStatus {
                enabled: true,
                ..SchedulerStatus::default()
            })),
            backoff_until: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn spawn_background(
        &self,
        config_manager: ConfigManager,
        store: Arc<CredentialStore>,
        transaction: Arc<RefreshTransaction>,
        logger: Arc<LogManager>,
    ) {
        let runtime = SchedulerRuntime {
            config_manager,
            store,
            transaction,
            logger,
            enabled: self.enabled.clone(),
            notify: self.notify.clone(),
            status: self.status.clone(),
            backoff_until: self.backoff_until.clone(),
        };
        tokio::spawn(async move {
            runtime.run().await;
        });
    }

    pub async fn start(&self) {
        self.enabled.store(true, Ordering::SeqCst);
        {
            let mut status = self.status.write().await;
            status.enabled = true;
            status.last_error = None;
        }
        self.notify.notify_waiters();
    }

    pub async fn stop(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        {
            let mut status = self.status.write().await;
            status.enabled = false;
            status.current_key = None;
        }
        self.notify.notify_waiters();
    }

    pub async fn status(&self) -> SchedulerStatus {
        self.status.read().await.clone()
    }

    pub fn wake(&self) {
        self.notify.notify_waiters();
    }
}

impl SchedulerRuntime {
    async fn run(self) {
        loop {
            if !self.enabled.load(Ordering::SeqCst) {
                {
                    let mut status = self.status.write().await;
                    status.enabled = false;
                    status.current_key = None;
                    status.next_wake_at = None;
                }
                self.notify.notified().await;
                continue;
            }
            if let Err(err) = self.run_cycle().await {
                let _ = self
                    .logger
                    .runtime("error", format!("scheduler cycle failed: {err:#}"));
                let mut status = self.status.write().await;
                status.last_error = Some(err.to_string());
                status.last_cycle_at = Some(Utc::now().to_rfc3339());
            }
        }
    }

    async fn run_cycle(&self) -> Result<()> {
        let config = self.config_manager.effective_config().await;
        let now = Utc::now();
        let entries = self.store.scan_zone(CredentialZone::Normal)?;
        let mut due_entries = Vec::new();
        let mut next_wake_at: Option<DateTime<Utc>> = None;
        let backoff_map = self.backoff_until.read().await.clone();
        for entry in entries {
            let key = entry.key.clone();
            let due = if let Some(credential) = entry.credential.as_ref() {
                due_at(&config, credential)?.unwrap_or(now)
            } else {
                now
            };
            let scheduled_time = if let Some(backoff) = backoff_map.get(&key) {
                (*backoff).max(due)
            } else {
                due
            };
            if scheduled_time <= now {
                due_entries.push(key);
            } else {
                next_wake_at = Some(match next_wake_at {
                    Some(existing) => existing.min(scheduled_time),
                    None => scheduled_time,
                });
            }
        }
        due_entries.sort();
        {
            let mut status = self.status.write().await;
            status.enabled = true;
            status.last_cycle_at = Some(now.to_rfc3339());
            status.next_wake_at = next_wake_at.map(|value| value.to_rfc3339());
        }
        if due_entries.is_empty() {
            let sleep_duration = compute_idle_sleep(&config, now, next_wake_at)?;
            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {}
                _ = self.notify.notified() => {}
            }
            return Ok(());
        }

        let _ = self.logger.runtime(
            "info",
            format!(
                "scheduler picked {} due credential(s); next_wake_at={}",
                due_entries.len(),
                next_wake_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "none".to_string())
            ),
        );

        for key in due_entries {
            if !self.enabled.load(Ordering::SeqCst) {
                break;
            }
            {
                let mut status = self.status.write().await;
                status.current_key = Some(key.clone());
                status.last_error = None;
            }
            let outcome = self
                .transaction
                .refresh_one(
                    &config,
                    CredentialZone::Normal,
                    &key,
                    crate::transaction::RefreshTrigger::Scheduler,
                )
                .await?;
            self.update_backoff(&config, &outcome).await?;
            {
                let mut status = self.status.write().await;
                status.current_key = None;
            }
            if !self.enabled.load(Ordering::SeqCst) {
                break;
            }
            let delay = random_delay(
                parse_duration_str(&config.refresh.inter_refresh_delay_min)?,
                parse_duration_str(&config.refresh.inter_refresh_delay_max)?,
            );
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.notify.notified() => {}
            }
        }
        Ok(())
    }

    async fn update_backoff(
        &self,
        config: &crate::config::AppConfig,
        outcome: &RefreshOutcome,
    ) -> Result<()> {
        let mut backoff = self.backoff_until.write().await;
        if outcome.success || outcome.zone == CredentialZone::Abnormal {
            backoff.remove(&outcome.key);
            return Ok(());
        }
        let failure_backoff = parse_duration_str(&config.refresh.failure_backoff)?;
        let until = Utc::now()
            + chrono::Duration::from_std(failure_backoff)
                .map_err(|err| anyhow::anyhow!("invalid failure_backoff duration: {err}"))?;
        backoff.insert(outcome.key.clone(), until);
        let _ = self.logger.runtime(
            "info",
            format!(
                "scheduler backoff set for {} until {} (failure_code={})",
                outcome.key,
                until.to_rfc3339(),
                outcome.failure_code.as_deref().unwrap_or("unknown")
            ),
        );
        Ok(())
    }
}

fn compute_idle_sleep(
    config: &crate::config::AppConfig,
    now: DateTime<Utc>,
    next_wake_at: Option<DateTime<Utc>>,
) -> Result<Duration> {
    let max_sleep = parse_duration_str(&config.refresh.max_sleep)?;
    let min_sleep = parse_duration_str(&config.refresh.min_sleep)?;
    let until_next = next_wake_at
        .map(|value| {
            (value - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1))
        })
        .unwrap_or(max_sleep);
    if until_next <= Duration::from_secs(1) {
        return Ok(Duration::from_secs(1));
    }
    if until_next <= min_sleep {
        return Ok(until_next);
    }
    Ok(until_next.min(max_sleep))
}

fn random_delay(min: Duration, max: Duration) -> Duration {
    if max <= min {
        return min;
    }
    let min_ms = min.as_millis() as u64;
    let max_ms = max.as_millis() as u64;
    let value = rand::rng().random_range(min_ms..=max_ms);
    Duration::from_millis(value)
}
