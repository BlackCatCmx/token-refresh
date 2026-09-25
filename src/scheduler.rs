use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

use crate::backup::BackupCoordinator;
use crate::config::{ConfigManager, parse_duration_str};
use crate::credential::parse_rfc3339;
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::fsutil;
use crate::logging::LogManager;
use crate::status::{CredentialStatusRecord, CredentialStatusStore};
use crate::transaction::{RefreshOutcome, RefreshTransaction, due_at};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SchedulerStatus {
    pub enabled: bool,
    pub current_key: Option<String>,
    pub next_key: Option<String>,
    pub last_cycle_at: Option<String>,
    pub next_wake_at: Option<String>,
    pub next_due_at: Option<String>,
    pub wait_reason: Option<String>,
    pub last_error: Option<String>,
    pub manual_pending: bool,
    pub manual_running: bool,
    pub manual_current_key: Option<String>,
    pub manual_total_count: usize,
    pub manual_processed_count: usize,
    pub manual_success_count: usize,
    pub manual_failed_count: usize,
    pub manual_last_started_at: Option<String>,
    pub manual_last_finished_at: Option<String>,
    pub manual_last_item_error_key: Option<String>,
    pub manual_last_item_error: Option<String>,
    pub manual_last_run_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SchedulerPersistedState {
    #[serde(default = "default_scheduler_enabled")]
    enabled: bool,
}

impl Default for SchedulerPersistedState {
    fn default() -> Self {
        Self {
            enabled: default_scheduler_enabled(),
        }
    }
}

#[derive(Debug)]
struct SchedulerStateStore {
    path: PathBuf,
    state: Mutex<SchedulerPersistedState>,
}

impl SchedulerStateStore {
    fn load(path: PathBuf) -> Result<Self> {
        let state = match fsutil::read_file_if_exists(&path)? {
            Some(raw) if raw.is_empty() => SchedulerPersistedState::default(),
            Some(raw) => serde_json::from_slice::<SchedulerPersistedState>(&raw)
                .with_context(|| format!("invalid scheduler state file {}", path.display()))?,
            None => SchedulerPersistedState::default(),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn enabled(&self) -> Result<bool> {
        let guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("scheduler state lock poisoned"))?;
        Ok(guard.enabled)
    }

    fn set_enabled(&self, enabled: bool) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("scheduler state lock poisoned"))?;
        guard.enabled = enabled;
        fsutil::atomic_write_json(&self.path, &*guard)
    }
}

fn default_scheduler_enabled() -> bool {
    true
}

#[derive(Clone)]
pub struct SchedulerHandle {
    enabled: Arc<AtomicBool>,
    manual_busy: Arc<AtomicBool>,
    manual_requested: Arc<AtomicBool>,
    notify: Arc<Notify>,
    status: Arc<RwLock<SchedulerStatus>>,
    backoff_until: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    state_store: Arc<SchedulerStateStore>,
}

#[derive(Clone)]
struct SchedulerRuntime {
    config_manager: ConfigManager,
    store: Arc<CredentialStore>,
    status_store: Arc<CredentialStatusStore>,
    transaction: Arc<RefreshTransaction>,
    backup: Option<Arc<BackupCoordinator>>,
    logger: Arc<LogManager>,
    enabled: Arc<AtomicBool>,
    manual_busy: Arc<AtomicBool>,
    manual_requested: Arc<AtomicBool>,
    notify: Arc<Notify>,
    status: Arc<RwLock<SchedulerStatus>>,
    backoff_until: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl SchedulerHandle {
    pub fn load(state_path: PathBuf) -> Result<Self> {
        let state_store = Arc::new(SchedulerStateStore::load(state_path)?);
        let enabled = state_store.enabled()?;
        Ok(Self {
            enabled: Arc::new(AtomicBool::new(enabled)),
            manual_busy: Arc::new(AtomicBool::new(false)),
            manual_requested: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            status: Arc::new(RwLock::new(SchedulerStatus {
                enabled,
                ..SchedulerStatus::default()
            })),
            backoff_until: Arc::new(RwLock::new(HashMap::new())),
            state_store,
        })
    }

    pub fn spawn_background(
        &self,
        config_manager: ConfigManager,
        store: Arc<CredentialStore>,
        status_store: Arc<CredentialStatusStore>,
        transaction: Arc<RefreshTransaction>,
        backup: Option<Arc<BackupCoordinator>>,
        logger: Arc<LogManager>,
    ) {
        let runtime = SchedulerRuntime {
            config_manager,
            store,
            status_store,
            transaction,
            backup,
            logger,
            enabled: self.enabled.clone(),
            manual_busy: self.manual_busy.clone(),
            manual_requested: self.manual_requested.clone(),
            notify: self.notify.clone(),
            status: self.status.clone(),
            backoff_until: self.backoff_until.clone(),
        };
        tokio::spawn(async move {
            loop {
                let worker = runtime.clone();
                match tokio::spawn(async move { worker.run().await }).await {
                    Ok(()) => break,
                    Err(err) if err.is_cancelled() => break,
                    Err(err) => {
                        let message = err.to_string();
                        let _ = runtime.logger.runtime(
                            "error",
                            format!(
                                "scheduler background task panicked and will restart: {message}"
                            ),
                        );
                        runtime.recover_after_worker_panic(&message).await;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    pub async fn start(&self) -> Result<()> {
        self.state_store.set_enabled(true)?;
        self.set_runtime_enabled(true, true).await;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.state_store.set_enabled(false)?;
        self.set_runtime_enabled(false, false).await;
        Ok(())
    }

    pub async fn status(&self) -> SchedulerStatus {
        self.status.read().await.clone()
    }

    pub async fn trigger_manual_refresh_all(&self) -> Result<()> {
        if self
            .manual_busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            bail!("手动全量刷新正在执行中");
        }
        self.manual_requested.store(true, Ordering::SeqCst);
        {
            let mut status = self.status.write().await;
            status.manual_pending = true;
            status.manual_last_item_error_key = None;
            status.manual_last_item_error = None;
            status.manual_last_run_error = None;
        }
        self.notify.notify_waiters();
        Ok(())
    }

    pub fn wake(&self) {
        self.notify.notify_one();
    }

    pub async fn clear_backoff(&self) {
        let mut guard = self.backoff_until.write().await;
        guard.clear();
    }

    pub fn persisted_enabled(&self) -> Result<bool> {
        self.state_store.enabled()
    }

    pub async fn pause(&self) {
        self.set_runtime_enabled(false, false).await;
    }

    pub async fn resume(&self) {
        self.set_runtime_enabled(true, false).await;
    }

    async fn set_runtime_enabled(&self, enabled: bool, clear_last_error: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        {
            let mut status = self.status.write().await;
            status.enabled = enabled;
            if !enabled {
                status.current_key = None;
                status.next_key = None;
                status.next_wake_at = None;
                status.next_due_at = None;
                status.wait_reason = None;
            }
            if clear_last_error {
                status.last_error = None;
            }
        }
        self.notify.notify_waiters();
    }
}

impl SchedulerRuntime {
    async fn run(self) {
        loop {
            if self.manual_requested.swap(false, Ordering::SeqCst) {
                let manual_result = self.run_manual_refresh_all().await;
                self.manual_busy.store(false, Ordering::SeqCst);
                if let Err(err) = manual_result {
                    let _ = self
                        .logger
                        .runtime("error", format!("manual full refresh failed: {err:#}"));
                    let mut status = self.status.write().await;
                    status.manual_pending = false;
                    status.manual_running = false;
                    status.manual_current_key = None;
                    status.manual_last_run_error = Some(err.to_string());
                    status.manual_last_finished_at = Some(Utc::now().to_rfc3339());
                }
                continue;
            }
            if !self.enabled.load(Ordering::SeqCst) {
                {
                    let mut status = self.status.write().await;
                    status.enabled = false;
                    status.current_key = None;
                    status.next_key = None;
                    status.next_wake_at = None;
                    status.next_due_at = None;
                    status.wait_reason = None;
                }
                self.notify.notified().await;
                continue;
            }
            if let Err(err) = self.run_cycle().await {
                let _ = self
                    .logger
                    .runtime("error", format!("scheduler cycle failed: {err:#}"));
                let mut status = self.status.write().await;
                status.current_key = None;
                status.last_error = Some(err.to_string());
                status.last_cycle_at = Some(Utc::now().to_rfc3339());
            }
        }
    }

    async fn run_cycle(&self) -> Result<()> {
        let config = self.config_manager.effective_config().await;
        // A still-due credential must not monopolize the batch after a refresh.
        let mut processed_keys = HashSet::new();
        loop {
            let now = Utc::now();
            let plan = self.collect_schedule_plan(&config, now).await?;
            let next_key = plan.next_key_excluding(&processed_keys);
            {
                let mut status = self.status.write().await;
                status.enabled = true;
                status.last_cycle_at = Some(now.to_rfc3339());
                status.next_key = next_key;
                status.next_wake_at = None;
                status.next_due_at = plan.next_due_at_rfc3339();
                status.wait_reason = None;
            }
            let Some((index, due_entry)) = plan
                .due_keys
                .iter()
                .enumerate()
                .find(|(_, entry)| !processed_keys.contains(&entry.key))
            else {
                if !processed_keys.is_empty() {
                    return Ok(());
                }
                let sleep_duration = compute_idle_sleep(&config, now, plan.next_due_at)?;
                let next_check_at = advance_time(now, sleep_duration)?;
                {
                    let mut status = self.status.write().await;
                    status.next_wake_at = Some(next_check_at.to_rfc3339());
                    status.wait_reason = Some("idle_sleep".to_string());
                }
                tokio::select! {
                    _ = tokio::time::sleep(sleep_duration) => {}
                    _ = self.notify.notified() => {}
                }
                return Ok(());
            };

            if processed_keys.is_empty() {
                let _ = self.logger.runtime(
                    "info",
                    format!(
                        "scheduler picked {} due credential(s); next_due_at={}",
                        plan.due_keys.len(),
                        plan.next_due_at
                            .as_ref()
                            .map(DateTime::to_rfc3339)
                            .unwrap_or_else(|| "none".to_string())
                    ),
                );
            }

            if !self.enabled.load(Ordering::SeqCst) {
                return Ok(());
            }
            let key = due_entry.key.clone();
            {
                let mut status = self.status.write().await;
                status.current_key = Some(key.clone());
                status.next_key = plan
                    .due_keys
                    .iter()
                    .skip(index + 1)
                    .find(|entry| !processed_keys.contains(&entry.key))
                    .map(|entry| entry.key.clone())
                    .or_else(|| plan.next_future_key.clone());
                status.last_error = None;
                status.next_wake_at = None;
                status.wait_reason = None;
            }
            drop(plan);
            let outcome = self
                .transaction
                .refresh_one(
                    &config,
                    CredentialZone::Normal,
                    &key,
                    crate::transaction::RefreshTrigger::Scheduler,
                )
                .await?;
            processed_keys.insert(key);
            if outcome.success
                && let Some(backup) = &self.backup
            {
                backup.mark_dirty("scheduler_refresh_success");
            }
            self.update_backoff(&config, &outcome).await?;
            let latest_plan = self.collect_schedule_plan(&config, Utc::now()).await?;
            let latest_next_key = latest_plan.next_key_excluding(&processed_keys);
            {
                let mut status = self.status.write().await;
                status.current_key = None;
                status.next_key = latest_next_key.clone();
                status.next_due_at = latest_plan.next_due_at_rfc3339();
            }
            if !self.enabled.load(Ordering::SeqCst) || self.manual_requested.load(Ordering::SeqCst)
            {
                return Ok(());
            }
            let delay = random_delay(
                parse_duration_str(&config.refresh.inter_refresh_delay_min)?,
                parse_duration_str(&config.refresh.inter_refresh_delay_max)?,
            );
            let next_check_at = advance_time(Utc::now(), delay)?;
            {
                let mut status = self.status.write().await;
                status.next_wake_at = Some(next_check_at.to_rfc3339());
                status.wait_reason = Some("inter_refresh_delay".to_string());
            }
            let wake_requested = self
                .wait_inter_refresh_delay(
                    next_check_at,
                    latest_next_key,
                    latest_plan.future_due.as_slice(),
                )
                .await?;
            {
                let mut status = self.status.write().await;
                status.next_wake_at = None;
                status.wait_reason = None;
            }
            if wake_requested {
                return Ok(());
            }
        }
    }

    async fn collect_schedule_plan(
        &self,
        config: &crate::config::AppConfig,
        now: DateTime<Utc>,
    ) -> Result<SchedulePlan> {
        let backoff_map = self.backoff_until.read().await.clone();
        collect_schedule_plan(config, &self.store, &self.status_store, &backoff_map, now)
    }

    async fn wait_inter_refresh_delay(
        &self,
        delay_until: DateTime<Utc>,
        next_key: Option<String>,
        future_due: &[FutureDueEntry],
    ) -> Result<bool> {
        wait_inter_refresh_delay_state(
            self.notify.as_ref(),
            self.status.as_ref(),
            delay_until,
            next_key,
            future_due,
        )
        .await
    }

    async fn run_manual_refresh_all(&self) -> Result<()> {
        let config = self.config_manager.effective_config().await;
        let mut keys = self
            .store
            .scan_zone(CredentialZone::Normal)?
            .into_iter()
            .map(|entry| entry.key)
            .collect::<Vec<_>>();
        keys.sort();
        {
            let mut status = self.status.write().await;
            status.manual_pending = false;
            status.manual_running = true;
            status.manual_current_key = None;
            status.manual_total_count = keys.len();
            status.manual_processed_count = 0;
            status.manual_success_count = 0;
            status.manual_failed_count = 0;
            status.manual_last_started_at = Some(Utc::now().to_rfc3339());
            status.manual_last_finished_at = None;
            status.manual_last_item_error_key = None;
            status.manual_last_item_error = None;
            status.manual_last_run_error = None;
        }
        let _ = self.logger.runtime(
            "info",
            format!(
                "manual full refresh started for {} credential(s)",
                keys.len()
            ),
        );
        let min_delay = parse_duration_str(&config.refresh.manual_inter_refresh_delay_min)?;
        let max_delay = parse_duration_str(&config.refresh.manual_inter_refresh_delay_max)?;
        for (index, key) in keys.iter().enumerate() {
            {
                let mut status = self.status.write().await;
                status.manual_current_key = Some(key.clone());
            }
            let result = self
                .transaction
                .refresh_one(
                    &config,
                    CredentialZone::Normal,
                    key,
                    crate::transaction::RefreshTrigger::ManualBatch,
                )
                .await;
            match result {
                Ok(outcome) => {
                    let mut status = self.status.write().await;
                    status.manual_processed_count += 1;
                    if outcome.success {
                        status.manual_success_count += 1;
                        if let Some(backup) = &self.backup {
                            backup.mark_dirty("manual_batch_refresh_success");
                        }
                    } else {
                        status.manual_failed_count += 1;
                    }
                    status.manual_current_key = None;
                }
                Err(err) => {
                    let _ = self.logger.runtime(
                        "error",
                        format!("manual full refresh hit internal error on {}: {err:#}", key),
                    );
                    let mut status = self.status.write().await;
                    status.manual_processed_count += 1;
                    status.manual_failed_count += 1;
                    status.manual_current_key = None;
                    status.manual_last_item_error_key = Some(key.clone());
                    status.manual_last_item_error = Some(err.to_string());
                }
            }
            if index + 1 == keys.len() {
                continue;
            }
            let delay = random_delay(min_delay, max_delay);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.notify.notified() => {}
            }
        }
        {
            let mut status = self.status.write().await;
            status.manual_running = false;
            status.manual_current_key = None;
            status.manual_last_finished_at = Some(Utc::now().to_rfc3339());
            let _ = self.logger.runtime(
                "info",
                format!(
                    "manual full refresh finished (total={}, processed={}, success={}, failed={})",
                    status.manual_total_count,
                    status.manual_processed_count,
                    status.manual_success_count,
                    status.manual_failed_count
                ),
            );
        }
        Ok(())
    }

    async fn recover_after_worker_panic(&self, error: &str) {
        self.manual_busy.store(false, Ordering::SeqCst);
        self.manual_requested.store(false, Ordering::SeqCst);
        let now = Utc::now().to_rfc3339();
        let mut status = self.status.write().await;
        let had_manual_activity = status.manual_pending || status.manual_running;
        status.current_key = None;
        status.next_key = None;
        status.next_wake_at = None;
        status.next_due_at = None;
        status.wait_reason = None;
        status.last_error = Some(format!("scheduler runtime panicked and restarted: {error}"));
        if had_manual_activity {
            status.manual_pending = false;
            status.manual_running = false;
            status.manual_current_key = None;
            status.manual_last_run_error = Some(format!("手动全量刷新因调度器异常中断: {error}"));
            status.manual_last_finished_at = Some(now);
        }
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SchedulePlan {
    due_keys: Vec<DueEntry>,
    next_future_key: Option<String>,
    next_due_at: Option<DateTime<Utc>>,
    future_due: Vec<FutureDueEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DueEntry {
    key: String,
    due_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FutureDueEntry {
    key: String,
    due_at: DateTime<Utc>,
}

impl SchedulePlan {
    fn next_key(&self) -> Option<String> {
        self.due_keys
            .first()
            .map(|entry| entry.key.clone())
            .or_else(|| self.next_future_key.clone())
    }

    fn next_key_excluding(&self, processed_keys: &HashSet<String>) -> Option<String> {
        self.due_keys
            .iter()
            .find(|entry| !processed_keys.contains(&entry.key))
            .map(|entry| entry.key.clone())
            .or_else(|| self.next_key())
    }

    fn next_due_at_rfc3339(&self) -> Option<String> {
        self.next_due_at.as_ref().map(DateTime::to_rfc3339)
    }
}

fn collect_schedule_plan(
    config: &crate::config::AppConfig,
    store: &CredentialStore,
    status_store: &CredentialStatusStore,
    backoff_map: &HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<SchedulePlan> {
    let entries = store.scan_zone(CredentialZone::Normal)?;
    let mut due_keys = Vec::new();
    let mut future_due = Vec::new();
    for entry in entries {
        let key = entry.key.clone();
        let expires_at = entry
            .credential
            .as_ref()
            .and_then(|value| value.expires_at());
        let due = if let Some(credential) = entry.credential.as_ref() {
            due_at(config, credential, now)?.unwrap_or(now)
        } else {
            now
        };
        let persisted_status = status_store.get(&key)?;
        let persisted_backoff = persisted_backoff_until(config, persisted_status.as_ref())?;
        let scheduled_time = persisted_backoff
            .into_iter()
            .chain(backoff_map.get(&key).copied())
            .fold(due, |current, value| current.max(value));
        if scheduled_time <= now {
            due_keys.push(DueEntry {
                key,
                due_at: scheduled_time,
                expires_at,
            });
            continue;
        }
        future_due.push(FutureDueEntry {
            key,
            due_at: scheduled_time,
        });
    }
    due_keys.sort_by(|left, right| {
        match (left.expires_at, right.expires_at) {
            (Some(left_expiry), Some(right_expiry)) => left_expiry.cmp(&right_expiry),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.due_at.cmp(&right.due_at),
        }
        .then_with(|| left.key.cmp(&right.key))
    });
    future_due.sort_by(|left, right| {
        left.due_at
            .cmp(&right.due_at)
            .then_with(|| left.key.cmp(&right.key))
    });
    let next_future_key = future_due.first().map(|entry| entry.key.clone());
    let next_due_at = future_due.first().map(|entry| entry.due_at);
    Ok(SchedulePlan {
        due_keys,
        next_future_key,
        next_due_at,
        future_due,
    })
}

fn first_future_due_after(future_due: &[FutureDueEntry], now: DateTime<Utc>) -> usize {
    future_due
        .iter()
        .position(|entry| entry.due_at > now)
        .unwrap_or(future_due.len())
}

async fn wait_inter_refresh_delay_state(
    notify: &Notify,
    status: &RwLock<SchedulerStatus>,
    delay_until: DateTime<Utc>,
    next_key: Option<String>,
    future_due: &[FutureDueEntry],
) -> Result<bool> {
    let mut next_future_index = first_future_due_after(future_due, Utc::now());
    loop {
        let now = Utc::now();
        if now >= delay_until {
            return Ok(false);
        }
        while next_future_index < future_due.len() && future_due[next_future_index].due_at <= now {
            next_future_index += 1;
        }
        let sleep_until = future_due
            .get(next_future_index)
            .map(|entry| entry.due_at)
            .filter(|value| *value < delay_until)
            .unwrap_or(delay_until);
        let sleep_duration = (sleep_until - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(1));
        let mut wake_requested = false;
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = notify.notified() => {
                wake_requested = true;
            }
        }
        if wake_requested {
            return Ok(true);
        }
        let now = Utc::now();
        if now >= delay_until {
            return Ok(false);
        }
        while next_future_index < future_due.len() && future_due[next_future_index].due_at <= now {
            next_future_index += 1;
        }
        let mut guard = status.write().await;
        guard.next_key = next_key.clone();
        guard.next_due_at = future_due
            .get(next_future_index)
            .map(|entry| entry.due_at.to_rfc3339());
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

fn advance_time(now: DateTime<Utc>, delay: Duration) -> Result<DateTime<Utc>> {
    Ok(now
        + chrono::Duration::from_std(delay)
            .map_err(|err| anyhow::anyhow!("invalid scheduler duration: {err}"))?)
}

fn persisted_backoff_until(
    config: &crate::config::AppConfig,
    status: Option<&CredentialStatusRecord>,
) -> Result<Option<DateTime<Utc>>> {
    let Some(last_failure_at) = status.and_then(|value| value.last_failure_at.as_deref()) else {
        return Ok(None);
    };
    let Some(last_failure_at) = parse_rfc3339(last_failure_at) else {
        return Ok(None);
    };
    let failure_backoff = parse_duration_str(&config.refresh.failure_backoff)?;
    Ok(Some(
        last_failure_at
            + chrono::Duration::from_std(failure_backoff)
                .map_err(|err| anyhow::anyhow!("invalid failure_backoff duration: {err}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use chrono::TimeZone;
    use tempfile::tempdir;

    use super::*;
    use crate::credential::CodexCredentialFile;
    use crate::credential_store::CredentialStore;
    use crate::status::CredentialStatusStore;

    #[test]
    fn persisted_backoff_uses_last_failure_timestamp() {
        let config = crate::config::AppConfig::default();
        let status = CredentialStatusRecord {
            last_failure_at: Some("2026-01-01T00:00:00Z".to_string()),
            ..CredentialStatusRecord::default()
        };

        let until = persisted_backoff_until(&config, Some(&status))
            .unwrap()
            .unwrap();

        assert_eq!(until, Utc.with_ymd_and_hms(2026, 1, 1, 0, 15, 0).unwrap());
    }

    #[tokio::test]
    async fn manual_refresh_request_rejects_duplicate_triggers() {
        let temp = tempdir().unwrap();
        let handle = SchedulerHandle::load(temp.path().join("scheduler_state.json")).unwrap();
        handle.trigger_manual_refresh_all().await.unwrap();
        assert!(handle.trigger_manual_refresh_all().await.is_err());
    }

    #[tokio::test]
    async fn persists_enabled_state_across_reloads() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("scheduler_state.json");
        let handle = SchedulerHandle::load(path.clone()).unwrap();
        handle.stop().await.unwrap();

        let reloaded = SchedulerHandle::load(path).unwrap();
        assert!(!reloaded.status().await.enabled);

        reloaded.start().await.unwrap();
        assert!(reloaded.status().await.enabled);
    }

    #[tokio::test]
    async fn wake_interrupts_inter_refresh_delay() {
        let temp = tempdir().unwrap();
        let handle = SchedulerHandle::load(temp.path().join("scheduler_state.json")).unwrap();
        let notify = handle.notify.clone();
        let status = handle.status.clone();
        let delay_until = Utc::now() + chrono::Duration::seconds(30);
        let future_due = vec![FutureDueEntry {
            key: "future.json".to_string(),
            due_at: Utc::now() + chrono::Duration::minutes(30),
        }];

        let worker = tokio::spawn(async move {
            wait_inter_refresh_delay_state(
                notify.as_ref(),
                status.as_ref(),
                delay_until,
                Some("queued.json".to_string()),
                future_due.as_slice(),
            )
            .await
            .unwrap()
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.wake();

        let wake_requested = tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(wake_requested);
    }

    #[tokio::test]
    async fn wake_before_waiting_is_not_lost() {
        let temp = tempdir().unwrap();
        let handle = SchedulerHandle::load(temp.path().join("scheduler_state.json")).unwrap();

        handle.wake();

        tokio::time::timeout(Duration::from_millis(50), handle.notify.notified())
            .await
            .unwrap();
    }

    #[test]
    fn collect_schedule_plan_prefers_due_queue_then_earliest_future_key() {
        let temp = tempdir().unwrap();
        let (mut config, store, status_store) = test_schedule_components(temp.path());
        config.refresh.interval = "1h".to_string();
        config.refresh.lead_time = "1h".to_string();

        store
            .write_credential(
                CredentialZone::Normal,
                "zeta.json",
                &test_credential("2026-05-26T10:45:00Z"),
            )
            .unwrap();
        store
            .write_credential(
                CredentialZone::Normal,
                "beta.json",
                &test_credential("2026-05-26T11:40:00Z"),
            )
            .unwrap();
        store
            .write_credential(
                CredentialZone::Normal,
                "alpha.json",
                &test_credential("2026-05-26T11:30:00Z"),
            )
            .unwrap();

        let now = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        let plan =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();

        assert_eq!(plan.due_keys[0].key, "zeta.json");
        assert_eq!(plan.next_future_key.as_deref(), Some("alpha.json"));
        assert_eq!(plan.next_key().as_deref(), Some("zeta.json"));
        assert_eq!(
            plan.next_due_at,
            Some(parse_rfc3339("2026-05-26T12:30:00Z").unwrap())
        );
    }

    #[test]
    fn collect_schedule_plan_applies_persisted_backoff_to_next_key() {
        let temp = tempdir().unwrap();
        let (mut config, store, status_store) = test_schedule_components(temp.path());
        config.refresh.interval = "1h".to_string();
        config.refresh.lead_time = "1h".to_string();
        config.refresh.failure_backoff = "15m".to_string();

        store
            .write_credential(
                CredentialZone::Normal,
                "alpha.json",
                &test_credential("2026-05-26T10:30:00Z"),
            )
            .unwrap();

        let mut records = BTreeMap::new();
        records.insert(
            "alpha.json".to_string(),
            CredentialStatusRecord {
                last_failure_at: Some("2026-05-26T11:55:00Z".to_string()),
                ..CredentialStatusRecord::default()
            },
        );
        status_store.replace_all(records).unwrap();

        let now = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        let plan =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();

        assert!(plan.due_keys.is_empty());
        assert_eq!(plan.next_future_key.as_deref(), Some("alpha.json"));
        assert_eq!(plan.next_key().as_deref(), Some("alpha.json"));
        assert_eq!(
            plan.next_due_at,
            Some(parse_rfc3339("2026-05-26T12:10:00Z").unwrap())
        );
    }

    #[test]
    fn due_credentials_prioritize_expiry_then_unknown_due_time_and_key() {
        let temp = tempdir().unwrap();
        let (mut config, store, status_store) = test_schedule_components(temp.path());
        config.refresh.interval = "1h".to_string();
        config.refresh.lead_time = "1h".to_string();

        for (key, last_refresh, expired) in [
            (
                "alpha.json",
                "2026-05-26T10:30:00Z",
                Some("2030-01-01T00:00:00Z"),
            ),
            (
                "zeta.json",
                "2026-05-26T10:30:00Z",
                Some("2026-05-26T12:20:00Z"),
            ),
            (
                "beta.json",
                "2026-05-26T10:30:00Z",
                Some("2026-05-26T12:20:00Z"),
            ),
            ("unknown-late.json", "2026-05-26T10:40:00Z", None),
            ("unknown-early.json", "2026-05-26T10:20:00Z", None),
        ] {
            let mut credential = test_credential(last_refresh);
            credential.expired = expired.map(str::to_string);
            store
                .write_credential(CredentialZone::Normal, key, &credential)
                .unwrap();
        }

        let now = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        let plan =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();
        let keys = plan
            .due_keys
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            [
                "beta.json",
                "zeta.json",
                "alpha.json",
                "unknown-early.json",
                "unknown-late.json",
            ]
        );
        assert_eq!(plan.next_key().as_deref(), Some("beta.json"));

        let mut processed = HashSet::new();
        processed.insert("beta.json".to_string());
        assert_eq!(
            plan.next_key_excluding(&processed).as_deref(),
            Some("zeta.json")
        );
        processed.extend(keys.into_iter().map(str::to_string));
        assert_eq!(
            plan.next_key_excluding(&processed).as_deref(),
            Some("beta.json")
        );
    }

    #[test]
    fn replanning_picks_newly_due_urgent_credential() {
        let temp = tempdir().unwrap();
        let (mut config, store, status_store) = test_schedule_components(temp.path());
        config.refresh.interval = "1h".to_string();
        config.refresh.lead_time = "15m".to_string();

        store
            .write_credential(
                CredentialZone::Normal,
                "far.json",
                &test_credential("2026-05-26T10:30:00Z"),
            )
            .unwrap();
        let mut urgent = test_credential("2026-05-26T11:00:30Z");
        urgent.expired = Some("2026-05-26T12:30:00Z".to_string());
        store
            .write_credential(CredentialZone::Normal, "urgent.json", &urgent)
            .unwrap();

        let before_delay = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        let before = collect_schedule_plan(
            &config,
            &store,
            &status_store,
            &HashMap::new(),
            before_delay,
        )
        .unwrap();
        assert_eq!(before.next_key().as_deref(), Some("far.json"));
        assert_eq!(before.next_future_key.as_deref(), Some("urgent.json"));

        let after_delay = Utc.with_ymd_and_hms(2026, 5, 26, 12, 1, 0).unwrap();
        let after =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), after_delay)
                .unwrap();
        assert_eq!(after.next_key().as_deref(), Some("urgent.json"));
    }

    #[test]
    fn replanning_reflects_added_and_deleted_credentials() {
        let temp = tempdir().unwrap();
        let (mut config, store, status_store) = test_schedule_components(temp.path());
        config.refresh.interval = "1h".to_string();
        config.refresh.lead_time = "1h".to_string();
        let now = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();

        store
            .write_credential(
                CredentialZone::Normal,
                "far.json",
                &test_credential("2026-05-26T10:30:00Z"),
            )
            .unwrap();
        let first =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();
        assert_eq!(first.next_key().as_deref(), Some("far.json"));

        let mut urgent = test_credential("2026-05-26T10:30:00Z");
        urgent.expired = Some("2026-05-26T12:20:00Z".to_string());
        store
            .write_credential(CredentialZone::Normal, "urgent.json", &urgent)
            .unwrap();
        let after_add =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();
        assert_eq!(after_add.next_key().as_deref(), Some("urgent.json"));

        store.delete(CredentialZone::Normal, "urgent.json").unwrap();
        let after_delete =
            collect_schedule_plan(&config, &store, &status_store, &HashMap::new(), now).unwrap();
        assert_eq!(after_delete.next_key().as_deref(), Some("far.json"));
    }

    fn test_schedule_components(
        root: &std::path::Path,
    ) -> (
        crate::config::AppConfig,
        CredentialStore,
        CredentialStatusStore,
    ) {
        let mut config = crate::config::AppConfig::default();
        config.credentials_dir = root.join("credentials");
        config.abnormal_credentials_dir = root.join("credentials_abnormal");
        config.state_dir = root.join("state");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store =
            CredentialStatusStore::load(config.state_dir.join("credential_status.json")).unwrap();
        (config, store, status_store)
    }

    fn test_credential(last_refresh: &str) -> CodexCredentialFile {
        CodexCredentialFile {
            provider_type: "codex".to_string(),
            last_refresh: Some(last_refresh.to_string()),
            expired: Some("2030-01-01T00:00:00Z".to_string()),
            ..CodexCredentialFile::default()
        }
    }
}
