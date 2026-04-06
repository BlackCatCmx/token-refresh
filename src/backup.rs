use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use tokio::sync::{Notify, RwLock};

use crate::backup_archive::{self, RestoredSnapshot};
use crate::config::{BackupConfig, ConfigManager, parse_duration_str};
use crate::credential_store::CredentialStore;
use crate::logging::LogManager;
use crate::s3_compatible::{RemoteSnapshot, S3CompatibleClient};
use crate::scheduler::SchedulerHandle;
use crate::status::CredentialStatusStore;
use crate::write_coordinator::WriteCoordinator;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct BackupStatus {
    pub enabled: bool,
    pub configured: bool,
    pub running: bool,
    pub restore_running: bool,
    pub dirty_pending: bool,
    pub last_success_at: Option<String>,
    pub last_snapshot_key: Option<String>,
    pub last_error: Option<String>,
    pub next_daily_at: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RestoreResult {
    pub snapshot_key: String,
    pub normal_count: usize,
    pub abnormal_count: usize,
}

#[derive(Clone)]
pub struct BackupCoordinator {
    inner: Arc<BackupRuntime>,
}

struct BackupRuntime {
    config_manager: ConfigManager,
    store: Arc<CredentialStore>,
    status_store: Arc<CredentialStatusStore>,
    scheduler: SchedulerHandle,
    logger: Arc<LogManager>,
    write_coordinator: Arc<WriteCoordinator>,
    notify: Notify,
    status: RwLock<BackupStatus>,
    dirty_since: RwLock<Option<DateTime<Utc>>>,
    last_auto_backup_at: RwLock<Option<DateTime<Utc>>>,
    last_daily_backup_for: RwLock<Option<NaiveDate>>,
    busy: AtomicBool,
}

#[derive(Clone, Copy, Debug)]
enum BackupTrigger {
    Daily,
    AfterRefresh,
    Manual,
}

impl BackupTrigger {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::AfterRefresh => "after-refresh",
            Self::Manual => "manual",
        }
    }
}

impl BackupCoordinator {
    pub fn new(
        config_manager: ConfigManager,
        store: Arc<CredentialStore>,
        status_store: Arc<CredentialStatusStore>,
        scheduler: SchedulerHandle,
        logger: Arc<LogManager>,
        write_coordinator: Arc<WriteCoordinator>,
    ) -> Self {
        Self {
            inner: Arc::new(BackupRuntime {
                config_manager,
                store,
                status_store,
                scheduler,
                logger,
                write_coordinator,
                notify: Notify::new(),
                status: RwLock::new(BackupStatus::default()),
                dirty_since: RwLock::new(None),
                last_auto_backup_at: RwLock::new(None),
                last_daily_backup_for: RwLock::new(None),
                busy: AtomicBool::new(false),
            }),
        }
    }

    pub fn spawn_background(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            this.background_loop().await;
        });
    }

    pub fn mark_dirty(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut dirty_since = this.inner.dirty_since.write().await;
            if dirty_since.is_none() {
                *dirty_since = Some(Utc::now());
            }
            drop(dirty_since);
            let mut status = this.inner.status.write().await;
            status.dirty_pending = true;
            drop(status);
            this.inner.notify.notify_waiters();
        });
    }

    pub fn wake(&self) {
        self.inner.notify.notify_waiters();
    }

    pub async fn status(&self) -> BackupStatus {
        self.inner.status.read().await.clone()
    }

    pub async fn run_manual_backup(&self) -> Result<RemoteSnapshot> {
        self.begin_backup_operation(false).await?;
        let result = self.run_backup_once(BackupTrigger::Manual).await;
        self.finish_backup_operation(false, &result).await;
        result
    }

    pub async fn list_snapshots(&self) -> Result<Vec<RemoteSnapshot>> {
        let config = self.inner.config_manager.effective_config().await;
        let backup = ensure_backup_ready(&config.backup)?;
        let client = S3CompatibleClient::new(&backup.remote)?;
        client.list_snapshots().await
    }

    pub async fn restore_snapshot(&self, snapshot_key: &str) -> Result<RestoreResult> {
        self.begin_backup_operation(true).await?;
        let result = self.restore_snapshot_inner(snapshot_key).await;
        self.finish_backup_operation(true, &result).await;
        result
    }

    async fn background_loop(self) {
        loop {
            if let Err(err) = self.background_tick().await {
                let _ = self
                    .inner
                    .logger
                    .runtime("error", format!("backup background loop failed: {err:#}"));
                let mut status = self.inner.status.write().await;
                status.last_error = Some(err.to_string());
                drop(status);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = self.inner.notify.notified() => {}
                }
            }
        }
    }

    async fn background_tick(&self) -> Result<()> {
        let config = self.inner.config_manager.effective_config().await;
        let configured = is_backup_remote_configured(&config.backup);
        let now = Utc::now();
        let next_daily_at = if config.backup.enabled && configured {
            compute_next_daily_at(
                &config.backup,
                *self.inner.last_daily_backup_for.read().await,
                now,
            )
        } else {
            None
        };
        {
            let mut status = self.inner.status.write().await;
            status.enabled = config.backup.enabled;
            status.configured = configured;
            status.next_daily_at = next_daily_at.map(|value| value.to_rfc3339());
        }
        if !config.backup.enabled || !configured {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                _ = self.inner.notify.notified() => {}
            }
            return Ok(());
        }

        if should_run_daily(
            &config.backup,
            *self.inner.last_daily_backup_for.read().await,
            now,
        ) {
            if !self.inner.busy.load(Ordering::SeqCst) {
                self.begin_backup_operation(false).await?;
                let result = self.run_backup_once(BackupTrigger::Daily).await;
                self.finish_backup_operation(false, &result).await;
                return Ok(());
            }
        }

        if self.should_run_after_refresh(&config.backup, now).await? {
            if !self.inner.busy.load(Ordering::SeqCst) {
                self.begin_backup_operation(false).await?;
                let result = self.run_backup_once(BackupTrigger::AfterRefresh).await;
                self.finish_backup_operation(false, &result).await;
                return Ok(());
            }
        }

        let wait_duration = self.next_wait_duration(&config.backup, now).await?;
        tokio::select! {
            _ = tokio::time::sleep(wait_duration) => {}
            _ = self.inner.notify.notified() => {}
        }
        Ok(())
    }

    async fn begin_backup_operation(&self, restore: bool) -> Result<()> {
        if self
            .inner
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            bail!("当前已有备份任务在执行，请稍后再试");
        }
        let mut status = self.inner.status.write().await;
        status.running = !restore;
        status.restore_running = restore;
        status.last_error = None;
        Ok(())
    }

    async fn finish_backup_operation<T>(&self, _restore: bool, result: &Result<T>) {
        self.inner.busy.store(false, Ordering::SeqCst);
        let mut status = self.inner.status.write().await;
        status.running = false;
        status.restore_running = false;
        if let Err(err) = result {
            status.last_error = Some(err.to_string());
        }
    }

    async fn run_backup_once(&self, trigger: BackupTrigger) -> Result<RemoteSnapshot> {
        let config = self.inner.config_manager.effective_config().await;
        let backup = ensure_backup_ready(&config.backup)?;
        let client = S3CompatibleClient::new(&backup.remote)?;
        let created_at = Utc::now();
        let snapshot_key = build_snapshot_key(&client, trigger, created_at);
        let archive_bytes = {
            let _guard = self.inner.write_coordinator.lock_commit().await;
            backup_archive::build_snapshot_archive(
                &self.inner.store,
                &self.inner.status_store,
                trigger.as_str(),
                created_at,
            )?
        };
        client.put_object(&snapshot_key, &archive_bytes).await?;
        trim_old_snapshots(&client).await?;
        {
            let mut status = self.inner.status.write().await;
            status.last_success_at = Some(created_at.to_rfc3339());
            status.last_snapshot_key = Some(snapshot_key.clone());
            status.last_error = None;
            status.dirty_pending = false;
        }
        {
            let mut dirty_since = self.inner.dirty_since.write().await;
            *dirty_since = None;
        }
        if matches!(trigger, BackupTrigger::Daily | BackupTrigger::AfterRefresh) {
            let mut last_auto = self.inner.last_auto_backup_at.write().await;
            *last_auto = Some(created_at);
        }
        if matches!(trigger, BackupTrigger::Daily) {
            let mut last_daily = self.inner.last_daily_backup_for.write().await;
            *last_daily = Some(created_at.date_naive());
        }
        self.inner.logger.runtime(
            "info",
            format!(
                "backup uploaded successfully trigger={} key={}",
                trigger.as_str(),
                snapshot_key
            ),
        )?;
        let (created_at_display, trigger_display) =
            crate::s3_compatible::parse_snapshot_name_for_display(&snapshot_key);
        Ok(RemoteSnapshot {
            key: snapshot_key,
            size: archive_bytes.len() as u64,
            last_modified: Some(created_at.to_rfc3339()),
            created_at: created_at_display,
            trigger: trigger_display,
        })
    }

    async fn restore_snapshot_inner(&self, snapshot_key: &str) -> Result<RestoreResult> {
        let scheduler_status = self.inner.scheduler.status().await;
        if scheduler_status.manual_running || scheduler_status.manual_pending {
            bail!("手动全量刷新正在执行中，请等待其完成后重试");
        }
        let config = self.inner.config_manager.effective_config().await;
        let backup = ensure_backup_ready(&config.backup)?;
        let client = S3CompatibleClient::new(&backup.remote)?;
        let freeze_guard = self.inner.write_coordinator.begin_restore()?;
        let scheduler_was_enabled = self.inner.scheduler.status().await.enabled;
        self.inner.scheduler.stop().await;
        let result = async {
            let archive_bytes = client.get_object(snapshot_key).await?;
            let parsed_snapshot = backup_archive::parse_snapshot_archive(&archive_bytes)?;
            let restored: RestoredSnapshot = {
                let _commit_guard = self.inner.write_coordinator.lock_commit().await;
                backup_archive::restore_snapshot_archive(
                    &self.inner.store,
                    &self.inner.status_store,
                    parsed_snapshot,
                )?
            };
            self.inner.scheduler.clear_backoff().await;
            Ok::<RestoredSnapshot, anyhow::Error>(restored)
        }
        .await;
        drop(freeze_guard);
        if scheduler_was_enabled {
            self.inner.scheduler.start().await;
        }
        let restored = result?;
        self.inner.logger.runtime(
            "info",
            format!("backup restore completed from {}", snapshot_key),
        )?;
        Ok(RestoreResult {
            snapshot_key: snapshot_key.to_string(),
            normal_count: restored.normal_count,
            abnormal_count: restored.abnormal_count,
        })
    }

    async fn should_run_after_refresh(
        &self,
        backup: &BackupConfig,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        if !backup.schedule.after_refresh_enabled {
            return Ok(false);
        }
        let Some(dirty_since) = *self.inner.dirty_since.read().await else {
            return Ok(false);
        };
        let debounce = chrono::Duration::from_std(parse_duration_str(
            &backup.schedule.after_refresh_debounce,
        )?)
        .context("invalid backup after_refresh_debounce")?;
        let min_interval = chrono::Duration::from_std(parse_duration_str(
            &backup.schedule.min_interval_between_auto_backups,
        )?)
        .context("invalid backup min_interval_between_auto_backups")?;
        let due_by_dirty = dirty_since + debounce;
        let last_auto = *self.inner.last_auto_backup_at.read().await;
        let due_by_interval = last_auto
            .map(|value| value + min_interval)
            .unwrap_or(due_by_dirty);
        Ok(now >= due_by_dirty.max(due_by_interval))
    }

    async fn next_wait_duration(
        &self,
        backup: &BackupConfig,
        now: DateTime<Utc>,
    ) -> Result<Duration> {
        let mut candidates = Vec::new();
        if let Some(next_daily_at) =
            compute_next_daily_at(backup, *self.inner.last_daily_backup_for.read().await, now)
        {
            let wait = (next_daily_at - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1));
            candidates.push(wait);
        }
        if backup.schedule.after_refresh_enabled {
            if let Some(dirty_since) = *self.inner.dirty_since.read().await {
                let debounce = chrono::Duration::from_std(parse_duration_str(
                    &backup.schedule.after_refresh_debounce,
                )?)?;
                let min_interval = chrono::Duration::from_std(parse_duration_str(
                    &backup.schedule.min_interval_between_auto_backups,
                )?)?;
                let due_by_dirty = dirty_since + debounce;
                let last_auto = *self.inner.last_auto_backup_at.read().await;
                let due_by_interval = last_auto
                    .map(|value| value + min_interval)
                    .unwrap_or(due_by_dirty);
                let due_at = due_by_dirty.max(due_by_interval);
                let wait = (due_at - now)
                    .to_std()
                    .unwrap_or_else(|_| Duration::from_secs(1));
                candidates.push(wait);
            }
        }
        Ok(candidates
            .into_iter()
            .min()
            .unwrap_or_else(|| Duration::from_secs(30))
            .max(Duration::from_secs(1)))
    }
}

fn ensure_backup_ready(backup: &BackupConfig) -> Result<&BackupConfig> {
    if !backup.enabled {
        bail!("备份功能未启用");
    }
    if !is_backup_remote_configured(backup) {
        bail!("备份远端配置不完整，请先在设置页补全");
    }
    Ok(backup)
}

fn is_backup_remote_configured(backup: &BackupConfig) -> bool {
    backup.remote.kind.trim() == "s3_compatible"
        && !backup.remote.endpoint.trim().is_empty()
        && !backup.remote.region.trim().is_empty()
        && !backup.remote.bucket.trim().is_empty()
        && !backup.remote.access_key_id.trim().is_empty()
        && !backup.remote.secret_access_key.trim().is_empty()
}

fn should_run_daily(
    backup: &BackupConfig,
    last_daily_backup_for: Option<NaiveDate>,
    now: DateTime<Utc>,
) -> bool {
    if !backup.schedule.daily_utc_enabled {
        return false;
    }
    last_daily_backup_for != Some(now.date_naive())
}

fn compute_next_daily_at(
    backup: &BackupConfig,
    last_daily_backup_for: Option<NaiveDate>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !backup.schedule.daily_utc_enabled {
        return None;
    }
    let target_date = if last_daily_backup_for == Some(now.date_naive()) {
        now.date_naive().succ_opt()?
    } else {
        now.date_naive()
    };
    target_date
        .and_hms_opt(0, 0, 0)
        .map(|value| DateTime::<Utc>::from_naive_utc_and_offset(value, Utc))
}

fn build_snapshot_key(
    client: &S3CompatibleClient,
    trigger: BackupTrigger,
    created_at: DateTime<Utc>,
) -> String {
    let root = client.snapshot_root_prefix();
    let date_path = created_at.format("%Y/%m/%d").to_string();
    let timestamp = match trigger {
        BackupTrigger::Daily => created_at.format("%Y%m%dT000000Z").to_string(),
        BackupTrigger::AfterRefresh | BackupTrigger::Manual => {
            created_at.format("%Y%m%dT%H%M%SZ").to_string()
        }
    };
    format!(
        "{}{}/snapshot-{}-{}.zip",
        root,
        date_path,
        timestamp,
        trigger.as_str()
    )
}

async fn trim_old_snapshots(client: &S3CompatibleClient) -> Result<()> {
    let snapshots = client.list_snapshots().await?;
    for snapshot in snapshots.into_iter().skip(1) {
        client.delete_object(&snapshot.key).await?;
    }
    Ok(())
}
