use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{fmt, fmt::Formatter};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use tempfile::Builder;
use tokio::sync::{Notify, RwLock};

use crate::backup_archive::{self, RestoredSnapshot};
use crate::config::{BackupConfig, BackupRemoteConfig, ConfigManager, parse_duration_str};
use crate::credential_store::CredentialStore;
use crate::fsutil;
use crate::logging::LogManager;
use crate::memdiag::{self, MemSample};
use crate::s3_compatible::{RemoteSnapshot, S3CompatibleClient};
use crate::scheduler::SchedulerHandle;
use crate::status::CredentialStatusStore;
use crate::write_coordinator::WriteCoordinator;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct BackupStatus {
    pub enabled: bool,
    pub configured: bool,
    pub configured_remote_count: usize,
    pub after_refresh_enabled: bool,
    pub running: bool,
    pub restore_running: bool,
    pub dirty_pending: bool,
    pub last_success_at: Option<String>,
    pub last_snapshot_key: Option<String>,
    pub latest_remote_name: Option<String>,
    pub active_remote_name: Option<String>,
    pub last_error: Option<String>,
    pub next_daily_at: Option<String>,
    pub next_after_refresh_at: Option<String>,
}

const BACKUP_OPERATION_BUSY_MESSAGE: &str = "当前已有备份任务在执行，请稍后再试";

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SnapshotListResult {
    pub items: Vec<RemoteSnapshot>,
    pub warnings: Vec<String>,
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
    state_store: Arc<BackupStateStore>,
    notify: Notify,
    status: RwLock<BackupStatus>,
    dirty_since: RwLock<Option<DateTime<Utc>>>,
    last_auto_backup_at: RwLock<Option<DateTime<Utc>>>,
    last_daily_backup_for: RwLock<Option<NaiveDate>>,
    last_after_refresh_failure_dirty_since: RwLock<Option<DateTime<Utc>>>,
    last_daily_failure_for: RwLock<Option<NaiveDate>>,
    s3_clients: RwLock<BTreeMap<String, CachedS3Client>>,
    busy: AtomicBool,
}

#[derive(Clone)]
struct CachedS3Client {
    key: BackupRemoteCacheKey,
    client: Arc<S3CompatibleClient>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct BackupPersistedState {
    last_success_at: Option<String>,
    last_snapshot_key: Option<String>,
    latest_remote_name: Option<String>,
}

#[derive(Debug)]
struct BackupStateStore {
    path: PathBuf,
    state: Mutex<BackupPersistedState>,
}

impl BackupStateStore {
    fn load(path: PathBuf) -> Result<Self> {
        let state = match fsutil::read_file_if_exists(&path)? {
            Some(raw) if raw.is_empty() => BackupPersistedState::default(),
            Some(raw) => serde_json::from_slice::<BackupPersistedState>(&raw)
                .with_context(|| format!("invalid backup state file {}", path.display()))?,
            None => BackupPersistedState::default(),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn get(&self) -> Result<BackupPersistedState> {
        self.state
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| anyhow::anyhow!("backup state lock poisoned"))
    }

    fn set_latest(
        &self,
        last_success_at: Option<String>,
        last_snapshot_key: Option<String>,
        latest_remote_name: Option<String>,
    ) -> Result<()> {
        let next = BackupPersistedState {
            last_success_at,
            last_snapshot_key,
            latest_remote_name,
        };
        fsutil::atomic_write_json(&self.path, &next)?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("backup state lock poisoned"))?;
        *guard = next;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
struct BackupRemoteCacheKey {
    kind: String,
    endpoint: String,
    region: String,
    bucket: String,
    object_prefix: String,
    access_key_id: String,
    secret_access_key: String,
    path_style: bool,
}

impl fmt::Debug for BackupRemoteCacheKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupRemoteCacheKey")
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("object_prefix", &self.object_prefix)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("path_style", &self.path_style)
            .finish()
    }
}

impl BackupRemoteCacheKey {
    fn from_remote_config(config: &BackupRemoteConfig) -> Self {
        Self {
            kind: config.kind.trim().to_string(),
            endpoint: config.endpoint.trim().trim_end_matches('/').to_string(),
            region: config.region.trim().to_string(),
            bucket: config.bucket.trim().to_string(),
            object_prefix: config.object_prefix.trim().trim_matches('/').to_string(),
            access_key_id: config.access_key_id.trim().to_string(),
            secret_access_key: config.secret_access_key.trim().to_string(),
            path_style: config.path_style,
        }
    }
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

#[derive(Clone, Copy, Debug)]
enum S3ClientCacheStatus {
    Hit,
    Created,
    Refreshed,
}

impl S3ClientCacheStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Created => "created",
            Self::Refreshed => "refreshed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SnapshotTrimSummary {
    listed_count: usize,
    deleted_count: usize,
}

impl BackupCoordinator {
    pub fn new(
        config_manager: ConfigManager,
        store: Arc<CredentialStore>,
        status_store: Arc<CredentialStatusStore>,
        scheduler: SchedulerHandle,
        logger: Arc<LogManager>,
        write_coordinator: Arc<WriteCoordinator>,
        state_path: PathBuf,
    ) -> Result<Self> {
        let state_store = Arc::new(BackupStateStore::load(state_path)?);
        let persisted = state_store.get()?;
        Ok(Self {
            inner: Arc::new(BackupRuntime {
                config_manager,
                store,
                status_store,
                scheduler,
                logger,
                write_coordinator,
                state_store,
                notify: Notify::new(),
                status: RwLock::new(BackupStatus {
                    last_success_at: persisted.last_success_at,
                    last_snapshot_key: persisted.last_snapshot_key,
                    latest_remote_name: persisted.latest_remote_name,
                    ..BackupStatus::default()
                }),
                dirty_since: RwLock::new(None),
                last_auto_backup_at: RwLock::new(None),
                last_daily_backup_for: RwLock::new(None),
                last_after_refresh_failure_dirty_since: RwLock::new(None),
                last_daily_failure_for: RwLock::new(None),
                s3_clients: RwLock::new(BTreeMap::new()),
                busy: AtomicBool::new(false),
            }),
        })
    }

    pub fn spawn_background(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            this.background_loop().await;
        });
    }

    pub fn mark_dirty(&self, reason: &'static str) {
        let this = self.clone();
        tokio::spawn(async move {
            let now = Utc::now();
            let mut dirty_since = this.inner.dirty_since.write().await;
            let already_pending = dirty_since.is_some();
            if dirty_since.is_none() {
                *dirty_since = Some(now);
            }
            let dirty_since_value = *dirty_since;
            drop(dirty_since);
            let mut last_after_refresh_failure = this
                .inner
                .last_after_refresh_failure_dirty_since
                .write()
                .await;
            *last_after_refresh_failure = None;
            drop(last_after_refresh_failure);
            let mut status = this.inner.status.write().await;
            status.dirty_pending = true;
            drop(status);
            let _ = this.inner.logger.runtime(
                "info",
                format!(
                    "backup marked dirty reason={} dirty_since={} already_pending={}",
                    reason,
                    format_optional_datetime(dirty_since_value),
                    already_pending,
                ),
            );
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

    pub async fn list_snapshots(&self) -> Result<SnapshotListResult> {
        let started_at = Instant::now();
        let rss_before_kb = memdiag::sample().rss_kb;
        let config = self.inner.config_manager.effective_config().await;
        self.sync_cached_s3_clients(&config.backup).await;
        let backup = ensure_backup_ready(&config.backup)?;
        let persisted = self.inner.state_store.get()?;
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut success_count = 0_usize;
        for (index, remote) in backup.configured_remotes().into_iter().enumerate() {
            let remote_name = remote.display_name(index);
            let (client, cache_status) = match self.cached_s3_client(remote).await {
                Ok(value) => value,
                Err(err) => {
                    warnings.push(format!("{remote_name}: {err}"));
                    let _ = self.inner.logger.runtime(
                        "error",
                        format!(
                            "backup snapshots client init failed remote={} rss_before_kb={} rss_after_kb={} elapsed_ms={} err={err:#}",
                            remote_name,
                            format_optional_u64(rss_before_kb),
                            format_optional_u64(memdiag::sample().rss_kb),
                            started_at.elapsed().as_millis(),
                        ),
                    );
                    continue;
                }
            };
            match client.list_snapshots().await {
                Ok(mut remote_items) => {
                    success_count += 1;
                    let remote_count = remote_items.len();
                    for item in &mut remote_items {
                        item.remote_name = Some(remote_name.clone());
                        item.is_current_latest = persisted.latest_remote_name.as_deref()
                            == Some(remote_name.as_str())
                            && persisted.last_snapshot_key.as_deref() == Some(item.key.as_str());
                    }
                    items.extend(remote_items);
                    let _ = self.inner.logger.runtime(
                        "info",
                        format!(
                            "backup snapshots listed remote={} count={} cache={} rss_before_kb={} rss_after_kb={} elapsed_ms={}",
                            remote_name,
                            remote_count,
                            cache_status.as_str(),
                            format_optional_u64(rss_before_kb),
                            format_optional_u64(memdiag::sample().rss_kb),
                            started_at.elapsed().as_millis(),
                        ),
                    );
                }
                Err(err) => {
                    warnings.push(format!("{remote_name}: {err}"));
                    let _ = self.inner.logger.runtime(
                        "error",
                        format!(
                            "backup snapshots listing failed remote={} cache={} rss_before_kb={} rss_after_kb={} elapsed_ms={} err={err:#}",
                            remote_name,
                            cache_status.as_str(),
                            format_optional_u64(rss_before_kb),
                            format_optional_u64(memdiag::sample().rss_kb),
                            started_at.elapsed().as_millis(),
                        ),
                    );
                }
            }
        }
        items.sort_by(compare_remote_snapshots_desc);
        let rss_after_kb = memdiag::sample().rss_kb;
        if should_fail_snapshot_listing(success_count, warnings.len()) {
            bail!("所有备份端读取失败：{}", warnings.join(" | "));
        }
        let _ = self.inner.logger.runtime(
            "info",
            format!(
                "backup snapshots merged count={} warnings={} rss_before_kb={} rss_after_kb={} elapsed_ms={}",
                items.len(),
                warnings.len(),
                format_optional_u64(rss_before_kb),
                format_optional_u64(rss_after_kb),
                started_at.elapsed().as_millis(),
            ),
        );
        Ok(SnapshotListResult { items, warnings })
    }

    pub async fn restore_snapshot(
        &self,
        remote_name: &str,
        snapshot_key: &str,
    ) -> Result<RestoreResult> {
        self.begin_backup_operation(true).await?;
        let result = self.restore_snapshot_inner(remote_name, snapshot_key).await;
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
        self.sync_cached_s3_clients(&config.backup).await;
        let configured_remote_count = config.backup.configured_remotes().len();
        let configured = configured_remote_count > 0;
        let now = Utc::now();
        let dirty_since = *self.inner.dirty_since.read().await;
        let last_daily_backup_for = *self.inner.last_daily_backup_for.read().await;
        let last_daily_failure_for = *self.inner.last_daily_failure_for.read().await;
        let last_auto_backup_at = *self.inner.last_auto_backup_at.read().await;
        let last_after_refresh_failure_dirty_since = *self
            .inner
            .last_after_refresh_failure_dirty_since
            .read()
            .await;
        let next_daily_at = if config.backup.enabled && configured {
            compute_next_daily_at(
                &config.backup,
                last_daily_backup_for,
                last_daily_failure_for,
                now,
            )
        } else {
            None
        };
        let next_after_refresh_at = if config.backup.enabled && configured {
            compute_after_refresh_due_at(
                &config.backup,
                dirty_since,
                last_auto_backup_at,
                last_after_refresh_failure_dirty_since,
            )?
        } else {
            None
        };
        {
            let mut status = self.inner.status.write().await;
            status.enabled = config.backup.enabled;
            status.configured = configured;
            status.configured_remote_count = configured_remote_count;
            status.after_refresh_enabled = config.backup.schedule.after_refresh_enabled;
            status.next_daily_at = next_daily_at.map(|value| value.to_rfc3339());
            status.next_after_refresh_at = next_after_refresh_at.map(|value| value.to_rfc3339());
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
            last_daily_backup_for,
            last_daily_failure_for,
            now,
        ) {
            if self.try_begin_backup_operation(false).await? {
                let result = self.run_backup_once(BackupTrigger::Daily).await;
                self.finish_backup_operation(false, &result).await;
                result?;
                return Ok(());
            }
        }

        if self.should_run_after_refresh(&config.backup, now).await? {
            if self.try_begin_backup_operation(false).await? {
                let result = self.run_backup_once(BackupTrigger::AfterRefresh).await;
                self.finish_backup_operation(false, &result).await;
                result?;
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
        if self.try_begin_backup_operation(restore).await? {
            return Ok(());
        }
        bail!(BACKUP_OPERATION_BUSY_MESSAGE);
    }

    async fn try_begin_backup_operation(&self, restore: bool) -> Result<bool> {
        if self
            .inner
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(false);
        }
        let mut status = self.inner.status.write().await;
        status.running = !restore;
        status.restore_running = restore;
        status.active_remote_name = None;
        status.last_error = None;
        Ok(true)
    }

    async fn finish_backup_operation<T>(&self, _restore: bool, result: &Result<T>) {
        self.inner.busy.store(false, Ordering::SeqCst);
        let mut status = self.inner.status.write().await;
        status.running = false;
        status.restore_running = false;
        status.active_remote_name = None;
        if let Err(err) = result {
            status.last_error = Some(err.to_string());
        }
    }

    async fn run_backup_once(&self, trigger: BackupTrigger) -> Result<RemoteSnapshot> {
        let started_at = Instant::now();
        let mem_before = memdiag::sample_full();
        let dirty_since = *self.inner.dirty_since.read().await;
        let last_auto_backup_at = *self.inner.last_auto_backup_at.read().await;
        let _ = self.inner.logger.runtime(
            "info",
            format!(
                "backup started trigger={} rss_before_kb={} cg_before_kb={} gap_before_kb={} cg_anon_kb={} cg_file_kb={} cg_shmem_kb={} cg_file_mapped_kb={} cg_active_file_kb={} cg_inactive_file_kb={} cg_pgfault={} cg_pgmajfault={} cg_workingset_refault_file={} cg_workingset_activate_file={} dirty_since={} last_auto_backup_at={}",
                trigger.as_str(),
                mem_before.fmt_rss(),
                mem_before.fmt_cg(),
                mem_before.fmt_gap(),
                mem_before.fmt_anon(),
                mem_before.fmt_file(),
                mem_before.fmt_shmem(),
                mem_before.fmt_file_mapped(),
                mem_before.fmt_active_file(),
                mem_before.fmt_inactive_file(),
                mem_before.fmt_pgfault(),
                mem_before.fmt_pgmajfault(),
                mem_before.fmt_workingset_refault_file(),
                mem_before.fmt_workingset_activate_file(),
                format_optional_datetime(dirty_since),
                format_optional_datetime(last_auto_backup_at),
            ),
        );

        let mut cache_status = None;
        let mut selected_remote_name = None::<String>;
        let mut snapshot_key_for_log: Option<String> = None;
        let mut archive_size_bytes = None;
        let mut mem_after_archive = MemSample::default();
        let mut mem_after_upload = MemSample::default();
        let mut mem_after_list = MemSample::default();
        let mut mem_after_delete = MemSample::default();
        let mut mem_after_drop = MemSample::default();
        let mut build_elapsed_ms = None;
        let mut upload_elapsed_ms = None;
        let mut list_elapsed_ms = None;
        let mut delete_elapsed_ms = None;
        let mut trim_summary = SnapshotTrimSummary::default();
        let mut fail_summaries = Vec::new();

        let result = async {
            let config = self.inner.config_manager.effective_config().await;
            self.sync_cached_s3_clients(&config.backup).await;
            let backup = ensure_backup_ready(&config.backup)?;
            let created_at = Utc::now();
            let temp_dir = config.state_dir.join("tmp");
            std::fs::create_dir_all(&temp_dir)
                .with_context(|| format!("failed to create {}", temp_dir.display()))?;
            let mut archive_file = Builder::new()
                .prefix("snapshot-")
                .suffix(".zip")
                .tempfile_in(&temp_dir)
                .with_context(|| {
                    format!("failed to create temp snapshot in {}", temp_dir.display())
                })?;
            {
                let _guard = self.inner.write_coordinator.lock_commit().await;
                backup_archive::build_snapshot_archive_to_writer(
                    archive_file.as_file_mut(),
                    &self.inner.store,
                    &self.inner.status_store,
                    trigger.as_str(),
                    created_at,
                )?;
            }
            archive_file
                .as_file_mut()
                .sync_all()
                .context("failed to sync temporary snapshot archive")?;
            let archive_size = archive_file
                .as_file()
                .metadata()
                .context("failed to inspect temporary snapshot archive")?
                .len();
            archive_size_bytes = Some(archive_size);
            mem_after_archive = memdiag::sample_full();
            build_elapsed_ms = Some(started_at.elapsed().as_millis());

            for (index, remote) in backup.configured_remotes().into_iter().enumerate() {
                let remote_name = remote.display_name(index);
                {
                    let mut status = self.inner.status.write().await;
                    status.active_remote_name = Some(remote_name.clone());
                }
                let (client, status) = match self.cached_s3_client(remote).await {
                    Ok(value) => value,
                    Err(err) => {
                        fail_summaries.push(format!("{remote_name}: {err}"));
                        let _ = self.inner.logger.runtime(
                            "error",
                            format!(
                                "backup attempt failed trigger={} remote={} endpoint={} bucket={} prefix={} err={err:#}",
                                trigger.as_str(),
                                remote_name,
                                display_config_value(remote.endpoint.trim()),
                                display_config_value(remote.bucket.trim()),
                                display_config_value(remote.object_prefix.trim()),
                            ),
                        );
                        continue;
                    }
                };
                cache_status = Some(status);
                selected_remote_name = Some(remote_name.clone());
                let snapshot_key = build_snapshot_key(&client, trigger, created_at);
                snapshot_key_for_log = Some(snapshot_key.clone());
                let _ = self.inner.logger.runtime(
                    "info",
                    format!(
                        "backup attempt started trigger={} remote={} key={} cache={} endpoint={} bucket={} prefix={}",
                        trigger.as_str(),
                        remote_name,
                        snapshot_key,
                        status.as_str(),
                        display_config_value(remote.endpoint.trim()),
                        display_config_value(remote.bucket.trim()),
                        display_config_value(remote.object_prefix.trim()),
                    ),
                );

                let attempt = async {
                    let upload_started_at = Instant::now();
                    let mut upload_handle = archive_file
                        .reopen()
                        .context("failed to reopen temporary snapshot archive")?;
                    upload_handle
                        .seek(SeekFrom::Start(0))
                        .context("failed to rewind temporary snapshot archive")?;
                    let mut upload_file = tokio::fs::File::from_std(upload_handle);
                    client
                        .put_object_stream(&snapshot_key, &mut upload_file)
                        .await?;
                    mem_after_upload = memdiag::sample_full();
                    upload_elapsed_ms = Some(upload_started_at.elapsed().as_millis());

                    let list_started_at = Instant::now();
                    let snapshots = client.list_snapshots().await?;
                    let listed_count = snapshots.len();
                    mem_after_list = memdiag::sample_full();
                    list_elapsed_ms = Some(list_started_at.elapsed().as_millis());

                    let delete_started_at = Instant::now();
                    let mut deleted_count = 0;
                    for snapshot in snapshots.into_iter().skip(1) {
                        client.delete_object(&snapshot.key).await?;
                        deleted_count += 1;
                    }
                    mem_after_delete = memdiag::sample_full();
                    delete_elapsed_ms = Some(delete_started_at.elapsed().as_millis());
                    trim_summary = SnapshotTrimSummary {
                        listed_count,
                        deleted_count,
                    };

                    drop(upload_file);
                    mem_after_drop = memdiag::sample_full();
                    self.inner.state_store.set_latest(
                        Some(created_at.to_rfc3339()),
                        Some(snapshot_key.clone()),
                        Some(remote_name.clone()),
                    )?;
                    {
                        let mut status = self.inner.status.write().await;
                        status.last_success_at = Some(created_at.to_rfc3339());
                        status.last_snapshot_key = Some(snapshot_key.clone());
                        status.latest_remote_name = Some(remote_name.clone());
                        status.last_error = None;
                        status.dirty_pending = false;
                        status.next_after_refresh_at = None;
                    }
                    {
                        let mut dirty_since = self.inner.dirty_since.write().await;
                        *dirty_since = None;
                    }
                    {
                        let mut last_after_refresh_failure = self
                            .inner
                            .last_after_refresh_failure_dirty_since
                            .write()
                            .await;
                        *last_after_refresh_failure = None;
                    }
                    if matches!(trigger, BackupTrigger::Daily | BackupTrigger::AfterRefresh) {
                        let mut last_auto = self.inner.last_auto_backup_at.write().await;
                        *last_auto = Some(created_at);
                    }
                    if matches!(trigger, BackupTrigger::Daily) {
                        let mut last_daily = self.inner.last_daily_backup_for.write().await;
                        *last_daily = Some(created_at.date_naive());
                        let mut last_daily_failure = self.inner.last_daily_failure_for.write().await;
                        *last_daily_failure = None;
                    }
                    let (created_at_display, trigger_display) =
                        crate::s3_compatible::parse_snapshot_name_for_display(&snapshot_key);
                    Ok::<RemoteSnapshot, anyhow::Error>(RemoteSnapshot {
                        key: snapshot_key.clone(),
                        size: archive_size,
                        last_modified: Some(created_at.to_rfc3339()),
                        created_at: created_at_display,
                        trigger: trigger_display,
                        remote_name: Some(remote_name.clone()),
                        is_current_latest: true,
                    })
                }
                .await;

                match attempt {
                    Ok(snapshot) => return Ok(snapshot),
                    Err(err) => {
                        fail_summaries.push(format!("{remote_name}: {err}"));
                        let _ = self.inner.logger.runtime(
                            "error",
                            format!(
                                "backup attempt failed trigger={} remote={} key={} cache={} endpoint={} bucket={} prefix={} err={err:#}",
                                trigger.as_str(),
                                remote_name,
                                snapshot_key,
                                status.as_str(),
                                display_config_value(remote.endpoint.trim()),
                                display_config_value(remote.bucket.trim()),
                                display_config_value(remote.object_prefix.trim()),
                            ),
                        );
                    }
                }
            }

            bail!("所有备份端均失败：{}", fail_summaries.join(" | "))
        }
        .await;

        let mem_final = memdiag::sample_full();
        let cache_status = cache_status
            .map(|value| value.as_str())
            .unwrap_or("unknown");
        let remote_name = selected_remote_name.as_deref().unwrap_or("-");
        let snapshot_key = snapshot_key_for_log.as_deref().unwrap_or("-");
        let archive_size_bytes = archive_size_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "na".to_string());
        let total_elapsed_ms = started_at.elapsed().as_millis();
        match &result {
            Ok(snapshot) => {
                let _ = self.inner.logger.runtime(
                    "info",
                    format!(
                        "backup finished trigger={} remote={} key={} cache={} archive_size_bytes={} snapshots_seen={} snapshots_deleted={} build_ms={} upload_ms={} list_ms={} delete_ms={} total_ms={}",
                        trigger.as_str(),
                        remote_name,
                        snapshot.key,
                        cache_status,
                        archive_size_bytes,
                        trim_summary.listed_count,
                        trim_summary.deleted_count,
                        format_optional_u128(build_elapsed_ms),
                        format_optional_u128(upload_elapsed_ms),
                        format_optional_u128(list_elapsed_ms),
                        format_optional_u128(delete_elapsed_ms),
                        total_elapsed_ms,
                    ),
                );
                let _ = self.inner.logger.runtime(
                    "info",
                    format!(
                        "backup metrics trigger={} rss_before_kb={} cg_before_kb={} gap_before_kb={} cg_anon_before_kb={} cg_file_before_kb={} cg_shmem_before_kb={} cg_file_mapped_before_kb={} cg_active_file_before_kb={} cg_inactive_file_before_kb={} rss_after_archive_kb={} cg_after_archive_kb={} gap_after_archive_kb={} cg_anon_after_archive_kb={} cg_file_after_archive_kb={} rss_after_upload_kb={} cg_after_upload_kb={} gap_after_upload_kb={} cg_anon_after_upload_kb={} cg_file_after_upload_kb={} rss_after_list_kb={} cg_after_list_kb={} gap_after_list_kb={} cg_anon_after_list_kb={} cg_file_after_list_kb={} rss_after_delete_kb={} cg_after_delete_kb={} gap_after_delete_kb={} cg_anon_after_delete_kb={} cg_file_after_delete_kb={} rss_after_drop_kb={} cg_after_drop_kb={} gap_after_drop_kb={} cg_anon_drop_kb={} cg_file_drop_kb={} cg_shmem_drop_kb={} cg_file_mapped_drop_kb={} cg_active_file_drop_kb={} cg_inactive_file_drop_kb={} pgfault_delta={} pgmajfault_delta={} workingset_refault_file_delta={} workingset_activate_file_delta={}",
                        trigger.as_str(),
                        mem_before.fmt_rss(),
                        mem_before.fmt_cg(),
                        mem_before.fmt_gap(),
                        mem_before.fmt_anon(),
                        mem_before.fmt_file(),
                        mem_before.fmt_shmem(),
                        mem_before.fmt_file_mapped(),
                        mem_before.fmt_active_file(),
                        mem_before.fmt_inactive_file(),
                        mem_after_archive.fmt_rss(),
                        mem_after_archive.fmt_cg(),
                        mem_after_archive.fmt_gap(),
                        mem_after_archive.fmt_anon(),
                        mem_after_archive.fmt_file(),
                        mem_after_upload.fmt_rss(),
                        mem_after_upload.fmt_cg(),
                        mem_after_upload.fmt_gap(),
                        mem_after_upload.fmt_anon(),
                        mem_after_upload.fmt_file(),
                        mem_after_list.fmt_rss(),
                        mem_after_list.fmt_cg(),
                        mem_after_list.fmt_gap(),
                        mem_after_list.fmt_anon(),
                        mem_after_list.fmt_file(),
                        mem_after_delete.fmt_rss(),
                        mem_after_delete.fmt_cg(),
                        mem_after_delete.fmt_gap(),
                        mem_after_delete.fmt_anon(),
                        mem_after_delete.fmt_file(),
                        mem_after_drop.fmt_rss(),
                        mem_after_drop.fmt_cg(),
                        mem_after_drop.fmt_gap(),
                        mem_after_drop.fmt_anon(),
                        mem_after_drop.fmt_file(),
                        mem_after_drop.fmt_shmem(),
                        mem_after_drop.fmt_file_mapped(),
                        mem_after_drop.fmt_active_file(),
                        mem_after_drop.fmt_inactive_file(),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_pgfault,
                            mem_after_drop.cg_pgfault,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_pgmajfault,
                            mem_after_drop.cg_pgmajfault,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_workingset_refault_file,
                            mem_after_drop.cg_workingset_refault_file,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_workingset_activate_file,
                            mem_after_drop.cg_workingset_activate_file,
                        )),
                    ),
                );
            }
            Err(err) => {
                match trigger {
                    BackupTrigger::AfterRefresh => {
                        let mut last_after_refresh_failure = self
                            .inner
                            .last_after_refresh_failure_dirty_since
                            .write()
                            .await;
                        *last_after_refresh_failure = dirty_since;
                    }
                    BackupTrigger::Daily => {
                        let mut last_daily_failure =
                            self.inner.last_daily_failure_for.write().await;
                        *last_daily_failure = Some(Utc::now().date_naive());
                    }
                    BackupTrigger::Manual => {}
                }
                let _ = self.inner.logger.runtime(
                    "error",
                    format!(
                        "backup failed trigger={} remote={} key={} cache={} rss_before_kb={} cg_before_kb={} gap_before_kb={} rss_after_archive_kb={} cg_after_archive_kb={} gap_after_archive_kb={} rss_after_upload_kb={} cg_after_upload_kb={} gap_after_upload_kb={} rss_final_kb={} cg_final_kb={} gap_final_kb={} cg_anon_final_kb={} cg_file_final_kb={} cg_shmem_final_kb={} cg_file_mapped_final_kb={} cg_active_file_final_kb={} cg_inactive_file_final_kb={} pgfault_delta={} pgmajfault_delta={} workingset_refault_file_delta={} workingset_activate_file_delta={} archive_size_bytes={} snapshots_seen={} snapshots_deleted={} build_ms={} upload_ms={} list_ms={} delete_ms={} total_ms={} err={err:#}",
                        trigger.as_str(),
                        remote_name,
                        snapshot_key,
                        cache_status,
                        mem_before.fmt_rss(),
                        mem_before.fmt_cg(),
                        mem_before.fmt_gap(),
                        mem_after_archive.fmt_rss(),
                        mem_after_archive.fmt_cg(),
                        mem_after_archive.fmt_gap(),
                        mem_after_upload.fmt_rss(),
                        mem_after_upload.fmt_cg(),
                        mem_after_upload.fmt_gap(),
                        mem_final.fmt_rss(),
                        mem_final.fmt_cg(),
                        mem_final.fmt_gap(),
                        mem_final.fmt_anon(),
                        mem_final.fmt_file(),
                        mem_final.fmt_shmem(),
                        mem_final.fmt_file_mapped(),
                        mem_final.fmt_active_file(),
                        mem_final.fmt_inactive_file(),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_pgfault,
                            mem_final.cg_pgfault,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_pgmajfault,
                            mem_final.cg_pgmajfault,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_workingset_refault_file,
                            mem_final.cg_workingset_refault_file,
                        )),
                        format_optional_u64(memdiag::counter_delta(
                            mem_before.cg_workingset_activate_file,
                            mem_final.cg_workingset_activate_file,
                        )),
                        archive_size_bytes,
                        trim_summary.listed_count,
                        trim_summary.deleted_count,
                        format_optional_u128(build_elapsed_ms),
                        format_optional_u128(upload_elapsed_ms),
                        format_optional_u128(list_elapsed_ms),
                        format_optional_u128(delete_elapsed_ms),
                        total_elapsed_ms,
                    ),
                );
            }
        }
        result
    }

    async fn restore_snapshot_inner(
        &self,
        remote_name: &str,
        snapshot_key: &str,
    ) -> Result<RestoreResult> {
        let started_at = Instant::now();
        let rss_before_kb = memdiag::sample().rss_kb;
        let scheduler_status = self.inner.scheduler.status().await;
        if scheduler_status.manual_running || scheduler_status.manual_pending {
            bail!("手动全量刷新正在执行中，请等待其完成后重试");
        }
        let mut cache_status = None;
        let mut downloaded_bytes = None;
        let mut manifest_normal_count = None;
        let mut manifest_abnormal_count = None;
        let result = async {
            let config = self.inner.config_manager.effective_config().await;
            self.sync_cached_s3_clients(&config.backup).await;
            let backup = ensure_backup_ready(&config.backup)?;
            let remote = find_backup_remote(backup, remote_name)
                .ok_or_else(|| anyhow::anyhow!("未找到名为 {remote_name} 的备份端"))?;
            {
                let mut status = self.inner.status.write().await;
                status.active_remote_name = Some(remote_name.to_string());
            }
            let (client, status) = self.cached_s3_client(remote).await?;
            cache_status = Some(status);
            let _activity_guard = self.inner.write_coordinator.lock_activity().await;
            let freeze_guard = self.inner.write_coordinator.begin_restore()?;
            self.inner.scheduler.pause().await;
            let result = async {
                let archive_bytes = client.get_object(snapshot_key).await?;
                downloaded_bytes = Some(archive_bytes.len());
                let parsed_snapshot = backup_archive::parse_snapshot_archive(&archive_bytes)?;
                manifest_normal_count = Some(parsed_snapshot.manifest.normal_count);
                manifest_abnormal_count = Some(parsed_snapshot.manifest.abnormal_count);
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
            if self.inner.scheduler.persisted_enabled()? {
                self.inner.scheduler.resume().await;
            }
            result
        }
        .await;
        let rss_after_kb = memdiag::sample().rss_kb;
        let cache_status = cache_status
            .map(|value| value.as_str())
            .unwrap_or("unknown");
        match &result {
            Ok(restored) => {
                let _ = self.inner.logger.runtime(
                    "info",
                    format!(
                        "backup restore completed remote={} snapshot_key={} cache={} downloaded_bytes={} manifest_normal_count={} manifest_abnormal_count={} restored_normal_count={} restored_abnormal_count={} rss_before_kb={} rss_after_kb={} elapsed_ms={}",
                        remote_name,
                        snapshot_key,
                        cache_status,
                        format_optional_usize(downloaded_bytes),
                        format_optional_usize(manifest_normal_count),
                        format_optional_usize(manifest_abnormal_count),
                        restored.normal_count,
                        restored.abnormal_count,
                        format_optional_u64(rss_before_kb),
                        format_optional_u64(rss_after_kb),
                        started_at.elapsed().as_millis(),
                    ),
                );
            }
            Err(err) => {
                let _ = self.inner.logger.runtime(
                    "error",
                    format!(
                        "backup restore failed remote={} snapshot_key={} cache={} downloaded_bytes={} manifest_normal_count={} manifest_abnormal_count={} rss_before_kb={} rss_after_kb={} elapsed_ms={} err={err:#}",
                        remote_name,
                        snapshot_key,
                        cache_status,
                        format_optional_usize(downloaded_bytes),
                        format_optional_usize(manifest_normal_count),
                        format_optional_usize(manifest_abnormal_count),
                        format_optional_u64(rss_before_kb),
                        format_optional_u64(rss_after_kb),
                        started_at.elapsed().as_millis(),
                    ),
                );
            }
        }
        let restored = result?;
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
        let dirty_since = *self.inner.dirty_since.read().await;
        let last_auto = *self.inner.last_auto_backup_at.read().await;
        let last_failed_dirty_since = *self
            .inner
            .last_after_refresh_failure_dirty_since
            .read()
            .await;
        let Some(due_at) =
            compute_after_refresh_due_at(backup, dirty_since, last_auto, last_failed_dirty_since)?
        else {
            return Ok(false);
        };
        Ok(now >= due_at)
    }

    async fn next_wait_duration(
        &self,
        backup: &BackupConfig,
        now: DateTime<Utc>,
    ) -> Result<Duration> {
        let mut candidates = Vec::new();
        if let Some(next_daily_at) = compute_next_daily_at(
            backup,
            *self.inner.last_daily_backup_for.read().await,
            *self.inner.last_daily_failure_for.read().await,
            now,
        ) {
            let wait = (next_daily_at - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1));
            candidates.push(wait);
        }
        let dirty_since = *self.inner.dirty_since.read().await;
        let last_auto = *self.inner.last_auto_backup_at.read().await;
        let last_failed_dirty_since = *self
            .inner
            .last_after_refresh_failure_dirty_since
            .read()
            .await;
        if let Some(due_at) =
            compute_after_refresh_due_at(backup, dirty_since, last_auto, last_failed_dirty_since)?
        {
            let wait = (due_at - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1));
            candidates.push(wait);
        }
        Ok(candidates
            .into_iter()
            .min()
            .unwrap_or_else(|| Duration::from_secs(30))
            .max(Duration::from_secs(1)))
    }

    async fn cached_s3_client(
        &self,
        remote: &BackupRemoteConfig,
    ) -> Result<(Arc<S3CompatibleClient>, S3ClientCacheStatus)> {
        let key = BackupRemoteCacheKey::from_remote_config(remote);
        let cache_name = remote_cache_name(remote);
        {
            let guard = self.inner.s3_clients.read().await;
            if let Some(cached) = guard.get(&cache_name)
                && cached.key == key
            {
                return Ok((Arc::clone(&cached.client), S3ClientCacheStatus::Hit));
            }
        }

        let client = Arc::new(S3CompatibleClient::new(remote)?);
        let mut guard = self.inner.s3_clients.write().await;
        if let Some(cached) = guard.get(&cache_name)
            && cached.key == key
        {
            return Ok((Arc::clone(&cached.client), S3ClientCacheStatus::Hit));
        }

        let cache_status = if guard.contains_key(&cache_name) {
            S3ClientCacheStatus::Refreshed
        } else {
            S3ClientCacheStatus::Created
        };
        guard.insert(
            cache_name.clone(),
            CachedS3Client {
                key: key.clone(),
                client: Arc::clone(&client),
            },
        );
        let _ = self.inner.logger.runtime(
            "info",
            format!(
                "backup s3 client cache {} remote={} endpoint={} bucket={} prefix={} region={} path_style={}",
                cache_status.as_str(),
                cache_name,
                display_config_value(&key.endpoint),
                display_config_value(&key.bucket),
                display_config_value(&key.object_prefix),
                display_config_value(&key.region),
                key.path_style,
            ),
        );
        Ok((client, cache_status))
    }

    async fn sync_cached_s3_clients(&self, backup: &BackupConfig) {
        let active_names: std::collections::BTreeSet<String> = backup
            .configured_remotes()
            .into_iter()
            .map(remote_cache_name)
            .collect();
        let mut guard = self.inner.s3_clients.write().await;
        let removed: Vec<String> = guard
            .keys()
            .filter(|name| !active_names.contains(*name))
            .cloned()
            .collect();
        if removed.is_empty() {
            return;
        }
        guard.retain(|name, _| active_names.contains(name));
        drop(guard);
        let _ = self.inner.logger.runtime(
            "info",
            format!(
                "backup s3 client cache pruned removed={} names={}",
                removed.len(),
                removed.join(",")
            ),
        );
    }
}

fn ensure_backup_ready(backup: &BackupConfig) -> Result<&BackupConfig> {
    if !backup.enabled {
        bail!("备份功能未启用");
    }
    if backup.configured_remotes().is_empty() {
        bail!("备份远端配置不完整，请先在设置页补全至少一个备份端");
    }
    Ok(backup)
}

fn find_backup_remote<'a>(
    backup: &'a BackupConfig,
    remote_name: &str,
) -> Option<&'a BackupRemoteConfig> {
    let target = remote_name.trim();
    backup
        .remotes
        .iter()
        .enumerate()
        .find(|(index, remote)| remote.is_configured() && remote.display_name(*index) == target)
        .map(|(_, remote)| remote)
}

fn remote_cache_name(remote: &BackupRemoteConfig) -> String {
    let name = remote.name.trim();
    if !name.is_empty() {
        return name.to_string();
    }
    if !remote.endpoint.trim().is_empty() {
        return remote.endpoint.trim().trim_end_matches('/').to_string();
    }
    "unnamed-backup-remote".to_string()
}

fn compare_remote_snapshots_desc(
    left: &RemoteSnapshot,
    right: &RemoteSnapshot,
) -> std::cmp::Ordering {
    snapshot_sort_key(right)
        .cmp(&snapshot_sort_key(left))
        .then_with(|| left.remote_name.cmp(&right.remote_name))
        .then_with(|| left.key.cmp(&right.key))
}

fn should_fail_snapshot_listing(success_count: usize, warning_count: usize) -> bool {
    success_count == 0 && warning_count > 0
}

fn snapshot_sort_key(snapshot: &RemoteSnapshot) -> String {
    snapshot
        .created_at
        .clone()
        .or_else(|| snapshot.last_modified.clone())
        .unwrap_or_else(|| snapshot.key.clone())
}

fn should_run_daily(
    backup: &BackupConfig,
    last_daily_backup_for: Option<NaiveDate>,
    last_daily_failure_for: Option<NaiveDate>,
    now: DateTime<Utc>,
) -> bool {
    if !backup.schedule.daily_utc_enabled {
        return false;
    }
    if last_daily_failure_for == Some(now.date_naive()) {
        return false;
    }
    last_daily_backup_for != Some(now.date_naive())
}

fn compute_next_daily_at(
    backup: &BackupConfig,
    last_daily_backup_for: Option<NaiveDate>,
    last_daily_failure_for: Option<NaiveDate>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if !backup.schedule.daily_utc_enabled {
        return None;
    }
    if last_daily_failure_for == Some(now.date_naive()) {
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

fn compute_after_refresh_due_at(
    backup: &BackupConfig,
    dirty_since: Option<DateTime<Utc>>,
    last_auto_backup_at: Option<DateTime<Utc>>,
    last_after_refresh_failure_dirty_since: Option<DateTime<Utc>>,
) -> Result<Option<DateTime<Utc>>> {
    if !backup.schedule.after_refresh_enabled {
        return Ok(None);
    }
    let Some(dirty_since) = dirty_since else {
        return Ok(None);
    };
    if last_after_refresh_failure_dirty_since == Some(dirty_since) {
        return Ok(None);
    }
    let debounce =
        chrono::Duration::from_std(parse_duration_str(&backup.schedule.after_refresh_debounce)?)
            .context("invalid backup after_refresh_debounce")?;
    let min_interval = chrono::Duration::from_std(parse_duration_str(
        &backup.schedule.min_interval_between_auto_backups,
    )?)
    .context("invalid backup min_interval_between_auto_backups")?;
    let due_by_dirty = dirty_since + debounce;
    let due_by_interval = last_auto_backup_at
        .map(|value| value + min_interval)
        .unwrap_or(due_by_dirty);
    Ok(Some(due_by_dirty.max(due_by_interval)))
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

fn format_optional_datetime(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| "none".to_string())
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "na".to_string())
}

fn format_optional_u128(value: Option<u128>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "na".to_string())
}

fn format_optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "na".to_string())
}

fn display_config_value(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn after_refresh_due_at_uses_debounce_without_previous_auto_backup() {
        let mut backup = BackupConfig::default();
        backup.schedule.after_refresh_debounce = "2m".to_string();
        backup.schedule.min_interval_between_auto_backups = "6h".to_string();
        let dirty_since = Utc.with_ymd_and_hms(2026, 4, 6, 15, 38, 1).unwrap();

        let due_at = compute_after_refresh_due_at(&backup, Some(dirty_since), None, None)
            .unwrap()
            .unwrap();

        assert_eq!(due_at, Utc.with_ymd_and_hms(2026, 4, 6, 15, 40, 1).unwrap());
    }

    #[test]
    fn after_refresh_due_at_respects_min_interval_from_last_auto_backup() {
        let mut backup = BackupConfig::default();
        backup.schedule.after_refresh_debounce = "2m".to_string();
        backup.schedule.min_interval_between_auto_backups = "6h".to_string();
        let dirty_since = Utc.with_ymd_and_hms(2026, 4, 6, 15, 38, 1).unwrap();
        let last_auto_backup_at = Utc.with_ymd_and_hms(2026, 4, 6, 11, 54, 41).unwrap();

        let due_at = compute_after_refresh_due_at(
            &backup,
            Some(dirty_since),
            Some(last_auto_backup_at),
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            due_at,
            Utc.with_ymd_and_hms(2026, 4, 6, 17, 54, 41).unwrap()
        );
    }

    #[test]
    fn after_refresh_due_at_is_none_when_no_pending_dirty_data() {
        let backup = BackupConfig::default();

        let due_at = compute_after_refresh_due_at(&backup, None, None, None).unwrap();

        assert_eq!(due_at, None);
    }

    #[test]
    fn after_refresh_due_at_is_none_after_failure_until_new_dirty_mark() {
        let backup = BackupConfig::default();
        let dirty_since = Utc.with_ymd_and_hms(2026, 4, 6, 15, 38, 1).unwrap();

        let due_at =
            compute_after_refresh_due_at(&backup, Some(dirty_since), None, Some(dirty_since))
                .unwrap();

        assert_eq!(due_at, None);
    }

    #[test]
    fn remote_cache_key_normalizes_remote_config_values() {
        let key = BackupRemoteCacheKey::from_remote_config(&BackupRemoteConfig {
            name: "primary".to_string(),
            kind: " s3_compatible ".to_string(),
            endpoint: " https://example.com/ ".to_string(),
            region: " us-east-1 ".to_string(),
            bucket: " bucket-a ".to_string(),
            object_prefix: " /snapshots/root/ ".to_string(),
            access_key_id: " key-id ".to_string(),
            secret_access_key: " secret-key ".to_string(),
            path_style: true,
        });

        assert_eq!(key.kind, "s3_compatible");
        assert_eq!(key.endpoint, "https://example.com");
        assert_eq!(key.region, "us-east-1");
        assert_eq!(key.bucket, "bucket-a");
        assert_eq!(key.object_prefix, "snapshots/root");
        assert_eq!(key.access_key_id, "key-id");
        assert_eq!(key.secret_access_key, "secret-key");
        assert!(key.path_style);
    }

    #[test]
    fn remote_cache_key_changes_when_credentials_change() {
        let mut first = BackupRemoteConfig::default();
        first.endpoint = "https://example.com".to_string();
        first.bucket = "bucket-a".to_string();
        first.access_key_id = "key-a".to_string();
        first.secret_access_key = "secret-a".to_string();

        let mut second = first.clone();
        second.secret_access_key = "secret-b".to_string();

        assert_ne!(
            BackupRemoteCacheKey::from_remote_config(&first),
            BackupRemoteCacheKey::from_remote_config(&second)
        );
    }

    #[test]
    fn snapshot_listing_failure_requires_all_remotes_to_fail() {
        assert!(!should_fail_snapshot_listing(1, 1));
        assert!(!should_fail_snapshot_listing(1, 0));
        assert!(!should_fail_snapshot_listing(0, 0));
        assert!(should_fail_snapshot_listing(0, 1));
    }
}
