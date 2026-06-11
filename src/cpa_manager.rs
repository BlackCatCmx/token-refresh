use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::backup::BackupCoordinator;
use crate::cpa_client::{CpaAuthEntry, CpaClient};
use crate::cpa_config::{CpaConfig, validate_cpa_proxy_list};
use crate::cpa_log::CpaLog;
use crate::credential::{CodexCredentialFile, parse_rfc3339};
use crate::credential_store::{CredentialEntry, CredentialStore, CredentialZone};
use crate::scheduler::SchedulerHandle as RefreshSchedulerHandle;
use crate::status::{CredentialStatusRecord, CredentialStatusStore, normalize_status_key};
use crate::write_coordinator::WriteCoordinator;

const EXHAUSTED_RESET_FALLBACK_HOURS: i64 = 30 * 24 + 1;

#[derive(Clone, Debug, Default, Serialize)]
pub struct InspectResult {
    pub started_at: String,
    pub finished_at: String,
    pub ok: bool,
    pub error: Option<String>,
    pub total_codex: usize,
    pub candidates_401: usize,
    pub moved_to_abnormal: usize,
    pub candidates_exhausted: usize,
    pub moved_to_normal_exhausted: usize,
    pub supplement_target: usize,
    pub supplement_before: usize,
    pub supplement_needed: usize,
    pub supplement_done: usize,
    pub moved_abnormal_names: Vec<String>,
    pub moved_exhausted_names: Vec<String>,
    pub supplemented_names: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ReclaimResult {
    pub started_at: String,
    pub finished_at: String,
    pub ok: bool,
    pub error: Option<String>,
    pub total_codex: usize,
    pub imported_to_normal: usize,
    pub imported_to_abnormal: usize,
    pub imported_exhausted: usize,
    pub cleaned_disabled_residual: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ManualSupplementResult {
    pub started_at: String,
    pub finished_at: String,
    pub ok: bool,
    pub error: Option<String>,
    pub requested: usize,
    pub eligible: usize,
    pub supplemented: usize,
    pub supplemented_names: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

pub struct CpaManager {
    store: Arc<CredentialStore>,
    status_store: Arc<CredentialStatusStore>,
    write_coordinator: Arc<WriteCoordinator>,
    backup: Arc<BackupCoordinator>,
    scheduler: RefreshSchedulerHandle,
    cpa_log: Arc<CpaLog>,
    running: Arc<Mutex<()>>,
    running_flag: AtomicBool,
    last_result: StdMutex<Option<InspectResult>>,
}

impl CpaManager {
    pub fn new(
        store: Arc<CredentialStore>,
        status_store: Arc<CredentialStatusStore>,
        write_coordinator: Arc<WriteCoordinator>,
        backup: Arc<BackupCoordinator>,
        scheduler: RefreshSchedulerHandle,
        cpa_log: Arc<CpaLog>,
    ) -> Self {
        Self {
            store,
            status_store,
            write_coordinator,
            backup,
            scheduler,
            cpa_log,
            running: Arc::new(Mutex::new(())),
            running_flag: AtomicBool::new(false),
            last_result: StdMutex::new(None),
        }
    }

    pub fn last_result(&self) -> Option<InspectResult> {
        self.last_result.lock().ok().and_then(|guard| guard.clone())
    }

    pub fn is_running(&self) -> bool {
        self.running_flag.load(Ordering::SeqCst)
    }

    pub fn clear_due_exhausted(&self) -> Result<usize> {
        let pending = self.status_store.list_exhausted_pending_reset()?;
        let now = Utc::now();
        let mut cleared = 0usize;
        for item in pending {
            let should_clear = match item.exhausted_resets_at.as_deref() {
                Some(value) => match parse_rfc3339(value) {
                    Some(resets_at) => now >= resets_at,
                    None => {
                        self.log_best_effort(format!(
                            "[WARN] CPA exhausted reset timestamp is invalid for {}: {}",
                            item.key, value
                        ));
                        false
                    }
                },
                None => item
                    .cpa_imported_at
                    .as_deref()
                    .and_then(parse_rfc3339)
                    .map(|imported_at| {
                        now >= imported_at + ChronoDuration::hours(EXHAUSTED_RESET_FALLBACK_HOURS)
                    })
                    .unwrap_or(false),
            };
            if !should_clear {
                continue;
            }
            self.status_store.clear_cpa_exhausted(&item.key)?;
            self.log_best_effort(format!(
                "[INFO] cleared CPA exhausted flag for {}",
                item.key
            ));
            cleared += 1;
        }
        if cleared > 0 {
            self.backup.mark_dirty("cpa_clear_due_exhausted");
        }
        Ok(cleared)
    }

    pub async fn inspect_once(&self, cfg: &CpaConfig) -> InspectResult {
        let started_at = Utc::now().to_rfc3339();
        let guard = match self.running.clone().try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                return self.finish_result(InspectResult {
                    started_at,
                    finished_at: String::new(),
                    ok: false,
                    error: Some("CPA 巡查正在执行中".to_string()),
                    supplement_target: cfg.supplement_target,
                    ..InspectResult::default()
                });
            }
        };
        self.running_flag.store(true, Ordering::SeqCst);
        let _running_guard = RunningFlagGuard {
            flag: &self.running_flag,
            _guard: guard,
        };
        self.log_best_effort("[INFO] CPA inspect started");

        let mut result = InspectResult {
            started_at,
            finished_at: String::new(),
            ok: false,
            error: None,
            total_codex: 0,
            candidates_401: 0,
            moved_to_abnormal: 0,
            candidates_exhausted: 0,
            moved_to_normal_exhausted: 0,
            supplement_target: cfg.supplement_target,
            supplement_before: 0,
            supplement_needed: 0,
            supplement_done: 0,
            moved_abnormal_names: Vec::new(),
            moved_exhausted_names: Vec::new(),
            supplemented_names: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };
        let mut local_changed = false;

        if let Err(err) = self.write_coordinator.ensure_writes_allowed() {
            result.error = Some(err.to_string());
            return self.finish_result(result);
        }

        let client = match CpaClient::new(&cfg.base_url, &cfg.management_key) {
            Ok(client) => client,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_result(result);
            }
        };

        let entries = match client.list_codex_files().await {
            Ok(entries) => entries,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_result(result);
            }
        };
        result.total_codex = entries.len();

        for entry in entries.iter().filter(|entry| is_disabled_entry(entry)) {
            if let Err(err) = self.cleanup_disabled_residual(&client, entry).await {
                let message = format!("清理 CPA 禁用残留失败 {}: {err:#}", entry.name);
                self.log_best_effort(format!("[WARN] {message}"));
                result.warnings.push(message);
            }
        }

        let active_entries: Vec<CpaAuthEntry> = entries
            .into_iter()
            .filter(|entry| !is_disabled_entry(entry))
            .collect();
        let unauthorized_entries: Vec<CpaAuthEntry> = active_entries
            .iter()
            .filter(|entry| is_unauthorized_entry(entry))
            .cloned()
            .collect();
        let exhausted_entries: Vec<CpaAuthEntry> = active_entries
            .iter()
            .filter(|entry| is_exhausted_entry(entry))
            .cloned()
            .collect();
        result.candidates_401 = unauthorized_entries.len();
        result.candidates_exhausted = exhausted_entries.len();

        let safety_abort = cfg.safety_abort_enabled
            && result.total_codex > 0
            && (result.candidates_401 * 100)
                >= (result.total_codex * usize::from(cfg.safety_abort_ratio_percent));
        if safety_abort {
            let message = format!(
                "异常凭证占比达到保护阈值，已跳过本轮 401 移除（{}/{}）",
                result.candidates_401, result.total_codex
            );
            self.log_best_effort(format!("[WARN] {message}"));
            result.warnings.push(message);
        } else {
            for entry in unauthorized_entries {
                match self
                    .move_from_cpa(
                        &client,
                        &entry,
                        CredentialZone::Abnormal,
                        None,
                        ImportStatusKind::Abnormal {
                            code: "cpa_unauthorized",
                            default_reason: "unauthorized",
                        },
                    )
                    .await
                {
                    Ok(outcome) => {
                        local_changed |= outcome.local_changed;
                        if outcome.moved {
                            result.moved_to_abnormal += 1;
                            result.moved_abnormal_names.push(entry.name.clone());
                        }
                        if let Some(message) = outcome.message {
                            result.warnings.push(message);
                        }
                    }
                    Err(err) => {
                        let message =
                            format!("导入 CPA 异常凭证失败 {}: {err:#}", entry.name.as_str());
                        self.log_best_effort(format!("[ERROR] {message}"));
                        result.errors.push(message);
                    }
                }
            }
        }

        for entry in exhausted_entries {
            match self
                .move_from_cpa(
                    &client,
                    &entry,
                    CredentialZone::Normal,
                    exhausted_resets_at(&entry, Utc::now()),
                    ImportStatusKind::NormalExhausted,
                )
                .await
            {
                Ok(outcome) => {
                    local_changed |= outcome.local_changed;
                    if outcome.moved {
                        result.moved_to_normal_exhausted += 1;
                        result.moved_exhausted_names.push(entry.name.clone());
                    }
                    if let Some(message) = outcome.message {
                        result.warnings.push(message);
                    }
                }
                Err(err) => {
                    let message = format!("导入 CPA 耗尽凭证失败 {}: {err:#}", entry.name);
                    self.log_best_effort(format!("[ERROR] {message}"));
                    result.errors.push(message);
                }
            }
        }

        if cfg.auto_supplement_enabled {
            match client.list_codex_files().await {
                Ok(remaining) => {
                    let remaining_active: Vec<CpaAuthEntry> = remaining
                        .into_iter()
                        .filter(|entry| !is_disabled_entry(entry))
                        .collect();
                    result.supplement_before = remaining_active.len();
                    result.supplement_needed = cfg
                        .supplement_target
                        .saturating_sub(result.supplement_before);
                    if result.supplement_needed > 0 {
                        match SupplementProxyAssignment::from_config(cfg) {
                            Ok(proxy_assignment) => {
                                match self
                                    .supplement_from_local(
                                        &client,
                                        result.supplement_needed,
                                        &remaining_active,
                                        &proxy_assignment,
                                    )
                                    .await
                                {
                                    Ok(summary) => {
                                        local_changed |= summary.local_changed;
                                        result.supplement_done = summary.done;
                                        result.supplemented_names = summary.names;
                                        result.errors.extend(summary.errors);
                                    }
                                    Err(err) => {
                                        let message = format!("自动补号失败: {err:#}");
                                        self.log_best_effort(format!("[ERROR] {message}"));
                                        result.errors.push(message);
                                    }
                                }
                            }
                            Err(err) => {
                                let message = format!("CPA 补号代理配置无效: {err:#}");
                                self.log_best_effort(format!("[ERROR] {message}"));
                                result.errors.push(message);
                            }
                        }
                    }
                }
                Err(err) => {
                    let message = format!("重新读取 CPA 凭证列表失败: {err:#}");
                    self.log_best_effort(format!("[ERROR] {message}"));
                    result.errors.push(message);
                }
            }
        }

        if local_changed {
            self.backup.mark_dirty("cpa_inspect_once");
            self.scheduler.wake();
        }

        recompute_ok(&mut result);
        self.log_best_effort(format!(
            "[INFO] CPA inspect finished ok={} total={} moved_abnormal={} moved_exhausted={} supplemented={} warnings={} errors={}",
            result.ok,
            result.total_codex,
            result.moved_to_abnormal,
            result.moved_to_normal_exhausted,
            result.supplement_done,
            result.warnings.len(),
            result.errors.len()
        ));
        self.finish_result(result)
    }

    pub async fn reclaim_all(&self, cfg: &CpaConfig) -> ReclaimResult {
        let started_at = Utc::now().to_rfc3339();
        let guard = match self.running.clone().try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                return self.finish_reclaim_result(ReclaimResult {
                    started_at,
                    finished_at: String::new(),
                    ok: false,
                    error: Some("CPA 操作正在执行中".to_string()),
                    ..ReclaimResult::default()
                });
            }
        };
        self.running_flag.store(true, Ordering::SeqCst);
        let _running_guard = RunningFlagGuard {
            flag: &self.running_flag,
            _guard: guard,
        };
        self.log_best_effort("[INFO] CPA reclaim started");

        let mut result = ReclaimResult {
            started_at,
            ..ReclaimResult::default()
        };
        let mut local_changed = false;

        if let Err(err) = self.write_coordinator.ensure_writes_allowed() {
            result.error = Some(err.to_string());
            return self.finish_reclaim_result(result);
        }

        let client = match CpaClient::new(&cfg.base_url, &cfg.management_key) {
            Ok(client) => client,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_reclaim_result(result);
            }
        };

        let entries = match client.list_codex_files().await {
            Ok(entries) => entries,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_reclaim_result(result);
            }
        };
        result.total_codex = entries.len();

        for entry in entries {
            let has_local_copy = match self.local_copy_exists(&entry.name) {
                Ok(exists) => exists,
                Err(err) => {
                    let message = format!("检查本地同名凭证失败 {}: {err:#}", entry.name);
                    self.log_best_effort(format!("[ERROR] {message}"));
                    result.errors.push(message);
                    continue;
                }
            };
            // Disabled entries with an existing local copy only need remote residual cleanup.
            // When no local copy exists, they are reclaimed into the abnormal zone below.
            if is_disabled_entry(&entry) && has_local_copy {
                match self.cleanup_disabled_residual(&client, &entry).await {
                    Ok(()) => {
                        result.cleaned_disabled_residual += 1;
                    }
                    Err(err) => {
                        let message = format!("清理 CPA 禁用残留失败 {}: {err:#}", entry.name);
                        self.log_best_effort(format!("[WARN] {message}"));
                        result.warnings.push(message);
                    }
                }
                continue;
            }

            let status_kind = classify_reclaim_import(&entry);
            let target_zone = status_kind.target_zone();
            match self
                .move_from_cpa(
                    &client,
                    &entry,
                    target_zone,
                    exhausted_resets_at(&entry, Utc::now()),
                    status_kind,
                )
                .await
            {
                Ok(outcome) => {
                    local_changed |= outcome.local_changed;
                    if outcome.moved {
                        match status_kind {
                            ImportStatusKind::Normal => result.imported_to_normal += 1,
                            ImportStatusKind::NormalExhausted => result.imported_exhausted += 1,
                            ImportStatusKind::Abnormal { .. } => {
                                result.imported_to_abnormal += 1;
                            }
                        }
                    } else {
                        result.skipped += 1;
                    }
                    if let Some(message) = outcome.message {
                        result.warnings.push(message);
                    }
                }
                Err(err) => {
                    let message = format!("取回 CPA 凭证失败 {}: {err:#}", entry.name);
                    self.log_best_effort(format!("[ERROR] {message}"));
                    result.errors.push(message);
                }
            }
        }

        if local_changed {
            self.backup.mark_dirty("cpa_reclaim_all");
            self.scheduler.wake();
        }

        recompute_reclaim_ok(&mut result);
        self.log_best_effort(format!(
            "[INFO] CPA reclaim finished ok={} total={} normal={} abnormal={} exhausted={} cleaned_disabled_residual={} skipped={} warnings={} errors={}",
            result.ok,
            result.total_codex,
            result.imported_to_normal,
            result.imported_to_abnormal,
            result.imported_exhausted,
            result.cleaned_disabled_residual,
            result.skipped,
            result.warnings.len(),
            result.errors.len()
        ));
        self.finish_reclaim_result(result)
    }

    pub async fn supplement_once(
        &self,
        cfg: &CpaConfig,
        requested: usize,
    ) -> ManualSupplementResult {
        let started_at = Utc::now().to_rfc3339();
        let guard = match self.running.clone().try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                return self.finish_manual_supplement_result(ManualSupplementResult {
                    started_at,
                    finished_at: String::new(),
                    ok: false,
                    error: Some("CPA 操作正在执行中".to_string()),
                    requested,
                    ..ManualSupplementResult::default()
                });
            }
        };
        self.running_flag.store(true, Ordering::SeqCst);
        let _running_guard = RunningFlagGuard {
            flag: &self.running_flag,
            _guard: guard,
        };
        self.log_best_effort(format!(
            "[INFO] CPA manual supplement started requested={requested}"
        ));

        let mut result = ManualSupplementResult {
            started_at,
            finished_at: String::new(),
            ok: false,
            error: None,
            requested,
            eligible: 0,
            supplemented: 0,
            supplemented_names: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        };
        let mut local_changed = false;

        if requested == 0 {
            result.error = Some("补充数量必须大于 0".to_string());
            return self.finish_manual_supplement_result(result);
        }

        if let Err(err) = self.write_coordinator.ensure_writes_allowed() {
            result.error = Some(err.to_string());
            return self.finish_manual_supplement_result(result);
        }

        let client = match CpaClient::new(&cfg.base_url, &cfg.management_key) {
            Ok(client) => client,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_manual_supplement_result(result);
            }
        };
        let proxy_assignment = match SupplementProxyAssignment::from_config(cfg) {
            Ok(proxy_assignment) => proxy_assignment,
            Err(err) => {
                result.error = Some(format!("CPA 补号代理配置无效: {err:#}"));
                return self.finish_manual_supplement_result(result);
            }
        };

        let remaining = match client.list_codex_files().await {
            Ok(entries) => entries,
            Err(err) => {
                result.error = Some(err.to_string());
                return self.finish_manual_supplement_result(result);
            }
        };
        let remaining_active: Vec<CpaAuthEntry> = remaining
            .into_iter()
            .filter(|entry| !is_disabled_entry(entry))
            .collect();

        match self
            .supplement_from_local(&client, requested, &remaining_active, &proxy_assignment)
            .await
        {
            Ok(summary) => {
                local_changed |= summary.local_changed;
                result.eligible = summary.eligible;
                result.supplemented = summary.done;
                result.supplemented_names = summary.names;
                result.errors.extend(summary.errors);
                if result.eligible < requested {
                    let message = if result.eligible == 0 {
                        "当前没有符合条件的正常区凭证可补充".to_string()
                    } else {
                        format!(
                            "当前仅有 {} 个符合条件的正常区账号，已按最大数量尝试补充",
                            result.eligible
                        )
                    };
                    self.log_best_effort(format!("[WARN] {message}"));
                    result.warnings.push(message);
                }
            }
            Err(err) => {
                let message = format!("手动补充凭证失败: {err:#}");
                self.log_best_effort(format!("[ERROR] {message}"));
                result.errors.push(message);
            }
        }

        if local_changed {
            self.backup.mark_dirty("cpa_manual_supplement");
            self.scheduler.wake();
        }

        recompute_manual_supplement_ok(&mut result);
        self.log_best_effort(format!(
            "[INFO] CPA manual supplement finished ok={} requested={} eligible={} supplemented={} warnings={} errors={}",
            result.ok,
            result.requested,
            result.eligible,
            result.supplemented,
            result.warnings.len(),
            result.errors.len()
        ));
        self.finish_manual_supplement_result(result)
    }

    fn finish_result(&self, mut result: InspectResult) -> InspectResult {
        if result.finished_at.is_empty() {
            result.finished_at = Utc::now().to_rfc3339();
        }
        if let Ok(mut guard) = self.last_result.lock() {
            *guard = Some(result.clone());
        }
        result
    }

    fn finish_reclaim_result(&self, mut result: ReclaimResult) -> ReclaimResult {
        if result.finished_at.is_empty() {
            result.finished_at = Utc::now().to_rfc3339();
        }
        result
    }

    fn finish_manual_supplement_result(
        &self,
        mut result: ManualSupplementResult,
    ) -> ManualSupplementResult {
        if result.finished_at.is_empty() {
            result.finished_at = Utc::now().to_rfc3339();
        }
        result
    }

    fn log_best_effort(&self, message: impl AsRef<str>) {
        let _ = self.cpa_log.write(message.as_ref());
    }

    async fn cleanup_disabled_residual(
        &self,
        client: &CpaClient,
        entry: &CpaAuthEntry,
    ) -> Result<()> {
        if !self.local_copy_exists(&entry.name)? {
            return Ok(());
        }
        client.delete_file(&entry.name).await?;
        self.log_best_effort(format!(
            "[INFO] deleted disabled CPA residual {} because local copy already exists",
            entry.name
        ));
        Ok(())
    }

    async fn move_from_cpa(
        &self,
        client: &CpaClient,
        entry: &CpaAuthEntry,
        target_zone: CredentialZone,
        resets_at: Option<String>,
        status_kind: ImportStatusKind,
    ) -> Result<MoveFromCpaOutcome> {
        let local_name = entry.name.trim().to_string();
        if local_name.is_empty() {
            return Ok(MoveFromCpaOutcome::skipped("CPA 文件名为空，已跳过"));
        }
        if self.local_copy_exists(&local_name)? {
            let message = format!("本地已存在同名凭证 {}，跳过 CPA 导入", local_name);
            self.log_best_effort(format!("[WARN] {message}"));
            return Ok(MoveFromCpaOutcome::skipped(message));
        }

        client.set_disabled(&entry.name, true).await?;
        self.log_best_effort(format!("[INFO] disabled CPA credential {}", entry.name));

        let bytes = match client.download_file(&entry.name).await {
            Ok(bytes) => bytes,
            Err(err) => {
                self.reenable_best_effort(client, &entry.name).await;
                return Err(err);
            }
        };
        let _credential = match validate_credential_bytes(&bytes, "CPA 返回的凭证") {
            Ok(credential) => credential,
            Err(err) => {
                self.reenable_best_effort(client, &entry.name).await;
                return Err(err);
            }
        };

        let activity_guard = self.write_coordinator.lock_activity().await;
        let generation = self.write_coordinator.generation();
        if let Err(err) = self.write_coordinator.ensure_writes_allowed() {
            drop(activity_guard);
            self.reenable_best_effort(client, &entry.name).await;
            return Err(err);
        }

        let commit_outcome = {
            let _commit_guard = self.write_coordinator.lock_commit().await;
            if let Err(err) = self.write_coordinator.ensure_generation_current(generation) {
                MoveImportCommitOutcome::Failed {
                    err,
                    should_reenable: false,
                }
            } else if let Err(err) = self.local_copy_exists(&local_name).and_then(|exists| {
                if exists {
                    anyhow::bail!("本地已存在同名凭证 {}", local_name);
                }
                Ok(())
            }) {
                MoveImportCommitOutcome::Failed {
                    err,
                    should_reenable: false,
                }
            } else if let Err(err) = self.store.write_bytes(target_zone, &local_name, &bytes) {
                MoveImportCommitOutcome::Failed {
                    err,
                    should_reenable: false,
                }
            } else {
                let status_result = match status_kind {
                    ImportStatusKind::Normal => {
                        self.status_store.restore_to_normal(&local_name).map(|_| ())
                    }
                    ImportStatusKind::NormalExhausted => self
                        .status_store
                        .set_cpa_exhausted(&local_name, resets_at.clone())
                        .map(|_| ()),
                    ImportStatusKind::Abnormal {
                        code,
                        default_reason,
                    } => self
                        .status_store
                        .record_failure(
                            &local_name,
                            CredentialZone::Normal.as_str(),
                            false,
                            true,
                            code,
                            cpa_failure_reason(entry, default_reason),
                        )
                        .map(|_| ()),
                };
                if let Err(err) = status_result {
                    MoveImportCommitOutcome::Failed {
                        err,
                        should_reenable: self.store.delete(target_zone, &local_name).is_ok(),
                    }
                } else {
                    MoveImportCommitOutcome::Success
                }
            }
        };

        if let MoveImportCommitOutcome::Failed {
            err,
            should_reenable,
        } = commit_outcome
        {
            drop(activity_guard);
            if should_reenable || !self.local_copy_exists(&local_name)? {
                self.reenable_best_effort(client, &entry.name).await;
            }
            return Err(err);
        }

        let delete_result = client.delete_file(&entry.name).await;
        drop(activity_guard);
        match delete_result {
            Ok(()) => {
                self.log_best_effort(format!(
                    "[INFO] moved CPA credential {} to local {} zone",
                    entry.name,
                    target_zone.as_str()
                ));
                Ok(MoveFromCpaOutcome {
                    moved: true,
                    local_changed: true,
                    message: None,
                })
            }
            Err(err) => {
                let message = format!(
                    "CPA 远端删除失败，已保留本地副本并等待下次清理 {}: {err:#}",
                    entry.name
                );
                self.log_best_effort(format!("[WARN] {message}"));
                Ok(MoveFromCpaOutcome {
                    moved: true,
                    local_changed: true,
                    message: Some(message),
                })
            }
        }
    }

    async fn supplement_from_local(
        &self,
        client: &CpaClient,
        need: usize,
        remaining_active: &[CpaAuthEntry],
        proxy_assignment: &SupplementProxyAssignment,
    ) -> Result<SupplementSummary> {
        let candidates = self.collect_supplement_candidates(remaining_active)?;
        let mut summary = SupplementSummary {
            eligible: count_supplement_candidate_accounts(&candidates),
            ..SupplementSummary::default()
        };
        // Only lock an email after one local copy succeeds, so a broken duplicate
        // does not block the next local copy for the same account.
        let mut selected_emails = HashSet::new();

        for candidate in candidates {
            if summary.done >= need {
                break;
            }
            if selected_emails.contains(&candidate.email) {
                continue;
            }
            let assigned_proxy_url = proxy_assignment.assigned_proxy(summary.done);
            match self
                .supplement_to_cpa(client, &candidate.key, assigned_proxy_url)
                .await
            {
                Ok(outcome) => {
                    summary.local_changed |= outcome.local_changed;
                    if outcome.done {
                        summary.done += 1;
                        summary.names.push(candidate.key.clone());
                        selected_emails.insert(candidate.email);
                    }
                    if let Some(message) = outcome.message {
                        summary.errors.push(message);
                    }
                }
                Err(err) => {
                    let message = format!("补号失败 {}: {err:#}", candidate.key);
                    self.log_best_effort(format!("[ERROR] {message}"));
                    summary.errors.push(message);
                }
            }
        }

        Ok(summary)
    }

    fn collect_supplement_candidates(
        &self,
        remaining_active: &[CpaAuthEntry],
    ) -> Result<Vec<SupplementCandidate>> {
        let entries = self.store.scan_zone(CredentialZone::Normal)?;
        let statuses = self.status_store.all()?;
        Ok(select_supplement_candidates(
            &entries,
            &statuses,
            remaining_active,
        ))
    }

    async fn supplement_to_cpa(
        &self,
        client: &CpaClient,
        local_key: &str,
        assigned_proxy_url: Option<&str>,
    ) -> Result<SupplementOutcome> {
        let activity_guard = self.write_coordinator.lock_activity().await;
        let generation = self.write_coordinator.generation();
        self.write_coordinator.ensure_writes_allowed()?;

        let bytes = self.store.read_bytes(CredentialZone::Normal, local_key)?;
        validate_credential_bytes(&bytes, "待补充的本地凭证")?;
        let upload_bytes = normalize_cpa_supplement_upload_bytes(&bytes, assigned_proxy_url)?;
        let remote_name = file_name_from_key(local_key);

        client.upload_file(&remote_name, &upload_bytes).await?;

        let commit_outcome = {
            let _commit_guard = self.write_coordinator.lock_commit().await;
            if let Err(err) = self.write_coordinator.ensure_generation_current(generation) {
                SupplementCommitOutcome::Failed {
                    err,
                    rollback_remote: true,
                }
            } else if let Err(err) = self.store.delete(CredentialZone::Normal, local_key) {
                SupplementCommitOutcome::Failed {
                    err,
                    rollback_remote: true,
                }
            } else {
                if let Err(err) = self.status_store.remove(local_key) {
                    self.log_best_effort(format!(
                        "[WARN] local status cleanup failed after CPA supplement {}: {err:#}",
                        local_key
                    ));
                }
                SupplementCommitOutcome::Success
            }
        };

        if let SupplementCommitOutcome::Failed {
            err,
            rollback_remote,
        } = commit_outcome
        {
            if rollback_remote {
                rollback_remote_best_effort(client, &remote_name, &self.cpa_log).await;
            }
            drop(activity_guard);
            return Err(err);
        }
        drop(activity_guard);

        self.log_best_effort(format!(
            "[INFO] supplemented local credential {} to CPA and removed local copy",
            local_key
        ));
        Ok(SupplementOutcome {
            done: true,
            local_changed: true,
            message: None,
        })
    }

    async fn reenable_best_effort(&self, client: &CpaClient, name: &str) {
        match client.set_disabled(name, false).await {
            Ok(()) => self.log_best_effort(format!(
                "[INFO] re-enabled CPA credential {} after local import rollback",
                name
            )),
            Err(err) => self.log_best_effort(format!(
                "[WARN] failed to re-enable CPA credential {} after rollback: {err:#}",
                name
            )),
        }
    }

    fn local_copy_exists(&self, key: &str) -> Result<bool> {
        Ok(self.local_key_exists(CredentialZone::Normal, key)?
            || self.local_key_exists(CredentialZone::Abnormal, key)?)
    }

    fn local_key_exists(&self, zone: CredentialZone, key: &str) -> Result<bool> {
        Ok(self.store.key_to_path(zone, key)?.exists())
    }
}

#[derive(Clone, Copy)]
enum ImportStatusKind {
    Normal,
    NormalExhausted,
    Abnormal {
        code: &'static str,
        default_reason: &'static str,
    },
}

impl ImportStatusKind {
    fn target_zone(self) -> CredentialZone {
        match self {
            Self::Normal | Self::NormalExhausted => CredentialZone::Normal,
            Self::Abnormal { .. } => CredentialZone::Abnormal,
        }
    }
}

struct RunningFlagGuard<'a> {
    flag: &'a AtomicBool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for RunningFlagGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct SupplementSummary {
    eligible: usize,
    done: usize,
    names: Vec<String>,
    errors: Vec<String>,
    local_changed: bool,
}

struct SupplementProxyAssignment {
    enabled: bool,
    proxies: Vec<String>,
}

impl SupplementProxyAssignment {
    fn from_config(cfg: &CpaConfig) -> Result<Self> {
        Ok(Self {
            enabled: cfg.auto_assign_proxy_enabled,
            proxies: validate_cpa_proxy_list(&cfg.proxy_list)?,
        })
    }

    fn assigned_proxy(&self, done: usize) -> Option<&str> {
        if !self.enabled || self.proxies.is_empty() {
            return None;
        }
        self.proxies
            .get(done % self.proxies.len())
            .map(String::as_str)
    }
}

struct MoveFromCpaOutcome {
    moved: bool,
    local_changed: bool,
    message: Option<String>,
}

impl MoveFromCpaOutcome {
    fn skipped(message: impl Into<String>) -> Self {
        Self {
            moved: false,
            local_changed: false,
            message: Some(message.into()),
        }
    }
}

struct SupplementOutcome {
    done: bool,
    local_changed: bool,
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupplementCandidate {
    key: String,
    email: String,
}

enum MoveImportCommitOutcome {
    Success,
    Failed {
        err: anyhow::Error,
        should_reenable: bool,
    },
}

enum SupplementCommitOutcome {
    Success,
    Failed {
        err: anyhow::Error,
        rollback_remote: bool,
    },
}

fn is_unauthorized_entry(entry: &CpaAuthEntry) -> bool {
    let status = entry.status.trim().to_ascii_lowercase();
    let status_message = entry.status_message.trim().to_ascii_lowercase();
    status == "error"
        && (status_message.contains("unauthorized")
            || status_message.contains("account_deactivated")
            || contains_status_code(&status_message, 401))
}

fn is_exhausted_entry(entry: &CpaAuthEntry) -> bool {
    let status = entry.status.trim().to_ascii_lowercase();
    status == "error" && status_message_indicates_exhausted(&entry.status_message)
}

fn exhausted_resets_at(entry: &CpaAuthEntry, now: chrono::DateTime<Utc>) -> Option<String> {
    entry
        .next_retry_after
        .clone()
        .or_else(|| parse_status_message_resets_at(&entry.status_message, now))
}

fn status_message_indicates_exhausted(status_message: &str) -> bool {
    let status_message_lower = status_message.trim().to_ascii_lowercase();
    if status_message_lower.contains("quota exhausted")
        || status_message_lower.contains("usage limit has been reached")
    {
        return true;
    }
    if status_message_error_type(status_message).as_deref() == Some("usage_limit_reached") {
        return true;
    }
    false
}

fn parse_status_message_resets_at(
    status_message: &str,
    now: chrono::DateTime<Utc>,
) -> Option<String> {
    let error = parse_status_message_error(status_message)?;
    if let Some(resets_at) =
        json_i64(error.get("resets_at")).filter(|value| *value > now.timestamp())
    {
        return chrono::DateTime::<Utc>::from_timestamp(resets_at, 0)
            .map(|value| value.to_rfc3339());
    }
    let resets_in_seconds = json_i64(error.get("resets_in_seconds")).filter(|value| *value > 0)?;
    Some((now + ChronoDuration::seconds(resets_in_seconds)).to_rfc3339())
}

fn status_message_error_type(status_message: &str) -> Option<String> {
    parse_status_message_error(status_message)?
        .get("type")?
        .as_str()
        .map(|value| value.trim().to_ascii_lowercase())
}

fn parse_status_message_error(status_message: &str) -> Option<Value> {
    let parsed: Value = serde_json::from_str(status_message.trim()).ok()?;
    parsed
        .get("error")
        .cloned()
        .or_else(|| parsed.pointer("/body/error").cloned())
}

fn json_i64(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(number) => number.as_i64(),
        Value::String(value) => value.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn is_disabled_entry(entry: &CpaAuthEntry) -> bool {
    entry.disabled || entry.status.trim().eq_ignore_ascii_case("disabled")
}

fn is_payment_required_entry(entry: &CpaAuthEntry) -> bool {
    let status = entry.status.trim().to_ascii_lowercase();
    let status_message = entry.status_message.trim().to_ascii_lowercase();
    status == "error"
        && (status_message.contains("payment_required")
            || contains_status_code(&status_message, 402)
            || contains_status_code(&status_message, 403))
}

fn is_not_found_entry(entry: &CpaAuthEntry) -> bool {
    let status = entry.status.trim().to_ascii_lowercase();
    let status_message = entry.status_message.trim().to_ascii_lowercase();
    status == "error"
        && (status_message.contains("not_found") || contains_status_code(&status_message, 404))
}

fn classify_reclaim_import(entry: &CpaAuthEntry) -> ImportStatusKind {
    if is_exhausted_entry(entry) {
        return ImportStatusKind::NormalExhausted;
    }
    if is_disabled_entry(entry) {
        return ImportStatusKind::Abnormal {
            code: "cpa_disabled",
            default_reason: "disabled via management API",
        };
    }
    if is_unauthorized_entry(entry) {
        return ImportStatusKind::Abnormal {
            code: "cpa_unauthorized",
            default_reason: "unauthorized",
        };
    }
    if is_payment_required_entry(entry) {
        return ImportStatusKind::Abnormal {
            code: "cpa_payment_required",
            default_reason: "payment_required",
        };
    }
    if is_not_found_entry(entry) {
        return ImportStatusKind::Abnormal {
            code: "cpa_not_found",
            default_reason: "not_found",
        };
    }
    if entry.status.trim().eq_ignore_ascii_case("error") || entry.unavailable {
        return ImportStatusKind::Abnormal {
            code: "cpa_error",
            default_reason: "request failed",
        };
    }
    ImportStatusKind::Normal
}

fn contains_status_code(status_message: &str, code: u16) -> bool {
    let compact: String = status_message
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    compact.contains(&format!("\"status\":{code}"))
}

fn recompute_ok(result: &mut InspectResult) {
    result.ok = result.error.is_none() && result.errors.is_empty();
}

fn recompute_reclaim_ok(result: &mut ReclaimResult) {
    result.ok = result.error.is_none() && result.errors.is_empty();
}

fn recompute_manual_supplement_ok(result: &mut ManualSupplementResult) {
    result.ok = result.error.is_none() && result.errors.is_empty();
}

fn cpa_failure_reason(entry: &CpaAuthEntry, default_reason: &str) -> String {
    let trimmed = entry.status_message.trim();
    if trimmed.is_empty() {
        default_reason.to_string()
    } else {
        trimmed.to_string()
    }
}

fn validate_credential_bytes(bytes: &[u8], source_label: &str) -> Result<CodexCredentialFile> {
    let credential: CodexCredentialFile =
        serde_json::from_slice(bytes).with_context(|| format!("{source_label}不是有效 JSON"))?;
    if !credential.is_codex() {
        anyhow::bail!("{source_label} type 不是 codex");
    }
    if credential.refresh_token.trim().is_empty() {
        anyhow::bail!("{source_label}缺少 refresh_token");
    }
    Ok(credential)
}

fn normalize_cpa_supplement_upload_bytes(
    bytes: &[u8],
    assigned_proxy_url: Option<&str>,
) -> Result<Vec<u8>> {
    let mut value: Value =
        serde_json::from_slice(bytes).context("待补充的本地凭证不是有效 JSON")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("待补充的本地凭证必须是 JSON 对象"))?;
    if object.get("disabled") == Some(&Value::Bool(true)) {
        object.insert("disabled".to_string(), Value::Bool(false));
    }
    object.remove("disabled_until");
    if let Some(proxy_url) = assigned_proxy_url {
        object.insert(
            "proxy_url".to_string(),
            Value::String(proxy_url.to_string()),
        );
    }
    serde_json::to_vec(&value).context("failed to serialize CPA supplement upload JSON")
}

fn select_supplement_candidates(
    entries: &[CredentialEntry],
    statuses: &BTreeMap<String, CredentialStatusRecord>,
    remaining_active: &[CpaAuthEntry],
) -> Vec<SupplementCandidate> {
    let occupied_emails: HashSet<String> = remaining_active
        .iter()
        .filter_map(|entry| normalize_email(entry.email.as_deref()))
        .collect();
    let mut selected = Vec::new();

    for entry in entries {
        let Some(credential) = entry.credential.as_ref() else {
            continue;
        };
        if entry.parse_error.is_some() || credential.refresh_token.trim().is_empty() {
            continue;
        }
        let Some(email) = normalize_email(credential.email.as_deref()) else {
            continue;
        };
        let status_key = normalize_status_key(&entry.key);
        if statuses
            .get(&status_key)
            .and_then(|record| record.cpa_exhausted)
            .unwrap_or(false)
        {
            continue;
        }
        if occupied_emails.contains(&email) {
            continue;
        }
        selected.push(SupplementCandidate {
            key: entry.key.clone(),
            email,
        });
    }

    selected
}

fn count_supplement_candidate_accounts(candidates: &[SupplementCandidate]) -> usize {
    candidates
        .iter()
        .map(|candidate| candidate.email.as_str())
        .collect::<HashSet<_>>()
        .len()
}

fn normalize_email(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn file_name_from_key(key: &str) -> String {
    Path::new(key)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(key)
        .to_string()
}

async fn rollback_remote_best_effort(client: &CpaClient, remote_name: &str, cpa_log: &CpaLog) {
    if let Err(err) = client.delete_file(remote_name).await {
        let _ = cpa_log.write(&format!(
            "[ERROR] failed to rollback CPA upload {}: {err:#}",
            remote_name
        ));
    } else {
        let _ = cpa_log.write(&format!(
            "[INFO] rolled back CPA upload {} after local commit failure",
            remote_name
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn classifies_unauthorized_entries() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "Unauthorized".to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(is_unauthorized_entry(&entry));
        assert!(!is_exhausted_entry(&entry));
    }

    #[test]
    fn exhausted_reset_fallback_matches_monthly_quota_window() {
        assert_eq!(EXHAUSTED_RESET_FALLBACK_HOURS, 721);
    }

    #[test]
    fn classifies_json_401_entries() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "{\"error\":{\"code\":\"account_deactivated\"},\"status\":401}"
                .to_string(),
            disabled: false,
            unavailable: true,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(is_unauthorized_entry(&entry));
        assert!(!is_exhausted_entry(&entry));
    }

    #[test]
    fn classifies_exhausted_entries() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "quota exhausted".to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(is_exhausted_entry(&entry));
    }

    #[test]
    fn classifies_usage_limit_reached_entries_as_exhausted() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: r#"{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_at":1893456000,"resets_in_seconds":60}}"#.to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        let now = parse_rfc3339("2029-12-31T23:00:00Z").unwrap();
        assert!(is_exhausted_entry(&entry));
        assert_eq!(
            exhausted_resets_at(&entry, now).as_deref(),
            Some("2030-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn classifies_usage_limit_type_without_message_as_exhausted() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: r#"{"error":{"type":"usage_limit_reached"}}"#.to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(is_exhausted_entry(&entry));
    }

    #[test]
    fn plain_usage_limit_token_is_not_enough_to_mark_exhausted() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "usage_limit_reached".to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(!is_exhausted_entry(&entry));
    }

    #[test]
    fn parses_wrapped_usage_limit_resets_in_seconds() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: r#"{"status":429,"body":{"error":{"type":"usage_limit_reached","message":"usage limit reached","resets_in_seconds":"7"}}}"#.to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        let now = parse_rfc3339("2030-01-01T00:00:00Z").unwrap();

        assert!(is_exhausted_entry(&entry));
        assert_eq!(
            parse_status_message_resets_at(&entry.status_message, now).as_deref(),
            Some("2030-01-01T00:00:07+00:00")
        );
    }

    #[test]
    fn expired_status_message_resets_at_falls_back_to_resets_in_seconds() {
        let now = parse_rfc3339("2030-01-01T00:00:00Z").unwrap();
        let status_message =
            r#"{"error":{"type":"usage_limit_reached","resets_at":1,"resets_in_seconds":9}}"#;

        assert_eq!(
            parse_status_message_resets_at(status_message, now).as_deref(),
            Some("2030-01-01T00:00:09+00:00")
        );
    }

    #[test]
    fn prefers_cpa_next_retry_after_over_raw_status_message_reset() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: r#"{"error":{"type":"usage_limit_reached","resets_at":1893456000}}"#
                .to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: Some("2030-02-01T00:00:00Z".to_string()),
        };

        assert_eq!(
            exhausted_resets_at(&entry, Utc::now()).as_deref(),
            Some("2030-02-01T00:00:00Z")
        );
    }

    #[test]
    fn classifies_disabled_reclaim_entries_as_abnormal() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "disabled".to_string(),
            status_message: "disabled via management API".to_string(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(matches!(
            classify_reclaim_import(&entry),
            ImportStatusKind::Abnormal {
                code: "cpa_disabled",
                ..
            }
        ));
        assert!(is_disabled_entry(&entry));
    }

    #[test]
    fn classifies_payment_required_reclaim_entries_as_abnormal() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "payment_required".to_string(),
            disabled: false,
            unavailable: true,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(matches!(
            classify_reclaim_import(&entry),
            ImportStatusKind::Abnormal {
                code: "cpa_payment_required",
                ..
            }
        ));
    }

    #[test]
    fn classifies_not_found_reclaim_entries_as_abnormal() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "not_found".to_string(),
            disabled: false,
            unavailable: true,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(matches!(
            classify_reclaim_import(&entry),
            ImportStatusKind::Abnormal {
                code: "cpa_not_found",
                ..
            }
        ));
    }

    #[test]
    fn classifies_active_reclaim_entries_as_normal() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "active".to_string(),
            status_message: String::new(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(matches!(
            classify_reclaim_import(&entry),
            ImportStatusKind::Normal
        ));
    }

    #[test]
    fn classifies_transient_error_reclaim_entries_as_abnormal() {
        let entry = CpaAuthEntry {
            name: "a.json".to_string(),
            email: None,
            status: "error".to_string(),
            status_message: "transient upstream error".to_string(),
            disabled: false,
            unavailable: true,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        };
        assert!(matches!(
            classify_reclaim_import(&entry),
            ImportStatusKind::Abnormal {
                code: "cpa_error",
                ..
            }
        ));
    }

    #[test]
    fn inspect_result_with_warning_stays_ok() {
        let mut result = InspectResult {
            warnings: vec!["warn".to_string()],
            ..InspectResult::default()
        };
        recompute_ok(&mut result);
        assert!(result.ok);
    }

    #[test]
    fn reclaim_result_with_error_becomes_failed() {
        let mut result = ReclaimResult {
            errors: vec!["err".to_string()],
            ..ReclaimResult::default()
        };
        recompute_reclaim_ok(&mut result);
        assert!(!result.ok);
    }

    #[test]
    fn inspect_result_with_error_becomes_failed() {
        let mut result = InspectResult {
            errors: vec!["err".to_string()],
            ..InspectResult::default()
        };
        recompute_ok(&mut result);
        assert!(!result.ok);
    }

    #[test]
    fn file_name_is_extracted_from_key() {
        assert_eq!(file_name_from_key("nested/user.json"), "user.json");
    }

    #[test]
    fn normalize_email_lowercases() {
        assert_eq!(
            normalize_email(Some(" User@Example.com ")).as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn supplement_upload_normalization_enables_disabled_credential() {
        let raw = serde_json::json!({
            "type": "codex",
            "refresh_token": "refresh",
            "disabled": true,
            "disabled_until": "2030-01-01T00:00:00Z"
        });

        let normalized = normalize_upload_json(&raw, None);

        assert_eq!(normalized.get("disabled"), Some(&Value::Bool(false)));
        assert!(normalized.get("disabled_until").is_none());
    }

    #[test]
    fn supplement_upload_normalization_keeps_disabled_false() {
        let raw = serde_json::json!({
            "type": "codex",
            "refresh_token": "refresh",
            "disabled": false
        });

        let normalized = normalize_upload_json(&raw, None);

        assert_eq!(normalized.get("disabled"), Some(&Value::Bool(false)));
    }

    #[test]
    fn supplement_upload_normalization_does_not_add_missing_disabled() {
        let raw = serde_json::json!({
            "type": "codex",
            "refresh_token": "refresh"
        });

        let normalized = normalize_upload_json(&raw, None);

        assert!(normalized.get("disabled").is_none());
    }

    #[test]
    fn supplement_upload_normalization_rejects_non_object_json() {
        let raw = serde_json::to_vec(&serde_json::json!(["not-object"])).unwrap();

        assert!(normalize_cpa_supplement_upload_bytes(&raw, None).is_err());
    }

    #[test]
    fn supplement_upload_normalization_writes_assigned_proxy_url() {
        let raw = serde_json::json!({
            "type": "codex",
            "refresh_token": "refresh"
        });

        let normalized = normalize_upload_json(&raw, Some("socks5h://127.0.0.1:10808"));

        assert_eq!(
            normalized.get("proxy_url").and_then(Value::as_str),
            Some("socks5h://127.0.0.1:10808")
        );
    }

    #[test]
    fn supplement_upload_normalization_preserves_existing_proxy_without_assignment() {
        let raw = serde_json::json!({
            "type": "codex",
            "refresh_token": "refresh",
            "proxy_url": "https://proxy.example.com"
        });

        let normalized = normalize_upload_json(&raw, None);

        assert_eq!(
            normalized.get("proxy_url").and_then(Value::as_str),
            Some("https://proxy.example.com")
        );
    }

    #[test]
    fn supplement_proxy_assignment_disabled_or_empty_returns_none() {
        let disabled = SupplementProxyAssignment {
            enabled: false,
            proxies: vec!["socks5h://127.0.0.1:10808".to_string()],
        };
        let empty = SupplementProxyAssignment {
            enabled: true,
            proxies: Vec::new(),
        };

        assert_eq!(disabled.assigned_proxy(0), None);
        assert_eq!(empty.assigned_proxy(0), None);
    }

    #[test]
    fn supplement_proxy_assignment_reuses_single_proxy() {
        let assignment = SupplementProxyAssignment {
            enabled: true,
            proxies: vec!["socks5h://127.0.0.1:10808".to_string()],
        };

        assert_eq!(
            (0..3)
                .map(|done| assignment.assigned_proxy(done).unwrap())
                .collect::<Vec<_>>(),
            vec![
                "socks5h://127.0.0.1:10808",
                "socks5h://127.0.0.1:10808",
                "socks5h://127.0.0.1:10808"
            ]
        );
    }

    #[test]
    fn supplement_proxy_assignment_round_robins_by_success_count() {
        let assignment = SupplementProxyAssignment {
            enabled: true,
            proxies: vec![
                "socks5h://us1:1080".to_string(),
                "socks5h://jp1:1080".to_string(),
                "socks5h://sg1:1080".to_string(),
            ],
        };

        assert_eq!(
            (0..4)
                .map(|done| assignment.assigned_proxy(done).unwrap())
                .collect::<Vec<_>>(),
            vec![
                "socks5h://us1:1080",
                "socks5h://jp1:1080",
                "socks5h://sg1:1080",
                "socks5h://us1:1080"
            ]
        );
    }

    #[test]
    fn supplement_candidates_keep_same_email_fallbacks_and_count_unique_accounts() {
        let entries = vec![
            make_entry(
                "available-a.json",
                Some("available-a@example.com"),
                Some("refresh-a"),
            ),
            make_entry(
                "duplicate-a.json",
                Some("available-a@example.com"),
                Some("refresh-b"),
            ),
            make_entry("on-cpa.json", Some("on-cpa@example.com"), Some("refresh-c")),
            make_entry(
                "exhausted.json",
                Some("exhausted@example.com"),
                Some("refresh-d"),
            ),
            make_entry(
                "missing-refresh.json",
                Some("missing@example.com"),
                Some(""),
            ),
            make_entry("missing-email.json", None, Some("refresh-e")),
            make_parse_error_entry("broken.json"),
            make_entry(
                "available-b.json",
                Some("available-b@example.com"),
                Some("refresh-f"),
            ),
        ];
        let mut exhausted_status = CredentialStatusRecord::default();
        exhausted_status.cpa_exhausted = Some(true);
        let statuses = BTreeMap::from([(normalize_status_key("exhausted.json"), exhausted_status)]);
        let remaining_active = vec![CpaAuthEntry {
            name: "remote.json".to_string(),
            email: Some("on-cpa@example.com".to_string()),
            status: "active".to_string(),
            status_message: String::new(),
            disabled: false,
            unavailable: false,
            source: "file".to_string(),
            runtime_only: false,
            next_retry_after: None,
        }];

        let selected = select_supplement_candidates(&entries, &statuses, &remaining_active);

        assert_eq!(
            selected,
            vec![
                SupplementCandidate {
                    key: "available-a.json".to_string(),
                    email: "available-a@example.com".to_string(),
                },
                SupplementCandidate {
                    key: "duplicate-a.json".to_string(),
                    email: "available-a@example.com".to_string(),
                },
                SupplementCandidate {
                    key: "available-b.json".to_string(),
                    email: "available-b@example.com".to_string(),
                },
            ]
        );
        assert_eq!(count_supplement_candidate_accounts(&selected), 2);
    }

    fn normalize_upload_json(raw: &Value, assigned_proxy_url: Option<&str>) -> Value {
        let bytes = serde_json::to_vec(raw).unwrap();
        serde_json::from_slice(
            &normalize_cpa_supplement_upload_bytes(&bytes, assigned_proxy_url).unwrap(),
        )
        .unwrap()
    }

    fn make_entry(key: &str, email: Option<&str>, refresh_token: Option<&str>) -> CredentialEntry {
        CredentialEntry {
            zone: CredentialZone::Normal,
            key: key.to_string(),
            path: PathBuf::from(key),
            credential: Some(CodexCredentialFile {
                provider_type: "codex".to_string(),
                email: email.map(str::to_string),
                refresh_token: refresh_token.unwrap_or_default().to_string(),
                ..CodexCredentialFile::default()
            }),
            parse_error: None,
        }
    }

    fn make_parse_error_entry(key: &str) -> CredentialEntry {
        CredentialEntry {
            zone: CredentialZone::Normal,
            key: key.to_string(),
            path: PathBuf::from(key),
            credential: None,
            parse_error: Some("invalid json".to_string()),
        }
    }
}
