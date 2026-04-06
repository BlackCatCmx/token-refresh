use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Result, bail};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Clone, Debug)]
pub struct WriteCoordinator {
    commit_lock: Arc<Mutex<()>>,
    restore_active: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
}

impl Default for WriteCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteCoordinator {
    pub fn new() -> Self {
        Self {
            commit_lock: Arc::new(Mutex::new(())),
            restore_active: Arc::new(AtomicBool::new(false)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn ensure_writes_allowed(&self) -> Result<()> {
        if self.restore_active.load(Ordering::SeqCst) {
            bail!("正在从备份还原，请稍后重试");
        }
        Ok(())
    }

    pub fn begin_restore(&self) -> Result<RestoreFreezeGuard> {
        if self
            .restore_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            bail!("当前已有备份还原任务在执行");
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(RestoreFreezeGuard {
            coordinator: self.clone(),
            active: true,
        })
    }

    pub async fn lock_commit(&self) -> OwnedMutexGuard<()> {
        self.commit_lock.clone().lock_owned().await
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn ensure_generation_current(&self, generation: u64) -> Result<()> {
        self.ensure_writes_allowed()?;
        if self.generation.load(Ordering::SeqCst) != generation {
            bail!("本地数据已在备份还原期间被切换，本次写入结果已丢弃");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RestoreFreezeGuard {
    coordinator: WriteCoordinator,
    active: bool,
}

impl Drop for RestoreFreezeGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.coordinator
            .restore_active
            .store(false, Ordering::SeqCst);
        self.active = false;
    }
}
