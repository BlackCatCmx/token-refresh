use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use tokio::sync::{Notify, RwLock};

use crate::cpa_config::CpaConfigStore;
use crate::cpa_manager::CpaManager;
use crate::credential::parse_rfc3339;

#[derive(Clone, Debug, Default, Serialize)]
pub struct CpaSchedulerStatus {
    pub enabled: bool,
    pub running: bool,
    pub last_started_at: Option<String>,
    pub last_finished_at: Option<String>,
    pub next_wake_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct CpaSchedulerHandle {
    manager: Arc<CpaManager>,
    config_store: Arc<CpaConfigStore>,
    notify: Arc<Notify>,
    status: Arc<RwLock<CpaSchedulerStatus>>,
    last_auto_finished_at: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl CpaSchedulerHandle {
    pub fn start(manager: Arc<CpaManager>, config_store: Arc<CpaConfigStore>) -> Self {
        let handle = Self {
            manager,
            config_store,
            notify: Arc::new(Notify::new()),
            status: Arc::new(RwLock::new(CpaSchedulerStatus::default())),
            last_auto_finished_at: Arc::new(RwLock::new(None)),
        };
        let runtime = handle.clone();
        tokio::spawn(async move {
            runtime.background_loop().await;
        });
        handle
    }

    pub fn wake(&self) {
        self.notify.notify_waiters();
    }

    pub async fn status(&self) -> CpaSchedulerStatus {
        let mut status = self.status.read().await.clone();
        status.running = self.manager.is_running();
        status
    }

    async fn background_loop(self) {
        loop {
            if let Err(err) = self.tick().await {
                let mut status = self.status.write().await;
                status.last_error = Some(err.to_string());
                drop(status);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = self.notify.notified() => {}
                }
            }
        }
    }

    async fn tick(&self) -> Result<()> {
        self.manager.clear_due_exhausted()?;
        let config = self.config_store.get();
        {
            let mut status = self.status.write().await;
            status.enabled = config.enabled;
        }
        if !config.enabled {
            let mut status = self.status.write().await;
            status.next_wake_at = None;
            status.running = self.manager.is_running();
            drop(status);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                _ = self.notify.notified() => {}
            }
            return Ok(());
        }

        let now = Utc::now();
        let last_auto_finished = *self.last_auto_finished_at.read().await;
        let next_wake_at = last_auto_finished
            .map(|finished_at| {
                finished_at + ChronoDuration::minutes(config.inspect_interval_minutes as i64)
            })
            .unwrap_or(now);
        {
            let mut status = self.status.write().await;
            status.next_wake_at = Some(next_wake_at.to_rfc3339());
            status.running = self.manager.is_running();
        }
        if now < next_wake_at {
            let wait_duration = (next_wake_at - now)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(1))
                .max(Duration::from_secs(1));
            tokio::select! {
                _ = tokio::time::sleep(wait_duration) => {}
                _ = self.notify.notified() => {}
            }
            return Ok(());
        }

        {
            let mut status = self.status.write().await;
            status.running = true;
            status.last_started_at = Some(now.to_rfc3339());
            status.last_error = None;
        }
        let result = self.manager.inspect_once(&config).await;
        let finished_at = parse_rfc3339(&result.finished_at).unwrap_or_else(Utc::now);
        {
            let mut last_auto_finished = self.last_auto_finished_at.write().await;
            *last_auto_finished = Some(finished_at);
        }
        let mut status = self.status.write().await;
        status.running = self.manager.is_running();
        status.last_finished_at = Some(result.finished_at.clone());
        status.next_wake_at = Some(
            (finished_at + ChronoDuration::minutes(config.inspect_interval_minutes as i64))
                .to_rfc3339(),
        );
        status.last_error = if result.ok {
            None
        } else {
            result
                .error
                .clone()
                .or_else(|| result.errors.first().cloned())
        };
        Ok(())
    }
}
