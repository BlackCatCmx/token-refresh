use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::fsutil;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CredentialStatusRecord {
    #[serde(default = "default_zone")]
    pub zone: String,
    #[serde(default)]
    pub consecutive_failure_count: u32,
    #[serde(default)]
    pub last_failure_code: Option<String>,
    #[serde(default)]
    pub last_failure_reason: Option<String>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    #[serde(default)]
    pub moved_to_abnormal_at: Option<String>,
    #[serde(default)]
    pub last_success_at: Option<String>,
    #[serde(default)]
    pub cpa_exhausted: Option<bool>,
    #[serde(default)]
    pub cpa_imported_at: Option<String>,
    #[serde(default)]
    pub exhausted_resets_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExhaustedPendingReset {
    pub key: String,
    pub cpa_imported_at: Option<String>,
    pub exhausted_resets_at: Option<String>,
}

#[derive(Debug)]
pub struct CredentialStatusStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, CredentialStatusRecord>>,
}

impl CredentialStatusStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let records = if path.exists() {
            let raw = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            if raw.is_empty() {
                BTreeMap::new()
            } else {
                serde_json::from_slice::<BTreeMap<String, CredentialStatusRecord>>(&raw)
                    .with_context(|| format!("invalid status file {}", path.display()))?
            }
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            records: Mutex::new(records),
        })
    }

    pub fn all(&self) -> Result<BTreeMap<String, CredentialStatusRecord>> {
        let guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        Ok(guard.clone())
    }

    pub fn get(&self, key: &str) -> Result<Option<CredentialStatusRecord>> {
        let guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        Ok(guard.get(&normalize_status_key(key)).cloned())
    }

    pub fn record_failure(
        &self,
        key: &str,
        zone: &str,
        count_towards_abnormal: bool,
        moved_to_abnormal: bool,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<CredentialStatusRecord> {
        let code = code.into();
        let reason = reason.into();
        let now = Utc::now().to_rfc3339();
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        let record = guard.entry(normalize_status_key(key)).or_default();
        record.zone = if moved_to_abnormal {
            "abnormal".to_string()
        } else {
            zone.to_string()
        };
        if count_towards_abnormal {
            record.consecutive_failure_count = record.consecutive_failure_count.saturating_add(1);
        }
        record.last_failure_code = Some(code);
        record.last_failure_reason = Some(reason);
        record.last_failure_at = Some(now.clone());
        if moved_to_abnormal {
            record.moved_to_abnormal_at = Some(now);
            clear_cpa_flags(record);
        }
        let snapshot = record.clone();
        let _ = record;
        persist_locked(&self.path, &guard)?;
        Ok(snapshot)
    }

    pub fn record_success(&self, key: &str, zone: &str) -> Result<CredentialStatusRecord> {
        let now = Utc::now().to_rfc3339();
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        let record = guard.entry(normalize_status_key(key)).or_default();
        record.zone = zone.to_string();
        record.consecutive_failure_count = 0;
        record.last_failure_code = None;
        record.last_failure_reason = None;
        record.last_failure_at = None;
        record.moved_to_abnormal_at = None;
        record.last_success_at = Some(now);
        let snapshot = record.clone();
        let _ = record;
        persist_locked(&self.path, &guard)?;
        Ok(snapshot)
    }

    pub fn restore_to_normal(&self, key: &str) -> Result<CredentialStatusRecord> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        let record = guard.entry(normalize_status_key(key)).or_default();
        record.zone = "normal".to_string();
        record.consecutive_failure_count = 0;
        record.last_failure_code = None;
        record.last_failure_reason = None;
        record.last_failure_at = None;
        record.moved_to_abnormal_at = None;
        clear_cpa_flags(record);
        let snapshot = record.clone();
        let _ = record;
        persist_locked(&self.path, &guard)?;
        Ok(snapshot)
    }

    pub fn set_cpa_exhausted(
        &self,
        key: &str,
        resets_at: Option<String>,
    ) -> Result<CredentialStatusRecord> {
        let now = Utc::now().to_rfc3339();
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        let record = guard.entry(normalize_status_key(key)).or_default();
        record.zone = "normal".to_string();
        record.consecutive_failure_count = 0;
        record.last_failure_code = None;
        record.last_failure_reason = None;
        record.last_failure_at = None;
        record.moved_to_abnormal_at = None;
        record.cpa_exhausted = Some(true);
        record.cpa_imported_at = Some(now);
        record.exhausted_resets_at = normalize_optional_text(resets_at);
        let snapshot = record.clone();
        let _ = record;
        persist_locked(&self.path, &guard)?;
        Ok(snapshot)
    }

    pub fn clear_cpa_exhausted(&self, key: &str) -> Result<CredentialStatusRecord> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        let record = guard.entry(normalize_status_key(key)).or_default();
        clear_cpa_flags(record);
        let snapshot = record.clone();
        let _ = record;
        persist_locked(&self.path, &guard)?;
        Ok(snapshot)
    }

    pub fn list_exhausted_pending_reset(&self) -> Result<Vec<ExhaustedPendingReset>> {
        let guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        Ok(guard
            .iter()
            .filter(|(_, record)| record.cpa_exhausted.unwrap_or(false))
            .map(|(key, record)| ExhaustedPendingReset {
                key: key.clone(),
                cpa_imported_at: record.cpa_imported_at.clone(),
                exhausted_resets_at: record.exhausted_resets_at.clone(),
            })
            .collect())
    }

    pub fn remove(&self, key: &str) -> Result<()> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        guard.remove(&normalize_status_key(key));
        persist_locked(&self.path, &guard)
    }

    pub fn replace_all(&self, records: BTreeMap<String, CredentialStatusRecord>) -> Result<()> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("status store lock poisoned"))?;
        *guard = records
            .into_iter()
            .map(|(key, value)| (normalize_status_key(&key), value))
            .collect();
        persist_locked(&self.path, &guard)
    }
}

pub fn normalize_status_key(key: &str) -> String {
    #[cfg(windows)]
    {
        key.replace('\\', "/").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        key.replace('\\', "/")
    }
}

fn persist_locked(path: &Path, records: &BTreeMap<String, CredentialStatusRecord>) -> Result<()> {
    fsutil::atomic_write_json(path, records)
}

fn default_zone() -> String {
    "normal".to_string()
}

fn clear_cpa_flags(record: &mut CredentialStatusRecord) {
    record.cpa_exhausted = None;
    record.cpa_imported_at = None;
    record.exhausted_resets_at = None;
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_success_preserves_cpa_exhausted_flags() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStatusStore::load(temp.path().join("status.json")).unwrap();
        store
            .set_cpa_exhausted("user.json", Some("2026-07-08T12:00:00Z".to_string()))
            .unwrap();

        let record = store.record_success("user.json", "normal").unwrap();

        assert_eq!(record.consecutive_failure_count, 0);
        assert_eq!(record.last_failure_code, None);
        assert_eq!(record.cpa_exhausted, Some(true));
        assert!(record.cpa_imported_at.is_some());
        assert_eq!(
            record.exhausted_resets_at.as_deref(),
            Some("2026-07-08T12:00:00Z")
        );
    }
}
