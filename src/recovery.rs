use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::credential::CodexCredentialFile;
use crate::fsutil;
use crate::logging::LogManager;

pub const RECOVERY_SUFFIX: &str = ".refresh-recovery.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub target_file_name: String,
    pub written_at: String,
    pub credential: CodexCredentialFile,
}

pub fn recovery_path_for(target_path: &Path) -> Result<PathBuf> {
    let file_name = target_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("credential file name is invalid")?;
    Ok(target_path.with_file_name(format!("{file_name}{RECOVERY_SUFFIX}")))
}

pub fn write_recovery(target_path: &Path, credential: &CodexCredentialFile) -> Result<PathBuf> {
    let recovery_path = recovery_path_for(target_path)?;
    let record = RecoveryRecord {
        target_file_name: target_path
            .file_name()
            .and_then(|value| value.to_str())
            .context("credential file name is invalid")?
            .to_string(),
        written_at: Utc::now().to_rfc3339(),
        credential: credential.clone(),
    };
    fsutil::atomic_write_json(&recovery_path, &record)?;
    Ok(recovery_path)
}

pub fn delete_recovery(target_path: &Path) -> Result<()> {
    let recovery_path = recovery_path_for(target_path)?;
    if recovery_path.exists() {
        std::fs::remove_file(&recovery_path)
            .with_context(|| format!("failed to delete {}", recovery_path.display()))?;
    }
    Ok(())
}

pub fn is_recovery_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(RECOVERY_SUFFIX))
        .unwrap_or(false)
}

pub fn recover_all(directories: &[PathBuf], logger: &LogManager) -> Result<()> {
    for directory in directories {
        if !directory.exists() {
            continue;
        }
        for entry in WalkDir::new(directory)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() || !is_recovery_file(entry.path()) {
                continue;
            }
            if let Err(err) = recover_one(entry.path(), logger) {
                let _ = logger.runtime(
                    "error",
                    format!("recovery failed for {}: {err:#}", entry.path().display()),
                );
            }
        }
    }
    Ok(())
}

fn recover_one(recovery_path: &Path, logger: &LogManager) -> Result<()> {
    let record_bytes = std::fs::read(recovery_path)
        .with_context(|| format!("failed to read recovery file {}", recovery_path.display()))?;
    let record: RecoveryRecord = serde_json::from_slice(&record_bytes)
        .with_context(|| format!("invalid recovery file {}", recovery_path.display()))?;
    if record.target_file_name.contains('/') || record.target_file_name.contains('\\') {
        bail!("recovery target_file_name must not contain path separators");
    }
    let target_path = recovery_path.with_file_name(&record.target_file_name);
    let existing = fsutil::read_file_if_exists(&target_path)?;
    let desired = serde_json::to_vec_pretty(&record.credential).context("serialize recovery")?;
    let already_restored = existing
        .as_deref()
        .and_then(|bytes| {
            let existing_value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
            let desired_value: serde_json::Value = serde_json::from_slice(&desired).ok()?;
            Some(existing_value == desired_value)
        })
        .unwrap_or(false);
    if already_restored {
        std::fs::remove_file(recovery_path)
            .with_context(|| format!("failed to delete {}", recovery_path.display()))?;
        return Ok(());
    }
    fsutil::atomic_write_json(&target_path, &record.credential)?;
    std::fs::remove_file(recovery_path)
        .with_context(|| format!("failed to delete {}", recovery_path.display()))?;
    logger.runtime(
        "info",
        format!(
            "recovered credential {} from {}",
            target_path.display(),
            recovery_path.display()
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogManager;

    #[test]
    fn restores_target_from_recovery_file() {
        let temp = tempfile::tempdir().unwrap();
        let logs = LogManager::new(temp.path(), 1024, "info").unwrap();
        let target = temp.path().join("account.json");
        let credential = CodexCredentialFile {
            access_token: "new-access".to_string(),
            refresh_token: "new-refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        write_recovery(&target, &credential).unwrap();
        recover_all(&[temp.path().to_path_buf()], &logs).unwrap();
        let recovered: CodexCredentialFile =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(recovered.access_token, "new-access");
        assert!(!recovery_path_for(&target).unwrap().exists());
    }
}
