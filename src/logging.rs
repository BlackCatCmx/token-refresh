use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use chrono::{FixedOffset, Utc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogKind {
    Runtime,
    Audit,
}

impl LogKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "runtime" => Ok(Self::Runtime),
            "audit" => Ok(Self::Audit),
            other => bail!("unsupported log kind: {other}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuntimeLogLevel {
    Info,
    Warn,
    Error,
}

impl RuntimeLogLevel {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => bail!("unsupported runtime log level: {other}"),
        }
    }
}

#[derive(Debug)]
pub struct LogManager {
    dir: PathBuf,
    runtime_path: PathBuf,
    audit_path: PathBuf,
    max_file_size: Mutex<u64>,
    runtime_level: Mutex<RuntimeLogLevel>,
    write_lock: Mutex<()>,
}

impl LogManager {
    pub fn new(state_dir: &Path, max_file_size: u64, runtime_level: &str) -> Result<Self> {
        let dir = state_dir.join("logs");
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create log dir {}", dir.display()))?;
        let runtime_path = dir.join("runtime.log");
        let audit_path = dir.join("audit.log");
        touch(&runtime_path)?;
        touch(&audit_path)?;
        Ok(Self {
            dir,
            runtime_path,
            audit_path,
            max_file_size: Mutex::new(max_file_size),
            runtime_level: Mutex::new(RuntimeLogLevel::parse(runtime_level)?),
            write_lock: Mutex::new(()),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    pub fn update_max_file_size(&self, max_file_size: u64) -> Result<()> {
        let mut guard = self
            .max_file_size
            .lock()
            .map_err(|_| anyhow::anyhow!("log manager lock poisoned"))?;
        *guard = max_file_size;
        Ok(())
    }

    pub fn update_runtime_level(&self, runtime_level: &str) -> Result<()> {
        let mut guard = self
            .runtime_level
            .lock()
            .map_err(|_| anyhow::anyhow!("log level lock poisoned"))?;
        *guard = RuntimeLogLevel::parse(runtime_level)?;
        Ok(())
    }

    pub fn runtime(&self, level: &str, message: impl AsRef<str>) -> Result<()> {
        let event_level = RuntimeLogLevel::parse(level)?;
        let threshold = *self
            .runtime_level
            .lock()
            .map_err(|_| anyhow::anyhow!("log level lock poisoned"))?;
        if event_level < threshold {
            return Ok(());
        }
        self.append(
            self.runtime_path.as_path(),
            format!(
                "{} [{}] {}\n",
                log_timestamp(),
                level.to_ascii_uppercase(),
                message.as_ref()
            ),
        )
    }

    pub fn audit(&self, message: impl AsRef<str>) -> Result<()> {
        self.append(
            self.audit_path.as_path(),
            format!("{} {}\n", log_timestamp(), message.as_ref()),
        )
    }

    pub fn read_tail(&self, kind: LogKind, limit_lines: usize) -> Result<String> {
        match kind {
            LogKind::Runtime => read_tail_lines(&self.runtime_path, limit_lines),
            LogKind::Audit => read_tail_lines(&self.audit_path, limit_lines),
        }
    }

    pub fn clear(&self, kind: LogKind) -> Result<()> {
        match kind {
            LogKind::Runtime => truncate_file(&self.runtime_path),
            LogKind::Audit => truncate_file(&self.audit_path),
        }
    }

    pub fn read_bytes(&self, kind: LogKind) -> Result<Vec<u8>> {
        match kind {
            LogKind::Runtime => fs::read(&self.runtime_path)
                .with_context(|| format!("failed to read {}", self.runtime_path.display())),
            LogKind::Audit => fs::read(&self.audit_path)
                .with_context(|| format!("failed to read {}", self.audit_path.display())),
        }
    }

    fn append(&self, path: &Path, line: String) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("log manager lock poisoned"))?;
        let max_file_size = *self
            .max_file_size
            .lock()
            .map_err(|_| anyhow::anyhow!("log manager size lock poisoned"))?;
        let existing_len = fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        if existing_len.saturating_add(line.len() as u64) > max_file_size {
            truncate_file(path)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open log file {}", path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("failed to write log file {}", path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush log file {}", path.display()))?;
        Ok(())
    }
}

fn touch(path: &Path) -> Result<()> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    Ok(())
}

fn truncate_file(path: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to truncate {}", path.display()))?;
    file.set_len(0)
        .with_context(|| format!("failed to reset length for {}", path.display()))?;
    Ok(())
}

fn read_tail_lines(path: &Path, limit_lines: usize) -> Result<String> {
    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", path.display())),
    };
    if limit_lines == 0 {
        return Ok(String::new());
    }
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(limit_lines);
    Ok(lines[start..].join("\n"))
}

fn log_timestamp() -> String {
    let offset = FixedOffset::east_opt(8 * 60 * 60).expect("UTC+8 offset must be valid");
    Utc::now().with_timezone(&offset).to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_when_file_exceeds_limit() {
        let temp = tempfile::tempdir().unwrap();
        let manager = LogManager::new(temp.path(), 60, "info").unwrap();
        manager
            .runtime("info", "first line that is long enough")
            .unwrap();
        manager.runtime("info", "second line").unwrap();
        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        assert!(content.contains("second line"));
        assert!(!content.contains("first line that is long enough"));
    }

    #[test]
    fn filters_runtime_messages_by_level() {
        let temp = tempfile::tempdir().unwrap();
        let manager = LogManager::new(temp.path(), 1024, "warn").unwrap();
        manager.runtime("info", "skip me").unwrap();
        manager.runtime("error", "keep me").unwrap();
        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        assert!(!content.contains("skip me"));
        assert!(content.contains("keep me"));
    }

    #[test]
    fn updates_runtime_level_without_restart() {
        let temp = tempfile::tempdir().unwrap();
        let manager = LogManager::new(temp.path(), 1024, "error").unwrap();
        manager.runtime("warn", "skip me").unwrap();
        manager.update_runtime_level("warn").unwrap();
        manager.runtime("warn", "keep me now").unwrap();
        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        assert!(!content.contains("skip me"));
        assert!(content.contains("keep me now"));
    }

    #[test]
    fn rejects_removed_runtime_levels() {
        let temp = tempfile::tempdir().unwrap();
        assert!(LogManager::new(temp.path(), 1024, "debug").is_err());
        assert!(LogManager::new(temp.path(), 1024, "trace").is_err());
    }

    #[test]
    fn writes_logs_in_utc_plus_8_offset() {
        let temp = tempfile::tempdir().unwrap();
        let manager = LogManager::new(temp.path(), 1024, "info").unwrap();
        manager.runtime("info", "check offset").unwrap();
        let content = std::fs::read_to_string(temp.path().join("logs/runtime.log")).unwrap();
        let timestamp = content.split_whitespace().next().unwrap();
        assert!(timestamp.ends_with("+08:00"));
    }
}
