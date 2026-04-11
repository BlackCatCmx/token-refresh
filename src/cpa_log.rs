use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{FixedOffset, Utc};

const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub struct CpaLog {
    path: PathBuf,
    max_bytes: u64,
    lock: Mutex<()>,
}

impl CpaLog {
    pub fn new(state_dir: &Path) -> Result<Self> {
        let dir = state_dir.join("logs");
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create log dir {}", dir.display()))?;
        let path = dir.join("cpa.log");
        touch(&path)?;
        Ok(Self {
            path,
            max_bytes: DEFAULT_MAX_BYTES,
            lock: Mutex::new(()),
        })
    }

    pub fn write(&self, msg: &str) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("CPA log lock poisoned"))?;
        let line = format!("{} {}\n", log_timestamp(), msg.trim_end());
        let existing_len = fs::metadata(&self.path).map(|meta| meta.len()).unwrap_or(0);
        if existing_len.saturating_add(line.len() as u64) > self.max_bytes {
            truncate_file(&self.path)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", self.path.display()))?;
        Ok(())
    }

    pub fn read_tail(&self, limit_lines: usize) -> Result<String> {
        read_tail_lines(&self.path, limit_lines)
    }

    pub fn read_bytes(&self) -> Result<Vec<u8>> {
        fs::read(&self.path).with_context(|| format!("failed to read {}", self.path.display()))
    }

    pub fn clear(&self) -> Result<()> {
        truncate_file(&self.path)
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
    fn can_write_and_read_tail() {
        let temp = tempfile::tempdir().unwrap();
        let log = CpaLog::new(temp.path()).unwrap();
        log.write("[INFO] first").unwrap();
        log.write("[WARN] second").unwrap();
        let tail = log.read_tail(1).unwrap();
        assert!(tail.contains("second"));
        assert!(!tail.contains("first"));
    }
}
