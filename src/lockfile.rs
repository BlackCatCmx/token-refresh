use std::fs::{self, File, OpenOptions};
use std::path::Path;

use anyhow::{Context, Result, bail};
use fs2::FileExt;

#[derive(Debug)]
pub struct ServiceLock {
    _file: File,
}

impl ServiceLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create lock directory {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open lock file {}", path.display()))?;
        if let Err(err) = file.try_lock_exclusive() {
            bail!("failed to acquire service lock {}: {err}", path.display());
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_second_lock_holder() {
        let temp = tempfile::tempdir().unwrap();
        let lock_path = temp.path().join("service.lock");
        let _first = ServiceLock::acquire(&lock_path).unwrap();
        let second = ServiceLock::acquire(&lock_path);
        assert!(second.is_err());
    }
}
