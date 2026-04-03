use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory for {}", path.display()))?;
    }
    Ok(())
}

pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    let temp_path = temp_path(parent, path);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp_path)
        .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write temp file {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temp file {}", temp_path.display()))?;
    drop(file);
    replace_file(&temp_path, path)?;
    sync_dir(parent)?;
    Ok(())
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialize {}", path.display()))?;
    bytes.push(b'\n');
    atomic_write_bytes(path, &bytes)
}

pub fn read_file_if_exists(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn temp_path(parent: &Path, target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("temp");
    let suffix = rand::random::<u64>();
    parent.join(format!(".{file_name}.{suffix}.tmp"))
}

#[cfg(not(windows))]
fn replace_file(temp_path: &Path, target: &Path) -> Result<()> {
    fs::rename(temp_path, target).with_context(|| {
        format!(
            "failed to replace {} with {}",
            target.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW,
    };

    if !target.exists() {
        let from: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to move {} to {}",
                    temp_path.display(),
                    target.display()
                )
            });
        }
        return Ok(());
    }

    let target_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let temp_wide: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let ok = unsafe {
        ReplaceFileW(
            target_wide.as_ptr(),
            temp_wide.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to replace {} with {}",
                target.display(),
                temp_path.display()
            )
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn sync_dir(path: &Path) -> Result<()> {
    use std::fs::File;

    let dir = File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?;
    dir.sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn sync_dir(path: &Path) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "directory {} does not exist",
            path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_bytes_can_replace_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sample.json");

        atomic_write_bytes(&path, br#"{"value":1}"#).unwrap();
        atomic_write_bytes(&path, br#"{"value":2}"#).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, r#"{"value":2}"#);
    }
}
