use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::config::AppConfig;
use crate::credential::CodexCredentialFile;
use crate::fsutil;
use crate::recovery;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialZone {
    Normal,
    Abnormal,
}

impl CredentialZone {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "normal" => Ok(Self::Normal),
            "abnormal" => Ok(Self::Abnormal),
            other => bail!("unsupported zone: {other}"),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Abnormal => "abnormal",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialEntry {
    pub zone: CredentialZone,
    pub key: String,
    pub path: PathBuf,
    pub credential: Option<CodexCredentialFile>,
    pub parse_error: Option<String>,
}

impl CredentialEntry {
    pub fn file_name(&self) -> String {
        Path::new(&self.key)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or(&self.key)
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CredentialStore {
    normal_dir: PathBuf,
    abnormal_dir: PathBuf,
}

impl CredentialStore {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let store = Self {
            normal_dir: config.credentials_dir.clone(),
            abnormal_dir: config.abnormal_credentials_dir.clone(),
        };
        store.ensure_dirs()?;
        Ok(store)
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.normal_dir)
            .with_context(|| format!("failed to create {}", self.normal_dir.display()))?;
        fs::create_dir_all(&self.abnormal_dir)
            .with_context(|| format!("failed to create {}", self.abnormal_dir.display()))?;
        Ok(())
    }

    pub fn normal_dir(&self) -> &Path {
        &self.normal_dir
    }

    pub fn abnormal_dir(&self) -> &Path {
        &self.abnormal_dir
    }

    pub fn scan_zone(&self, zone: CredentialZone) -> Result<Vec<CredentialEntry>> {
        let root = self.zone_dir(zone);
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.into_path();
            if !is_json_file(&path) || recovery::is_recovery_file(&path) {
                continue;
            }
            let key = self.path_to_key(zone, &path)?;
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read credential {}", path.display()))?;
            match serde_json::from_slice::<CodexCredentialFile>(&bytes) {
                Ok(credential) if credential.is_codex() => entries.push(CredentialEntry {
                    zone,
                    key,
                    path,
                    credential: Some(credential),
                    parse_error: None,
                }),
                Ok(_) => {}
                Err(err) => entries.push(CredentialEntry {
                    zone,
                    key,
                    path,
                    credential: None,
                    parse_error: Some(err.to_string()),
                }),
            }
        }
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(entries)
    }

    pub fn scan_all(&self) -> Result<Vec<CredentialEntry>> {
        let mut entries = self.scan_zone(CredentialZone::Normal)?;
        entries.extend(self.scan_zone(CredentialZone::Abnormal)?);
        Ok(entries)
    }

    pub fn read_entry(&self, zone: CredentialZone, key: &str) -> Result<CredentialEntry> {
        let path = self.key_to_path(zone, key)?;
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read credential {}", path.display()))?;
        match serde_json::from_slice::<CodexCredentialFile>(&bytes) {
            Ok(credential) => Ok(CredentialEntry {
                zone,
                key: normalize_key(key),
                path,
                credential: Some(credential),
                parse_error: None,
            }),
            Err(err) => Ok(CredentialEntry {
                zone,
                key: normalize_key(key),
                path,
                credential: None,
                parse_error: Some(err.to_string()),
            }),
        }
    }

    pub fn write_credential(
        &self,
        zone: CredentialZone,
        key: &str,
        credential: &CodexCredentialFile,
    ) -> Result<PathBuf> {
        let path = self.key_to_path(zone, key)?;
        let mut prepared = credential.clone();
        prepared.provider_type = "codex".to_string();
        fsutil::atomic_write_json(&path, &prepared)?;
        Ok(path)
    }

    pub fn import_credential(
        &self,
        zone: CredentialZone,
        name: &str,
        credential: &CodexCredentialFile,
    ) -> Result<String> {
        let key = import_key_for(name, credential)?;
        self.write_credential(zone, &key, credential)?;
        Ok(key)
    }

    pub fn move_between_zones(
        &self,
        from: CredentialZone,
        to: CredentialZone,
        key: &str,
    ) -> Result<()> {
        let source = self.key_to_path(from, key)?;
        let target = self.key_to_path(to, key)?;
        let bytes = fs::read(&source)
            .with_context(|| format!("failed to read credential {}", source.display()))?;
        fsutil::atomic_write_bytes(&target, &bytes)?;
        if source.exists() {
            fs::remove_file(&source)
                .with_context(|| format!("failed to delete {}", source.display()))?;
        }
        remove_empty_ancestors(&source, self.zone_dir(from))?;
        Ok(())
    }

    pub fn delete(&self, zone: CredentialZone, key: &str) -> Result<()> {
        let path = self.key_to_path(zone, key)?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to delete {}", path.display()))?;
            remove_empty_ancestors(&path, self.zone_dir(zone))?;
        }
        Ok(())
    }

    pub fn read_bytes(&self, zone: CredentialZone, key: &str) -> Result<Vec<u8>> {
        let path = self.key_to_path(zone, key)?;
        fs::read(&path).with_context(|| format!("failed to read {}", path.display()))
    }

    pub fn key_to_path(&self, zone: CredentialZone, key: &str) -> Result<PathBuf> {
        let relative = validate_relative_key(key)?;
        Ok(self.zone_dir(zone).join(relative))
    }

    pub fn path_to_key(&self, zone: CredentialZone, path: &Path) -> Result<String> {
        let relative = path
            .strip_prefix(self.zone_dir(zone))
            .with_context(|| format!("{} is not under zone root", path.display()))?;
        Ok(normalize_key(&relative.to_string_lossy()))
    }

    fn zone_dir(&self, zone: CredentialZone) -> &Path {
        match zone {
            CredentialZone::Normal => &self.normal_dir,
            CredentialZone::Abnormal => &self.abnormal_dir,
        }
    }
}

pub fn import_key_for(name: &str, credential: &CodexCredentialFile) -> Result<String> {
    let trimmed = name.trim();
    if !trimmed.is_empty() {
        let key = normalize_key(trimmed);
        validate_relative_key(&key)?;
        if key.to_ascii_lowercase().ends_with(".json") {
            return Ok(key);
        }
        return Ok(format!("{key}.json"));
    }
    let email = credential
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("credential file is missing email and upload file name")?;
    Ok(format!("{email}.json"))
}

pub fn normalize_key(value: &str) -> String {
    value.replace('\\', "/").trim_start_matches('/').to_string()
}

fn validate_relative_key(key: &str) -> Result<PathBuf> {
    let normalized = normalize_key(key);
    if normalized.is_empty() {
        bail!("credential key cannot be empty");
    }
    let path = PathBuf::from(&normalized);
    if path.is_absolute() {
        bail!("credential key must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {}
            Component::ParentDir => bail!("credential key cannot contain parent directory"),
            Component::RootDir | Component::Prefix(_) => bail!("credential key must be relative"),
        }
    }
    Ok(path)
}

fn is_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn remove_empty_ancestors(path: &Path, stop_at: &Path) -> Result<()> {
    let mut current = path.parent();
    while let Some(dir) = current {
        if dir == stop_at {
            break;
        }
        if fs::read_dir(dir)?.next().is_none() {
            fs::remove_dir(dir)
                .with_context(|| format!("failed to delete empty dir {}", dir.display()))?;
        } else {
            break;
        }
        current = dir.parent();
    }
    Ok(())
}
