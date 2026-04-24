use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Component, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod};

use crate::credential_store::{CredentialStore, CredentialZone};
use crate::status::{CredentialStatusRecord, CredentialStatusStore};

const MANIFEST_PATH: &str = "manifest.json";
const STATUS_PATH: &str = "state/credential_status.json";
const AES_AUTH_CODE_ERROR_TEXT: &str =
    "Invalid authentication code, this could be due to an invalid password or errors in the data";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub version: u32,
    pub created_at: String,
    pub trigger: String,
    pub normal_count: usize,
    pub abnormal_count: usize,
    pub status_present: bool,
    pub entries: Vec<SnapshotManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifestEntry {
    pub path: String,
    pub sha256: String,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub struct ParsedSnapshot {
    pub manifest: SnapshotManifest,
    pub normal_files: BTreeMap<String, Vec<u8>>,
    pub abnormal_files: BTreeMap<String, Vec<u8>>,
    pub status_records: BTreeMap<String, CredentialStatusRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct RestoredSnapshot {
    pub normal_count: usize,
    pub abnormal_count: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("备份密码错误")]
struct InvalidBackupPasswordError;

pub fn is_invalid_backup_password(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<InvalidBackupPasswordError>())
}

pub fn build_snapshot_archive(
    store: &CredentialStore,
    status_store: &CredentialStatusStore,
    trigger: &str,
    created_at: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let cursor = build_snapshot_archive_to_writer(
        cursor,
        store,
        status_store,
        trigger,
        created_at,
        password,
    )?;
    Ok(cursor.into_inner())
}

pub fn build_snapshot_archive_to_writer<W: Write + Seek>(
    writer: W,
    store: &CredentialStore,
    status_store: &CredentialStatusStore,
    trigger: &str,
    created_at: DateTime<Utc>,
    password: &str,
) -> Result<W> {
    build_snapshot_archive_to_writer_inner(
        writer,
        store,
        status_store,
        trigger,
        created_at,
        Some(password),
    )
}

fn build_snapshot_archive_to_writer_inner<W: Write + Seek>(
    writer: W,
    store: &CredentialStore,
    status_store: &CredentialStatusStore,
    trigger: &str,
    created_at: DateTime<Utc>,
    password: Option<&str>,
) -> Result<W> {
    let normal_entries = store.scan_zone(CredentialZone::Normal)?;
    let abnormal_entries = store.scan_zone(CredentialZone::Abnormal)?;
    let mut manifest_entries = Vec::new();
    let mut writer = zip::ZipWriter::new(writer);

    for entry in &normal_entries {
        let archive_path = format!("normal/{}", entry.key);
        let bytes = store.read_bytes(CredentialZone::Normal, &entry.key)?;
        write_snapshot_entry(
            &mut writer,
            &archive_path,
            &bytes,
            password,
            &mut manifest_entries,
        )?;
    }
    for entry in &abnormal_entries {
        let archive_path = format!("abnormal/{}", entry.key);
        let bytes = store.read_bytes(CredentialZone::Abnormal, &entry.key)?;
        write_snapshot_entry(
            &mut writer,
            &archive_path,
            &bytes,
            password,
            &mut manifest_entries,
        )?;
    }

    let status_records = status_store.all()?;
    let mut status_bytes = serde_json::to_vec_pretty(&status_records)
        .context("failed to serialize credential_status.json")?;
    status_bytes.push(b'\n');
    write_snapshot_entry(
        &mut writer,
        STATUS_PATH,
        &status_bytes,
        password,
        &mut manifest_entries,
    )?;

    let manifest = SnapshotManifest {
        version: 1,
        created_at: created_at.to_rfc3339(),
        trigger: trigger.to_string(),
        normal_count: normal_entries.len(),
        abnormal_count: abnormal_entries.len(),
        status_present: true,
        entries: manifest_entries,
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize manifest.json")?;
    manifest_bytes.push(b'\n');
    write_raw_snapshot_entry(&mut writer, MANIFEST_PATH, &manifest_bytes, password)?;
    writer
        .finish()
        .context("failed to finalize snapshot archive")
}

pub fn parse_snapshot_archive(bytes: &[u8], password: &str) -> Result<ParsedSnapshot> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("invalid backup snapshot ZIP")?;
    let mut files = BTreeMap::new();
    let mut manifest: Option<SnapshotManifest> = None;

    for index in 0..archive.len() {
        let encrypted = archive
            .get_aes_verification_key_and_salt(index)
            .map_err(map_zip_read_error)
            .context("failed to inspect ZIP entry encryption")?
            .is_some();
        let mut file = if encrypted {
            archive
                .by_index_decrypt(index, password.as_bytes())
                .map_err(map_zip_read_error)
                .context("failed to decrypt ZIP entry")?
        } else {
            archive
                .by_index(index)
                .map_err(map_zip_read_error)
                .context("failed to read ZIP entry")?
        };
        if file.is_dir() {
            continue;
        }
        let name = file.name().replace('\\', "/");
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|error| map_zip_entry_content_error(&name, encrypted, error))?;
        if name == MANIFEST_PATH {
            manifest = Some(
                serde_json::from_slice(&content).context("invalid manifest.json in snapshot")?,
            );
            continue;
        }
        validate_snapshot_path(&name)?;
        if files.insert(name.clone(), content).is_some() {
            bail!("duplicate ZIP entry found: {name}");
        }
    }

    let manifest = manifest.context("snapshot is missing manifest.json")?;
    if manifest.version != 1 {
        bail!(
            "unsupported snapshot manifest version: {}",
            manifest.version
        );
    }
    if !manifest.status_present {
        bail!("snapshot manifest indicates missing status file");
    }
    if manifest.entries.len() != files.len() {
        bail!("snapshot manifest entry count does not match ZIP contents");
    }

    for entry in &manifest.entries {
        validate_snapshot_path(&entry.path)?;
        let Some(content) = files.get(&entry.path) else {
            bail!("snapshot is missing expected entry {}", entry.path);
        };
        if entry.size != content.len() {
            bail!("snapshot entry size mismatch for {}", entry.path);
        }
        let actual_sha = sha256_hex(content);
        if actual_sha != entry.sha256 {
            bail!("snapshot entry checksum mismatch for {}", entry.path);
        }
    }

    let status_bytes = files
        .get(STATUS_PATH)
        .context("snapshot is missing state/credential_status.json")?;
    let status_records =
        serde_json::from_slice::<BTreeMap<String, CredentialStatusRecord>>(status_bytes)
            .context("invalid state/credential_status.json in snapshot")?;

    let mut normal_files = BTreeMap::new();
    let mut abnormal_files = BTreeMap::new();
    for (path, bytes) in files {
        if path == STATUS_PATH {
            continue;
        }
        if let Some(stripped) = path.strip_prefix("normal/") {
            normal_files.insert(stripped.to_string(), bytes);
        } else if let Some(stripped) = path.strip_prefix("abnormal/") {
            abnormal_files.insert(stripped.to_string(), bytes);
        }
    }

    Ok(ParsedSnapshot {
        manifest,
        normal_files,
        abnormal_files,
        status_records,
    })
}

pub fn restore_snapshot_archive(
    store: &CredentialStore,
    status_store: &CredentialStatusStore,
    snapshot: ParsedSnapshot,
) -> Result<RestoredSnapshot> {
    replace_zone(
        store,
        CredentialZone::Normal,
        &snapshot.normal_files,
        "normal",
    )?;
    replace_zone(
        store,
        CredentialZone::Abnormal,
        &snapshot.abnormal_files,
        "abnormal",
    )?;
    status_store.replace_all(snapshot.status_records)?;
    Ok(RestoredSnapshot {
        normal_count: snapshot.normal_files.len(),
        abnormal_count: snapshot.abnormal_files.len(),
    })
}

fn replace_zone(
    store: &CredentialStore,
    zone: CredentialZone,
    desired: &BTreeMap<String, Vec<u8>>,
    label: &str,
) -> Result<()> {
    let existing = store
        .scan_zone(zone)?
        .into_iter()
        .map(|entry| entry.key)
        .collect::<BTreeSet<_>>();
    let desired_keys = desired.keys().cloned().collect::<BTreeSet<_>>();

    for key in existing.difference(&desired_keys) {
        store.delete(zone, key)?;
    }
    for (key, bytes) in desired {
        store
            .write_bytes(zone, key, bytes)
            .with_context(|| format!("failed to restore {label} credential {key}"))?;
    }
    Ok(())
}

fn write_snapshot_entry<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    path: &str,
    bytes: &[u8],
    password: Option<&str>,
    manifest_entries: &mut Vec<SnapshotManifestEntry>,
) -> Result<()> {
    write_raw_snapshot_entry(writer, path, bytes, password)?;
    manifest_entries.push(SnapshotManifestEntry {
        path: path.to_string(),
        sha256: sha256_hex(bytes),
        size: bytes.len(),
    });
    Ok(())
}

fn write_raw_snapshot_entry<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    path: &str,
    bytes: &[u8],
    password: Option<&str>,
) -> Result<()> {
    match password {
        Some(password) => writer.start_file(
            path,
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .with_aes_encryption(AesMode::Aes256, password),
        )?,
        None => writer.start_file(
            path,
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )?,
    }
    writer.write_all(bytes)?;
    Ok(())
}

fn map_zip_read_error(error: ZipError) -> anyhow::Error {
    match error {
        ZipError::InvalidPassword => InvalidBackupPasswordError.into(),
        other => other.into(),
    }
}

fn map_zip_entry_content_error(
    name: &str,
    encrypted: bool,
    error: std::io::Error,
) -> anyhow::Error {
    if encrypted && is_aes_auth_code_error(&error) {
        return anyhow::Error::new(InvalidBackupPasswordError)
            .context(format!("failed to read ZIP entry {name}"));
    }
    anyhow::Error::new(error).context(format!("failed to read ZIP entry {name}"))
}

fn is_aes_auth_code_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::InvalidData
        && error.to_string().contains(AES_AUTH_CODE_ERROR_TEXT)
}

fn validate_snapshot_path(path: &str) -> Result<()> {
    if path == STATUS_PATH {
        return Ok(());
    }
    let (zone, key) = if let Some(stripped) = path.strip_prefix("normal/") {
        (CredentialZone::Normal, stripped)
    } else if let Some(stripped) = path.strip_prefix("abnormal/") {
        (CredentialZone::Abnormal, stripped)
    } else {
        bail!("unsupported snapshot entry path: {path}");
    };
    let _ = zone;
    validate_relative_key(key)?;
    Ok(())
}

fn validate_relative_key(key: &str) -> Result<PathBuf> {
    let normalized = key.replace('\\', "/").trim_start_matches('/').to_string();
    if normalized.is_empty() {
        bail!("snapshot entry key cannot be empty");
    }
    let path = PathBuf::from(&normalized);
    if path.is_absolute() {
        bail!("snapshot entry key must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("snapshot entry key cannot contain parent directory"),
            Component::RootDir | Component::Prefix(_) => {
                bail!("snapshot entry key must be relative")
            }
        }
    }
    Ok(path)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::credential::CodexCredentialFile;

    const TEST_PASSWORD: &str = "backup-password";

    #[test]
    fn snapshot_round_trip_restores_files_and_status() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        config.state_dir = temp.path().join("state");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store =
            CredentialStatusStore::load(config.state_dir.join("credential_status.json")).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user.json", &credential)
            .unwrap();
        status_store.record_success("user.json", "normal").unwrap();

        let bytes =
            build_snapshot_archive(&store, &status_store, "manual", Utc::now(), TEST_PASSWORD)
                .unwrap();

        store.delete(CredentialZone::Normal, "user.json").unwrap();
        status_store.remove("user.json").unwrap();

        let parsed = parse_snapshot_archive(&bytes, TEST_PASSWORD).unwrap();
        restore_snapshot_archive(&store, &status_store, parsed).unwrap();

        assert!(
            store
                .read_bytes(CredentialZone::Normal, "user.json")
                .is_ok()
        );
        assert!(status_store.get("user.json").unwrap().is_some());
    }

    #[test]
    fn snapshot_writer_variant_persists_archive_to_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        config.state_dir = temp.path().join("state");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store =
            CredentialStatusStore::load(config.state_dir.join("credential_status.json")).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user.json", &credential)
            .unwrap();
        status_store.record_success("user.json", "normal").unwrap();

        let mut archive_file = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        build_snapshot_archive_to_writer(
            archive_file.as_file_mut(),
            &store,
            &status_store,
            "manual",
            Utc::now(),
            TEST_PASSWORD,
        )
        .unwrap();

        let bytes = std::fs::read(archive_file.path()).unwrap();
        let parsed = parse_snapshot_archive(&bytes, TEST_PASSWORD).unwrap();
        assert_eq!(parsed.manifest.normal_count, 1);
        assert_eq!(parsed.manifest.trigger, "manual");
        assert!(parsed.normal_files.contains_key("user.json"));
    }

    #[test]
    fn snapshot_restore_rejects_wrong_password() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        config.state_dir = temp.path().join("state");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store =
            CredentialStatusStore::load(config.state_dir.join("credential_status.json")).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user.json", &credential)
            .unwrap();
        status_store.record_success("user.json", "normal").unwrap();

        let bytes =
            build_snapshot_archive(&store, &status_store, "manual", Utc::now(), TEST_PASSWORD)
                .unwrap();
        let error = parse_snapshot_archive(&bytes, "wrong-password").unwrap_err();
        assert!(is_invalid_backup_password(&error));
    }

    #[test]
    fn legacy_unencrypted_snapshot_still_restores_when_password_is_provided() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        config.state_dir = temp.path().join("state");
        let store = CredentialStore::new(&config, None).unwrap();
        let status_store =
            CredentialStatusStore::load(config.state_dir.join("credential_status.json")).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user.json", &credential)
            .unwrap();
        status_store.record_success("user.json", "normal").unwrap();

        let cursor = Cursor::new(Vec::new());
        let cursor = build_snapshot_archive_to_writer_inner(
            cursor,
            &store,
            &status_store,
            "manual",
            Utc::now(),
            None,
        )
        .unwrap();
        let parsed = parse_snapshot_archive(&cursor.into_inner(), TEST_PASSWORD).unwrap();
        assert_eq!(parsed.manifest.normal_count, 1);
        assert!(parsed.normal_files.contains_key("user.json"));
    }

    #[test]
    fn aes_auth_code_error_maps_to_invalid_backup_password() {
        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, AES_AUTH_CODE_ERROR_TEXT);
        let mapped = map_zip_entry_content_error("manifest.json", true, error);
        assert!(is_invalid_backup_password(&mapped));
    }
}
