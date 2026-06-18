use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Component;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod};

use crate::backup_archive::validate_archive_relative_key;
use crate::config::EditableSettings;
use crate::cpa_config::CpaConfig;
use crate::credential::CodexCredentialFile;
use crate::status::CredentialStatusRecord;

const MANIFEST_PATH: &str = "manifest.json";
const STATUS_PATH: &str = "state/credential_status.json";
const SETTINGS_PATH: &str = "settings/editable_settings.yaml";
const CPA_CONFIG_PATH: &str = "cpa/cpa_config.json";
const FORMAT: &str = "token-refresh-migration";
const VERSION: u32 = 1;
const AES_AUTH_CODE_ERROR_TEXT: &str =
    "Invalid authentication code, this could be due to an invalid password or errors in the data";

#[derive(Clone, Debug)]
pub struct MigrationArchiveInput {
    pub normal_files: BTreeMap<String, Vec<u8>>,
    pub abnormal_files: BTreeMap<String, Vec<u8>>,
    pub status_records: BTreeMap<String, CredentialStatusRecord>,
    pub editable_settings: EditableSettings,
    pub cpa_config: CpaConfig,
}

#[derive(Clone, Debug)]
pub struct ParsedMigrationArchive {
    pub manifest: MigrationManifest,
    pub normal_files: BTreeMap<String, Vec<u8>>,
    pub abnormal_files: BTreeMap<String, Vec<u8>>,
    pub status_records: BTreeMap<String, CredentialStatusRecord>,
    pub editable_settings: EditableSettings,
    pub cpa_config: CpaConfig,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MigrationRestoreSummary {
    pub normal_count: usize,
    pub abnormal_count: usize,
    pub status_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub format: String,
    pub version: u32,
    pub created_at: String,
    pub normal_count: usize,
    pub abnormal_count: usize,
    pub status_present: bool,
    pub settings_present: bool,
    pub cpa_config_present: bool,
    pub cpa_sanitized: bool,
    pub entries: Vec<MigrationManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationManifestEntry {
    pub path: String,
    pub sha256: String,
    pub size: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("迁移包密码错误")]
struct InvalidMigrationPasswordError;

pub fn is_invalid_migration_password(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<InvalidMigrationPasswordError>())
}

pub fn sanitize_cpa_config(mut config: CpaConfig) -> CpaConfig {
    config.enabled = false;
    config.base_url.clear();
    config.management_key.clear();
    config
}

pub fn build_migration_archive(
    input: MigrationArchiveInput,
    created_at: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let cursor = build_migration_archive_to_writer(cursor, input, created_at, password)?;
    Ok(cursor.into_inner())
}

pub fn build_migration_archive_to_writer<W: Write + Seek>(
    writer: W,
    input: MigrationArchiveInput,
    created_at: DateTime<Utc>,
    password: &str,
) -> Result<W> {
    let mut writer = zip::ZipWriter::new(writer);
    let mut manifest_entries = Vec::new();

    for (key, bytes) in &input.normal_files {
        validate_credential_file(key, bytes)?;
        write_migration_entry(
            &mut writer,
            &format!("credentials/normal/{key}"),
            bytes,
            password,
            &mut manifest_entries,
        )?;
    }
    for (key, bytes) in &input.abnormal_files {
        validate_credential_file(key, bytes)?;
        write_migration_entry(
            &mut writer,
            &format!("credentials/abnormal/{key}"),
            bytes,
            password,
            &mut manifest_entries,
        )?;
    }

    let mut status_bytes = serde_json::to_vec_pretty(&input.status_records)
        .context("failed to serialize credential_status.json")?;
    status_bytes.push(b'\n');
    write_migration_entry(
        &mut writer,
        STATUS_PATH,
        &status_bytes,
        password,
        &mut manifest_entries,
    )?;

    let mut settings_bytes = serde_yaml::to_string(&input.editable_settings)
        .context("failed to serialize editable_settings.yaml")?
        .into_bytes();
    settings_bytes.push(b'\n');
    write_migration_entry(
        &mut writer,
        SETTINGS_PATH,
        &settings_bytes,
        password,
        &mut manifest_entries,
    )?;

    let cpa_config = sanitize_cpa_config(input.cpa_config);
    cpa_config.validate()?;
    let mut cpa_bytes =
        serde_json::to_vec_pretty(&cpa_config).context("failed to serialize cpa_config.json")?;
    cpa_bytes.push(b'\n');
    write_migration_entry(
        &mut writer,
        CPA_CONFIG_PATH,
        &cpa_bytes,
        password,
        &mut manifest_entries,
    )?;

    let manifest = MigrationManifest {
        format: FORMAT.to_string(),
        version: VERSION,
        created_at: created_at.to_rfc3339(),
        normal_count: input.normal_files.len(),
        abnormal_count: input.abnormal_files.len(),
        status_present: true,
        settings_present: true,
        cpa_config_present: true,
        cpa_sanitized: true,
        entries: manifest_entries,
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize manifest.json")?;
    manifest_bytes.push(b'\n');
    write_raw_migration_entry(&mut writer, MANIFEST_PATH, &manifest_bytes, password)?;
    writer
        .finish()
        .context("failed to finalize migration archive")
}

pub fn parse_migration_archive(bytes: &[u8], password: &str) -> Result<ParsedMigrationArchive> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("invalid migration ZIP")?;
    let mut files = BTreeMap::new();
    let mut manifest: Option<MigrationManifest> = None;

    for index in 0..archive.len() {
        let encrypted = archive
            .get_aes_verification_key_and_salt(index)
            .map_err(map_zip_read_error)
            .context("failed to inspect ZIP entry encryption")?
            .is_some();
        if !encrypted {
            let name = archive.name_for_index(index).unwrap_or("<unknown>");
            bail!("migration ZIP entry is not encrypted: {name}");
        }
        let mut file = archive
            .by_index_decrypt(index, password.as_bytes())
            .map_err(map_zip_read_error)
            .context("failed to decrypt ZIP entry")?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().replace('\\', "/");
        validate_zip_entry_path(&name)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|error| map_zip_entry_content_error(&name, error))?;
        if name == MANIFEST_PATH {
            if manifest.is_some() {
                bail!("duplicate manifest.json entry found");
            }
            manifest = Some(
                serde_json::from_slice(&content)
                    .context("invalid manifest.json in migration archive")?,
            );
            continue;
        }
        validate_migration_path(&name)?;
        if files.insert(name.clone(), content).is_some() {
            bail!("duplicate ZIP entry found: {name}");
        }
    }

    let manifest = manifest.context("migration archive is missing manifest.json")?;
    validate_manifest(&manifest, &files)?;

    let status_records = parse_status_records(&files)?;
    let editable_settings = parse_editable_settings(&files)?;
    let cpa_config = parse_cpa_config(&files)?;
    let (normal_files, abnormal_files) = split_credential_files(files)?;

    if normal_files.len() != manifest.normal_count {
        bail!("migration manifest normal_count does not match ZIP contents");
    }
    if abnormal_files.len() != manifest.abnormal_count {
        bail!("migration manifest abnormal_count does not match ZIP contents");
    }

    Ok(ParsedMigrationArchive {
        manifest,
        normal_files,
        abnormal_files,
        status_records,
        editable_settings,
        cpa_config,
    })
}

pub fn restore_migration_archive(
    store: &crate::credential_store::CredentialStore,
    status_store: &crate::status::CredentialStatusStore,
    archive: &ParsedMigrationArchive,
) -> Result<MigrationRestoreSummary> {
    replace_zone(
        store,
        crate::credential_store::CredentialZone::Normal,
        &archive.normal_files,
        "normal",
    )?;
    replace_zone(
        store,
        crate::credential_store::CredentialZone::Abnormal,
        &archive.abnormal_files,
        "abnormal",
    )?;
    status_store.replace_all(archive.status_records.clone())?;
    Ok(MigrationRestoreSummary {
        normal_count: archive.normal_files.len(),
        abnormal_count: archive.abnormal_files.len(),
        status_count: status_store.all()?.len(),
    })
}

fn replace_zone(
    store: &crate::credential_store::CredentialStore,
    zone: crate::credential_store::CredentialZone,
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

fn write_migration_entry<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    path: &str,
    bytes: &[u8],
    password: &str,
    manifest_entries: &mut Vec<MigrationManifestEntry>,
) -> Result<()> {
    write_raw_migration_entry(writer, path, bytes, password)?;
    manifest_entries.push(MigrationManifestEntry {
        path: path.to_string(),
        sha256: sha256_hex(bytes),
        size: bytes.len(),
    });
    Ok(())
}

fn write_raw_migration_entry<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    path: &str,
    bytes: &[u8],
    password: &str,
) -> Result<()> {
    writer.start_file(
        path,
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, password),
    )?;
    writer.write_all(bytes)?;
    Ok(())
}

fn validate_manifest(
    manifest: &MigrationManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    if manifest.format != FORMAT {
        bail!("unsupported migration archive format: {}", manifest.format);
    }
    if manifest.version != VERSION {
        bail!(
            "unsupported migration archive manifest version: {}",
            manifest.version
        );
    }
    if !manifest.status_present {
        bail!("migration manifest indicates missing status file");
    }
    if !manifest.settings_present {
        bail!("migration manifest indicates missing settings file");
    }
    if !manifest.cpa_config_present {
        bail!("migration manifest indicates missing CPA config file");
    }
    if manifest.entries.len() != files.len() {
        bail!("migration manifest entry count does not match ZIP contents");
    }

    let mut seen = BTreeSet::new();
    for entry in &manifest.entries {
        validate_migration_path(&entry.path)?;
        if !seen.insert(entry.path.clone()) {
            bail!("duplicate manifest entry found: {}", entry.path);
        }
        let Some(content) = files.get(&entry.path) else {
            bail!("migration archive is missing expected entry {}", entry.path);
        };
        if entry.size != content.len() {
            bail!("migration entry size mismatch for {}", entry.path);
        }
        let actual_sha = sha256_hex(content);
        if actual_sha != entry.sha256 {
            bail!("migration entry checksum mismatch for {}", entry.path);
        }
    }
    Ok(())
}

fn parse_status_records(
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, CredentialStatusRecord>> {
    let status_bytes = files
        .get(STATUS_PATH)
        .context("migration archive is missing state/credential_status.json")?;
    serde_json::from_slice::<BTreeMap<String, CredentialStatusRecord>>(status_bytes)
        .context("invalid state/credential_status.json in migration archive")
}

fn parse_editable_settings(files: &BTreeMap<String, Vec<u8>>) -> Result<EditableSettings> {
    let settings_bytes = files
        .get(SETTINGS_PATH)
        .context("migration archive is missing settings/editable_settings.yaml")?;
    let settings_text = std::str::from_utf8(settings_bytes)
        .context("settings/editable_settings.yaml is not valid UTF-8")?;
    serde_yaml::from_str::<EditableSettings>(settings_text)
        .context("invalid settings/editable_settings.yaml in migration archive")
}

fn parse_cpa_config(files: &BTreeMap<String, Vec<u8>>) -> Result<CpaConfig> {
    let cpa_bytes = files
        .get(CPA_CONFIG_PATH)
        .context("migration archive is missing cpa/cpa_config.json")?;
    let cpa = serde_json::from_slice::<CpaConfig>(cpa_bytes)
        .context("invalid cpa/cpa_config.json in migration archive")?;
    let cpa = sanitize_cpa_config(cpa).normalized();
    cpa.validate()?;
    Ok(cpa)
}

fn split_credential_files(
    files: BTreeMap<String, Vec<u8>>,
) -> Result<(BTreeMap<String, Vec<u8>>, BTreeMap<String, Vec<u8>>)> {
    let mut normal_files = BTreeMap::new();
    let mut abnormal_files = BTreeMap::new();
    for (path, bytes) in files {
        if matches!(path.as_str(), STATUS_PATH | SETTINGS_PATH | CPA_CONFIG_PATH) {
            continue;
        }
        if let Some(stripped) = path.strip_prefix("credentials/normal/") {
            validate_credential_file(stripped, &bytes)?;
            normal_files.insert(stripped.to_string(), bytes);
        } else if let Some(stripped) = path.strip_prefix("credentials/abnormal/") {
            validate_credential_file(stripped, &bytes)?;
            abnormal_files.insert(stripped.to_string(), bytes);
        }
    }
    Ok((normal_files, abnormal_files))
}

fn validate_credential_file(key: &str, bytes: &[u8]) -> Result<()> {
    validate_archive_relative_key(key)?;
    let credential = serde_json::from_slice::<CodexCredentialFile>(bytes)
        .with_context(|| format!("invalid credential JSON in migration archive: {key}"))?;
    if !credential.is_codex() {
        bail!("migration credential is not a codex credential: {key}");
    }
    Ok(())
}

fn validate_migration_path(path: &str) -> Result<()> {
    if matches!(path, STATUS_PATH | SETTINGS_PATH | CPA_CONFIG_PATH) {
        return Ok(());
    }
    if let Some(stripped) = path.strip_prefix("credentials/normal/") {
        validate_archive_relative_key(stripped)?;
        return Ok(());
    }
    if let Some(stripped) = path.strip_prefix("credentials/abnormal/") {
        validate_archive_relative_key(stripped)?;
        return Ok(());
    }
    bail!("unsupported migration entry path: {path}");
}

fn validate_zip_entry_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("ZIP entry path cannot be empty");
    }
    let path_buf = std::path::PathBuf::from(path);
    if path_buf.is_absolute() {
        bail!("ZIP entry path must be relative");
    }
    for component in path_buf.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("ZIP entry path cannot contain parent directory"),
            Component::RootDir | Component::Prefix(_) => bail!("ZIP entry path must be relative"),
        }
    }
    Ok(())
}

fn map_zip_read_error(error: ZipError) -> anyhow::Error {
    match error {
        ZipError::InvalidPassword => InvalidMigrationPasswordError.into(),
        other => other.into(),
    }
}

fn map_zip_entry_content_error(name: &str, error: std::io::Error) -> anyhow::Error {
    if is_aes_auth_code_error(&error) {
        return anyhow::Error::new(InvalidMigrationPasswordError)
            .context(format!("failed to read ZIP entry {name}"));
    }
    anyhow::Error::new(error).context(format!("failed to read ZIP entry {name}"))
}

fn is_aes_auth_code_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::InvalidData
        && error.to_string().contains(AES_AUTH_CODE_ERROR_TEXT)
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
    use crate::config::{AppConfig, BackupRemoteConfig};
    use crate::credential::CodexCredentialFile;
    use crate::status::CredentialStatusRecord;

    const TEST_PASSWORD: &str = "migration-password";

    #[test]
    fn migration_archive_round_trips_credentials_status_settings_and_cpa() {
        let mut normal_files = BTreeMap::new();
        normal_files.insert(
            "user@example.com.json".to_string(),
            credential_bytes("refresh-a"),
        );
        let mut abnormal_files = BTreeMap::new();
        abnormal_files.insert(
            "bad@example.com.json".to_string(),
            credential_bytes("refresh-b"),
        );
        let mut status_records = BTreeMap::new();
        status_records.insert(
            "user@example.com.json".to_string(),
            CredentialStatusRecord {
                cpa_exhausted: Some(true),
                cpa_imported_at: Some("2026-06-18T00:00:00Z".to_string()),
                exhausted_resets_at: Some("2026-07-18T00:00:00Z".to_string()),
                ..CredentialStatusRecord::default()
            },
        );
        let mut app_config = AppConfig::default();
        app_config.backup.enabled = true;
        app_config.backup.remotes = vec![BackupRemoteConfig {
            name: "main".to_string(),
            endpoint: "https://s3.example.com".to_string(),
            bucket: "token-refresh".to_string(),
            access_key_id: "access".to_string(),
            secret_access_key: "secret".to_string(),
            ..BackupRemoteConfig::default()
        }];
        let cpa_config = CpaConfig {
            enabled: true,
            base_url: "http://old-cpa:8317".to_string(),
            management_key: "old-key".to_string(),
            auto_supplement_enabled: true,
            supplement_target: 20,
            proxy_list: "socks5h://127.0.0.1:10808".to_string(),
            auto_assign_proxy_enabled: true,
            ..CpaConfig::default()
        };

        let bytes = build_migration_archive(
            MigrationArchiveInput {
                normal_files,
                abnormal_files,
                status_records,
                editable_settings: EditableSettings::from(&app_config),
                cpa_config,
            },
            Utc::now(),
            TEST_PASSWORD,
        )
        .unwrap();

        let parsed = parse_migration_archive(&bytes, TEST_PASSWORD).unwrap();
        assert_eq!(parsed.manifest.format, FORMAT);
        assert_eq!(parsed.manifest.normal_count, 1);
        assert_eq!(parsed.manifest.abnormal_count, 1);
        assert!(parsed.manifest.cpa_sanitized);
        assert!(parsed.normal_files.contains_key("user@example.com.json"));
        assert!(parsed.abnormal_files.contains_key("bad@example.com.json"));
        let status = parsed.status_records.get("user@example.com.json").unwrap();
        assert_eq!(status.cpa_exhausted, Some(true));
        assert_eq!(parsed.editable_settings.backup.remotes.len(), 1);
        assert!(!parsed.cpa_config.enabled);
        assert!(parsed.cpa_config.base_url.is_empty());
        assert!(parsed.cpa_config.management_key.is_empty());
        assert!(parsed.cpa_config.auto_supplement_enabled);
        assert!(parsed.cpa_config.auto_assign_proxy_enabled);
    }

    #[test]
    fn migration_archive_rejects_wrong_password() {
        let bytes = build_migration_archive(
            MigrationArchiveInput {
                normal_files: BTreeMap::from([(
                    "user.json".to_string(),
                    credential_bytes("refresh"),
                )]),
                abnormal_files: BTreeMap::new(),
                status_records: BTreeMap::new(),
                editable_settings: EditableSettings::from(&AppConfig::default()),
                cpa_config: CpaConfig::default(),
            },
            Utc::now(),
            TEST_PASSWORD,
        )
        .unwrap();

        let error = parse_migration_archive(&bytes, "wrong-password").unwrap_err();

        assert!(is_invalid_migration_password(&error));
    }

    #[test]
    fn migration_archive_rejects_parent_directory_entry() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "credentials/normal/../bad.json",
                SimpleFileOptions::default()
                    .compression_method(CompressionMethod::Deflated)
                    .with_aes_encryption(AesMode::Aes256, TEST_PASSWORD),
            )
            .unwrap();
        writer.write_all(&credential_bytes("refresh")).unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let error = parse_migration_archive(&bytes, TEST_PASSWORD).unwrap_err();

        assert!(error.to_string().contains("parent directory"));
    }

    #[test]
    fn migration_archive_rejects_unencrypted_entries() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "credentials/normal/user.json",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&credential_bytes("refresh")).unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let error = parse_migration_archive(&bytes, TEST_PASSWORD).unwrap_err();

        assert!(error.to_string().contains("not encrypted"));
    }

    fn credential_bytes(refresh_token: &str) -> Vec<u8> {
        serde_json::to_vec(&CodexCredentialFile {
            provider_type: "codex".to_string(),
            refresh_token: refresh_token.to_string(),
            ..CodexCredentialFile::default()
        })
        .unwrap()
    }
}
