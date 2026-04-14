use std::collections::BTreeSet;
use std::io::Write;

use anyhow::{Result, bail};
use zip::CompressionMethod;
use zip::write::FileOptions;

use crate::credential_store::{CredentialStore, CredentialZone, normalize_key};

pub fn build_credential_archive(store: &CredentialStore, zone: &str) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    if zone == "all" {
        add_zone(
            &mut writer,
            store,
            CredentialZone::Normal,
            "normal/",
            options,
        )?;
        add_zone(
            &mut writer,
            store,
            CredentialZone::Abnormal,
            "abnormal/",
            options,
        )?;
    } else {
        let zone = CredentialZone::parse(zone)?;
        add_zone(&mut writer, store, zone, "", options)?;
    }
    let cursor = writer.finish()?;
    Ok(cursor.into_inner())
}

pub fn build_selected_credential_archive(
    store: &CredentialStore,
    zone: &str,
    names: &[String],
) -> Result<Vec<u8>> {
    let zone = CredentialZone::parse(zone)?;
    let selected = normalize_selected_names(names);
    if selected.is_empty() {
        bail!("credential names cannot be empty");
    }

    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    add_selected_entries(&mut writer, store, zone, &selected, options)?;
    let cursor = writer.finish()?;
    Ok(cursor.into_inner())
}

fn add_zone(
    writer: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    store: &CredentialStore,
    zone: CredentialZone,
    prefix: &str,
    options: FileOptions,
) -> Result<()> {
    for entry in store.scan_zone(zone)? {
        let bytes = store.read_bytes(zone, &entry.key)?;
        writer.start_file(format!("{prefix}{}", entry.key), options)?;
        writer.write_all(&bytes)?;
    }
    Ok(())
}

fn add_selected_entries(
    writer: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    store: &CredentialStore,
    zone: CredentialZone,
    names: &[String],
    options: FileOptions,
) -> Result<()> {
    for name in names {
        let bytes = store.read_bytes(zone, name)?;
        writer.start_file(name, options)?;
        writer.write_all(&bytes)?;
    }
    Ok(())
}

fn normalize_selected_names(names: &[String]) -> Vec<String> {
    let mut unique = BTreeSet::new();
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            continue;
        }
        unique.insert(normalize_key(trimmed));
    }
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::credential::CodexCredentialFile;

    #[test]
    fn all_archive_contains_normal_and_abnormal_directories() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("user@example.com".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user@example.com.json", &credential)
            .unwrap();
        store
            .write_credential(
                CredentialZone::Abnormal,
                "user2@example.com.json",
                &credential,
            )
            .unwrap();
        let bytes = build_credential_archive(&store, "all").unwrap();
        let cursor = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let mut names = Vec::new();
        for index in 0..archive.len() {
            names.push(archive.by_index(index).unwrap().name().to_string());
        }
        assert!(names.contains(&"normal/user@example.com.json".to_string()));
        assert!(names.contains(&"abnormal/user2@example.com.json".to_string()));
    }

    #[test]
    fn archive_preserves_relative_paths() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("user@example.com".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(
                CredentialZone::Normal,
                "nested/user@example.com.json",
                &credential,
            )
            .unwrap();
        let bytes = build_credential_archive(&store, "normal").unwrap();
        let cursor = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let mut names = Vec::new();
        for index in 0..archive.len() {
            names.push(archive.by_index(index).unwrap().name().to_string());
        }
        assert!(names.contains(&"nested/user@example.com.json".to_string()));
    }

    #[test]
    fn selected_archive_contains_only_selected_files() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();
        let credential = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("user@example.com".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(
                CredentialZone::Normal,
                "nested/user@example.com.json",
                &credential,
            )
            .unwrap();
        store
            .write_credential(
                CredentialZone::Normal,
                "other@example.com.json",
                &credential,
            )
            .unwrap();

        let bytes = build_selected_credential_archive(
            &store,
            "normal",
            &["nested/user@example.com.json".to_string()],
        )
        .unwrap();
        let cursor = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let mut names = Vec::new();
        for index in 0..archive.len() {
            names.push(archive.by_index(index).unwrap().name().to_string());
        }

        assert_eq!(names, vec!["nested/user@example.com.json".to_string()]);
    }

    #[test]
    fn selected_archive_rejects_empty_names() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        assert!(build_selected_credential_archive(&store, "normal", &[]).is_err());
    }
}
