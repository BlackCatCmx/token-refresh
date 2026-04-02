use std::io::Write;

use anyhow::{Result, bail};
use zip::CompressionMethod;
use zip::write::FileOptions;

use crate::credential_store::{CredentialStore, CredentialZone};

pub fn build_credential_archive(store: &CredentialStore, zone: &str) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    match zone {
        "normal" => add_zone(&mut writer, store, CredentialZone::Normal, "", options)?,
        "abnormal" => add_zone(&mut writer, store, CredentialZone::Abnormal, "", options)?,
        "all" => {
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
        }
        other => bail!("unsupported archive zone: {other}"),
    }
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
        writer.start_file(format!("{prefix}{}", entry.file_name()), options)?;
        writer.write_all(&bytes)?;
    }
    Ok(())
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
        let store = CredentialStore::new(&config).unwrap();
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
}
