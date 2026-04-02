use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use zip::ZipArchive;

use crate::credential::CodexCredentialFile;
use crate::credential_store::{CredentialStore, CredentialZone};

#[derive(Clone, Debug)]
pub struct ImportedFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub zone: CredentialZone,
}

pub fn import_json_files(store: &CredentialStore, files: Vec<ImportedFile>) -> Result<Vec<String>> {
    let mut imported = Vec::new();
    for file in files {
        let credential: CodexCredentialFile = serde_json::from_slice(&file.bytes)
            .with_context(|| format!("invalid JSON credential: {}", file.name))?;
        if !credential.is_codex() {
            bail!("only type=codex credentials are supported: {}", file.name);
        }
        imported.push(store.import_credential(file.zone, &file.name, &credential)?);
    }
    Ok(imported)
}

pub fn import_zip(store: &CredentialStore, bytes: &[u8]) -> Result<Vec<String>> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("invalid ZIP archive")?;
    let mut files = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .context("failed to read ZIP entry")?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().replace('\\', "/");
        if !name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        let zone = if name.starts_with("abnormal/") {
            CredentialZone::Abnormal
        } else {
            CredentialZone::Normal
        };
        let normalized_name = if let Some(stripped) = name.strip_prefix("normal/") {
            stripped.to_string()
        } else if let Some(stripped) = name.strip_prefix("abnormal/") {
            stripped.to_string()
        } else {
            name
        };
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .with_context(|| format!("failed to read ZIP entry {}", file.name()))?;
        files.push(ImportedFile {
            name: normalized_name,
            bytes: content,
            zone,
        });
    }
    import_json_files(store, files)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::config::AppConfig;

    #[test]
    fn zip_import_respects_abnormal_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let credential = serde_json::json!({
            "id_token": "",
            "access_token": "access",
            "refresh_token": "refresh",
            "email": "user@example.com",
            "type": "codex"
        })
        .to_string();

        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer
                .start_file("abnormal/user@example.com.json", options)
                .unwrap();
            writer.write_all(credential.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        let imported = import_zip(&store, cursor.get_ref()).unwrap();
        assert_eq!(imported, vec!["user@example.com.json".to_string()]);
        assert!(
            config
                .abnormal_credentials_dir
                .join("user@example.com.json")
                .exists()
        );
    }
}
