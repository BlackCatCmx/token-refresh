use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use zip::ZipArchive;

use crate::config::RequestIdentityConfig;
use crate::credential::CodexCredentialFile;
use crate::credential_store::{CredentialStore, CredentialZone};
use crate::user_agent;

#[derive(Clone, Debug)]
pub struct ImportedFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub zone: CredentialZone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserAgentPatchMode {
    FillMissing,
    ReassignCliVersion,
    ForceReassign,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserAgentPatchSummary {
    pub updated: usize,
    pub unchanged: usize,
    pub skipped_invalid: usize,
}

pub fn import_json_files(
    store: &CredentialStore,
    files: Vec<ImportedFile>,
    request_identity: &RequestIdentityConfig,
) -> Result<Vec<String>> {
    let mut imported = Vec::new();
    for file in files {
        let mut credential: CodexCredentialFile = serde_json::from_slice(&file.bytes)
            .with_context(|| format!("invalid JSON credential: {}", file.name))?;
        if !credential.is_codex() {
            bail!("only type=codex credentials are supported: {}", file.name);
        }
        ensure_user_agent(&mut credential, request_identity)?;
        imported.push(store.import_credential(file.zone, &file.name, &credential)?);
    }
    Ok(imported)
}

pub fn import_zip(
    store: &CredentialStore,
    bytes: &[u8],
    request_identity: &RequestIdentityConfig,
) -> Result<Vec<String>> {
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
    import_json_files(store, files, request_identity)
}

fn ensure_user_agent(
    credential: &mut CodexCredentialFile,
    request_identity: &RequestIdentityConfig,
) -> Result<()> {
    credential.user_agent = match user_agent::normalize_optional(credential.user_agent.as_deref())?
    {
        Some(value) => Some(value),
        None => Some(user_agent::assign(
            &request_identity.originator,
            &request_identity.user_agent_mode,
            &request_identity.user_agent,
            &request_identity.user_agent_rules,
        )?),
    };
    Ok(())
}

pub fn patch_user_agents(
    store: &CredentialStore,
    request_identity: &RequestIdentityConfig,
    mode: UserAgentPatchMode,
) -> Result<UserAgentPatchSummary> {
    let mut summary = UserAgentPatchSummary::default();
    for entry in store.scan_all()? {
        let Some(mut credential) = entry.credential else {
            summary.skipped_invalid += 1;
            continue;
        };
        let next_user_agent = match mode {
            UserAgentPatchMode::FillMissing => {
                if credential.normalized_user_agent().is_some() {
                    summary.unchanged += 1;
                    continue;
                }
                user_agent::assign(
                    &request_identity.originator,
                    &request_identity.user_agent_mode,
                    &request_identity.user_agent,
                    &request_identity.user_agent_rules,
                )?
            }
            UserAgentPatchMode::ReassignCliVersion => {
                let Some(current_user_agent) = credential.normalized_user_agent() else {
                    summary.unchanged += 1;
                    continue;
                };
                let Some(updated_user_agent) = user_agent::reassign_cli_version(
                    current_user_agent,
                    &request_identity.originator,
                    &request_identity.user_agent_rules,
                )?
                else {
                    summary.unchanged += 1;
                    continue;
                };
                // Avoid a no-op write if the random version pick matched the current UA.
                if updated_user_agent == current_user_agent {
                    summary.unchanged += 1;
                    continue;
                }
                updated_user_agent
            }
            UserAgentPatchMode::ForceReassign => user_agent::assign(
                &request_identity.originator,
                &request_identity.user_agent_mode,
                &request_identity.user_agent,
                &request_identity.user_agent_rules,
            )?,
        };
        credential.user_agent = Some(next_user_agent);
        store.write_credential(entry.zone, &entry.key, &credential)?;
        summary.updated += 1;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::config::{AppConfig, RequestIdentityConfig};

    fn request_identity_with_list(user_agent: &str) -> RequestIdentityConfig {
        RequestIdentityConfig {
            user_agent: user_agent.to_string(),
            ..RequestIdentityConfig::default()
        }
    }

    fn generated_request_identity() -> RequestIdentityConfig {
        RequestIdentityConfig {
            user_agent_mode: "generated".to_string(),
            user_agent_rules: crate::user_agent::UserAgentRulesConfig {
                versions: "0.118.0".to_string(),
                profiles: "windows10".to_string(),
                terminals: "WindowsTerminal".to_string(),
            },
            ..RequestIdentityConfig::default()
        }
    }

    fn request_identity_with_version(version: &str) -> RequestIdentityConfig {
        RequestIdentityConfig {
            user_agent_rules: crate::user_agent::UserAgentRulesConfig {
                versions: version.to_string(),
                ..crate::user_agent::UserAgentRulesConfig::default()
            },
            ..RequestIdentityConfig::default()
        }
    }

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
        let imported = import_zip(
            &store,
            cursor.get_ref(),
            &request_identity_with_list(crate::user_agent::DEFAULT_USER_AGENT),
        )
        .unwrap();
        assert_eq!(imported, vec!["user@example.com.json".to_string()]);
        assert!(
            config
                .abnormal_credentials_dir
                .join("user@example.com.json")
                .exists()
        );
    }

    #[test]
    fn json_import_assigns_default_user_agent_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let files = vec![ImportedFile {
            name: "user@example.com.json".to_string(),
            bytes: serde_json::json!({
                "id_token": "",
                "access_token": "access",
                "refresh_token": "refresh",
                "email": "user@example.com",
                "type": "codex"
            })
            .to_string()
            .into_bytes(),
            zone: CredentialZone::Normal,
        }];

        import_json_files(&store, files, &request_identity_with_list("")).unwrap();
        let entry = store
            .read_entry(CredentialZone::Normal, "user@example.com.json")
            .unwrap();
        assert_eq!(
            entry
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some(crate::user_agent::DEFAULT_USER_AGENT)
        );
    }

    #[test]
    fn json_import_preserves_explicit_user_agent() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let files = vec![ImportedFile {
            name: "user@example.com.json".to_string(),
            bytes: serde_json::json!({
                "id_token": "",
                "access_token": "access",
                "refresh_token": "refresh",
                "email": "user@example.com",
                "type": "codex",
                "user-agent": "custom-ua"
            })
            .to_string()
            .into_bytes(),
            zone: CredentialZone::Normal,
        }];

        import_json_files(&store, files, &request_identity_with_list("pool-ua")).unwrap();
        let entry = store
            .read_entry(CredentialZone::Normal, "user@example.com.json")
            .unwrap();
        assert_eq!(
            entry
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("custom-ua")
        );
    }

    #[test]
    fn fill_missing_user_agents_only_updates_missing_entries() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let missing = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("missing@example.com".to_string()),
            ..CodexCredentialFile::default()
        };
        let existing = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("existing@example.com".to_string()),
            user_agent: Some("keep-me".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "missing.json", &missing)
            .unwrap();
        store
            .write_credential(CredentialZone::Abnormal, "existing.json", &existing)
            .unwrap();

        let summary = patch_user_agents(
            &store,
            &request_identity_with_list("ua-pool"),
            UserAgentPatchMode::FillMissing,
        )
        .unwrap();
        assert_eq!(
            summary,
            UserAgentPatchSummary {
                updated: 1,
                unchanged: 1,
                skipped_invalid: 0,
            }
        );
        assert_eq!(
            store
                .read_entry(CredentialZone::Normal, "missing.json")
                .unwrap()
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("ua-pool")
        );
        assert_eq!(
            store
                .read_entry(CredentialZone::Abnormal, "existing.json")
                .unwrap()
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("keep-me")
        );
    }

    #[test]
    fn force_reassign_user_agents_overwrites_existing_entries() {
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
            user_agent: Some("old-ua".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "user.json", &credential)
            .unwrap();

        let summary = patch_user_agents(
            &store,
            &request_identity_with_list("new-ua"),
            UserAgentPatchMode::ForceReassign,
        )
        .unwrap();
        assert_eq!(
            summary,
            UserAgentPatchSummary {
                updated: 1,
                unchanged: 0,
                skipped_invalid: 0,
            }
        );
        assert_eq!(
            store
                .read_entry(CredentialZone::Normal, "user.json")
                .unwrap()
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("new-ua")
        );
    }

    #[test]
    fn reassign_cli_version_only_updates_matching_user_agents() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let matching = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("matching@example.com".to_string()),
            user_agent: Some(
                "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal".to_string(),
            ),
            ..CodexCredentialFile::default()
        };
        let custom = CodexCredentialFile {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            provider_type: "codex".to_string(),
            email: Some("custom@example.com".to_string()),
            user_agent: Some("custom-ua".to_string()),
            ..CodexCredentialFile::default()
        };
        store
            .write_credential(CredentialZone::Normal, "matching.json", &matching)
            .unwrap();
        store
            .write_credential(CredentialZone::Abnormal, "custom.json", &custom)
            .unwrap();

        let summary = patch_user_agents(
            &store,
            &request_identity_with_version("9.9.9"),
            UserAgentPatchMode::ReassignCliVersion,
        )
        .unwrap();
        assert_eq!(
            summary,
            UserAgentPatchSummary {
                updated: 1,
                unchanged: 1,
                skipped_invalid: 0,
            }
        );
        assert_eq!(
            store
                .read_entry(CredentialZone::Normal, "matching.json")
                .unwrap()
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("codex_cli_rs/9.9.9 (Windows 10.0.19045; x86_64) WindowsTerminal")
        );
        assert_eq!(
            store
                .read_entry(CredentialZone::Abnormal, "custom.json")
                .unwrap()
                .credential
                .as_ref()
                .and_then(|credential| credential.user_agent.as_deref()),
            Some("custom-ua")
        );
    }

    #[test]
    fn generated_mode_assigns_compliant_user_agent() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.credentials_dir = temp.path().join("credentials");
        config.abnormal_credentials_dir = temp.path().join("credentials_abnormal");
        let store = CredentialStore::new(&config, None).unwrap();

        let files = vec![ImportedFile {
            name: "user@example.com.json".to_string(),
            bytes: serde_json::json!({
                "id_token": "",
                "access_token": "access",
                "refresh_token": "refresh",
                "email": "user@example.com",
                "type": "codex"
            })
            .to_string()
            .into_bytes(),
            zone: CredentialZone::Normal,
        }];

        import_json_files(&store, files, &generated_request_identity()).unwrap();
        let user_agent = store
            .read_entry(CredentialZone::Normal, "user@example.com.json")
            .unwrap()
            .credential
            .as_ref()
            .and_then(|credential| credential.user_agent.as_deref())
            .unwrap()
            .to_string();
        assert!(matches!(
            user_agent.as_str(),
            "codex_cli_rs/0.118.0 (Windows 10.0.19044; x86_64) WindowsTerminal"
                | "codex_cli_rs/0.118.0 (Windows 10.0.19045; x86_64) WindowsTerminal"
        ));
    }
}
