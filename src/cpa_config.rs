use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::fsutil;

const DEFAULT_INSPECT_INTERVAL_MINUTES: u64 = 60;
const DEFAULT_SUPPLEMENT_TARGET: usize = 50;
const DEFAULT_SAFETY_ABORT_RATIO_PERCENT: u8 = 50;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CpaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub management_key: String,
    #[serde(default = "default_inspect_interval_minutes")]
    pub inspect_interval_minutes: u64,
    #[serde(default)]
    pub auto_supplement_enabled: bool,
    #[serde(default = "default_supplement_target")]
    pub supplement_target: usize,
    #[serde(default)]
    pub auto_assign_proxy_enabled: bool,
    #[serde(default)]
    pub proxy_list: String,
    #[serde(default = "default_safety_abort_enabled")]
    pub safety_abort_enabled: bool,
    #[serde(default = "default_safety_abort_ratio_percent")]
    pub safety_abort_ratio_percent: u8,
}

impl Default for CpaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            management_key: String::new(),
            inspect_interval_minutes: default_inspect_interval_minutes(),
            auto_supplement_enabled: false,
            supplement_target: default_supplement_target(),
            auto_assign_proxy_enabled: false,
            proxy_list: String::new(),
            safety_abort_enabled: default_safety_abort_enabled(),
            safety_abort_ratio_percent: default_safety_abort_ratio_percent(),
        }
    }
}

impl CpaConfig {
    pub fn normalized(mut self) -> Self {
        self.base_url = self.base_url.trim().trim_end_matches('/').to_string();
        self.management_key = strip_bearer_prefix(&self.management_key);
        self.proxy_list = normalize_cpa_proxy_list_text(&self.proxy_list);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.inspect_interval_minutes == 0 {
            bail!("CPA 巡查间隔必须大于 0 分钟");
        }
        if self.supplement_target == 0 && self.auto_supplement_enabled {
            bail!("开启自动补号时，目标数量必须大于 0");
        }
        if self.safety_abort_ratio_percent == 0 || self.safety_abort_ratio_percent > 100 {
            bail!("异常占比保护阈值必须在 1 到 100 之间");
        }
        validate_cpa_proxy_list(&self.proxy_list)?;
        if self.enabled {
            if self.base_url.trim().is_empty() {
                bail!("开启 CPA 自动巡查时，Base URL 不能为空");
            }
            if self.management_key.trim().is_empty() {
                bail!("开启 CPA 自动巡查时，管理 Key 不能为空");
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CpaConfigStore {
    path: PathBuf,
    config: Mutex<CpaConfig>,
}

impl CpaConfigStore {
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("cpa_config.json");
        let config = match fsutil::read_file_if_exists(&path)? {
            Some(raw) if raw.is_empty() => CpaConfig::default(),
            Some(raw) => serde_json::from_slice::<CpaConfig>(&raw)
                .with_context(|| format!("invalid CPA config file {}", path.display()))?,
            None => CpaConfig::default(),
        }
        .normalized();
        config.validate()?;
        Ok(Self {
            path,
            config: Mutex::new(config),
        })
    }

    pub fn get(&self) -> CpaConfig {
        self.config
            .lock()
            .map(|guard| guard.clone())
            .expect("CPA config store lock poisoned")
    }

    pub fn set(&self, config: CpaConfig) -> Result<()> {
        let config = config.normalized();
        config.validate()?;
        let mut guard = self
            .config
            .lock()
            .map_err(|_| anyhow::anyhow!("CPA config store lock poisoned"))?;
        fsutil::atomic_write_json(&self.path, &config)?;
        *guard = config;
        Ok(())
    }
}

fn default_inspect_interval_minutes() -> u64 {
    DEFAULT_INSPECT_INTERVAL_MINUTES
}

fn default_supplement_target() -> usize {
    DEFAULT_SUPPLEMENT_TARGET
}

fn default_safety_abort_enabled() -> bool {
    true
}

fn default_safety_abort_ratio_percent() -> u8 {
    DEFAULT_SAFETY_ABORT_RATIO_PERCENT
}

fn normalize_cpa_proxy_list_text(list: &str) -> String {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn validate_cpa_proxy_list(list: &str) -> Result<Vec<String>> {
    let mut proxies = Vec::new();
    for proxy in list.lines().map(str::trim).filter(|line| !line.is_empty()) {
        validate_cpa_proxy_url(proxy)?;
        proxies.push(proxy.to_string());
    }
    Ok(proxies)
}

fn validate_cpa_proxy_url(proxy: &str) -> Result<()> {
    let url = Url::parse(proxy).with_context(|| format!("invalid CPA proxy entry: {proxy}"))?;
    match url.scheme() {
        "http" | "https" => {}
        "socks5" | "socks5h" => {
            if url.port().is_none() {
                bail!("CPA socks proxy must include port: {proxy}");
            }
        }
        _ => bail!("CPA proxy must use http, https, socks5 or socks5h scheme: {proxy}"),
    }
    if url.host_str().is_none() {
        bail!("CPA proxy must include host: {proxy}");
    }
    Ok(())
}

pub fn strip_bearer_prefix(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        trimmed[7..].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_bearer_prefix() {
        assert_eq!(strip_bearer_prefix("Bearer secret"), "secret");
        assert_eq!(strip_bearer_prefix("bearer secret "), "secret");
        assert_eq!(strip_bearer_prefix("secret"), "secret");
    }

    #[test]
    fn rejects_enabled_config_without_key() {
        let config = CpaConfig {
            enabled: true,
            base_url: "http://localhost:8317".to_string(),
            management_key: String::new(),
            ..CpaConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn default_config_disables_proxy_assignment() {
        let config = CpaConfig::default();

        assert!(!config.auto_assign_proxy_enabled);
        assert!(config.proxy_list.is_empty());
    }

    #[test]
    fn loads_legacy_config_without_proxy_fields() {
        let temp = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "enabled": false,
            "base_url": " http://localhost:8317/ ",
            "management_key": "",
            "inspect_interval_minutes": 60,
            "auto_supplement_enabled": false,
            "supplement_target": 50,
            "safety_abort_enabled": true,
            "safety_abort_ratio_percent": 50
        });
        std::fs::write(
            temp.path().join("cpa_config.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();

        let store = CpaConfigStore::load(temp.path()).unwrap();
        let config = store.get();

        assert!(!config.auto_assign_proxy_enabled);
        assert!(config.proxy_list.is_empty());
        assert_eq!(config.base_url, "http://localhost:8317");
    }

    #[test]
    fn saves_and_loads_proxy_assignment_config() {
        let temp = tempfile::tempdir().unwrap();
        let store = CpaConfigStore::load(temp.path()).unwrap();

        store
            .set(CpaConfig {
                auto_assign_proxy_enabled: true,
                proxy_list: " socks5h://127.0.0.1:10808 \n\nhttps://proxy.example.com".to_string(),
                ..CpaConfig::default()
            })
            .unwrap();

        let loaded = CpaConfigStore::load(temp.path()).unwrap().get();
        assert!(loaded.auto_assign_proxy_enabled);
        assert_eq!(
            loaded.proxy_list,
            "socks5h://127.0.0.1:10808\nhttps://proxy.example.com"
        );
    }

    #[test]
    fn rejects_invalid_cpa_proxy_url() {
        let config = CpaConfig {
            proxy_list: "ftp://proxy.example.com:21".to_string(),
            ..CpaConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn allows_empty_cpa_proxy_list() {
        let config = CpaConfig {
            auto_assign_proxy_enabled: true,
            proxy_list: String::new(),
            ..CpaConfig::default()
        };

        assert!(config.validate().is_ok());
        assert!(validate_cpa_proxy_list("").unwrap().is_empty());
    }

    #[test]
    fn set_does_not_mutate_memory_when_persist_fails() {
        let temp = tempfile::tempdir().unwrap();
        let blocker = temp.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();

        let store = CpaConfigStore {
            path: blocker.join("cpa_config.json"),
            config: Mutex::new(CpaConfig {
                base_url: "http://old.example".to_string(),
                ..CpaConfig::default()
            }),
        };
        let next = CpaConfig {
            base_url: "http://new.example".to_string(),
            ..CpaConfig::default()
        };

        assert!(store.set(next).is_err());
        assert_eq!(store.get().base_url, "http://old.example");
    }
}
