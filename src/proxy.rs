use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use reqwest::Url;

use crate::config::ProxyConfig;

#[derive(Debug)]
pub struct ProxySelector {
    next_index: Mutex<usize>,
}

impl Default for ProxySelector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxySelector {
    pub fn new() -> Self {
        Self {
            next_index: Mutex::new(0),
        }
    }

    pub fn select_proxy(&self, config: &ProxyConfig) -> Result<Option<String>> {
        let proxies = validate_proxy_list(&config.list)?;
        self.select_proxy_from_list(config.mode.trim(), &proxies)
    }

    pub fn reserve_proxy_index_from_list(
        &self,
        mode: &str,
        proxies: &[String],
    ) -> Result<Option<usize>> {
        if proxies.is_empty() {
            return Ok(None);
        }
        match mode {
            "fixed" => Ok(Some(0)),
            "round_robin" => {
                let mut guard = self
                    .next_index
                    .lock()
                    .map_err(|_| anyhow::anyhow!("proxy selector lock poisoned"))?;
                let index = *guard % proxies.len();
                *guard = (*guard + 1) % proxies.len();
                Ok(Some(index))
            }
            other => bail!("unsupported proxy mode: {other}"),
        }
    }

    pub fn select_proxy_from_list(&self, mode: &str, proxies: &[String]) -> Result<Option<String>> {
        let index = self.reserve_proxy_index_from_list(mode, proxies)?;
        Ok(index.and_then(|value| proxies.get(value).cloned()))
    }
}

pub fn validate_proxy_list(list: &str) -> Result<Vec<String>> {
    let mut proxies = Vec::new();
    for line in list.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let url = Url::parse(line).with_context(|| format!("invalid proxy entry: {line}"))?;
        if url.scheme() != "socks5" {
            bail!("proxy must use socks5 scheme: {line}");
        }
        if url.host_str().is_none() || url.port().is_none() {
            bail!("proxy must include host and port: {line}");
        }
        proxies.push(line.to_string());
    }
    Ok(proxies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;

    #[test]
    fn fixed_proxy_uses_first_entry() {
        let selector = ProxySelector::new();
        let config = ProxyConfig {
            mode: "fixed".to_string(),
            list: "socks5://127.0.0.1:10808\nsocks5://127.0.0.1:10809".to_string(),
            backup_list: String::new(),
        };
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5://127.0.0.1:10808".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5://127.0.0.1:10808".to_string())
        );
    }

    #[test]
    fn round_robin_cycles_through_entries() {
        let selector = ProxySelector::new();
        let config = ProxyConfig {
            mode: "round_robin".to_string(),
            list: "socks5://127.0.0.1:10808\nsocks5://127.0.0.1:10809".to_string(),
            backup_list: String::new(),
        };
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5://127.0.0.1:10808".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5://127.0.0.1:10809".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5://127.0.0.1:10808".to_string())
        );
    }

    #[test]
    fn reserve_proxy_index_cycles_through_entries() {
        let selector = ProxySelector::new();
        let proxies = vec![
            "socks5://127.0.0.1:10808".to_string(),
            "socks5://127.0.0.1:10809".to_string(),
        ];
        assert_eq!(
            selector
                .reserve_proxy_index_from_list("round_robin", &proxies)
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            selector
                .reserve_proxy_index_from_list("round_robin", &proxies)
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            selector
                .reserve_proxy_index_from_list("round_robin", &proxies)
                .unwrap(),
            Some(0)
        );
    }
}
