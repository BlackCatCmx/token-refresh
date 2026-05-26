use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use reqwest::Url;

use crate::config::ProxyConfig;

const SOCKS5_SCHEME: &str = "socks5";
const SOCKS5H_SCHEME: &str = "socks5h";

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
        match index.and_then(|value| proxies.get(value)) {
            Some(proxy) => Ok(Some(to_remote_dns_proxy(proxy)?)),
            None => Ok(None),
        }
    }
}

pub fn validate_proxy_list(list: &str) -> Result<Vec<String>> {
    let mut proxies = Vec::new();
    for line in list.lines().map(str::trim).filter(|line| !line.is_empty()) {
        proxies.push(to_remote_dns_proxy(line)?);
    }
    Ok(proxies)
}

pub fn to_remote_dns_proxy(proxy: &str) -> Result<String> {
    proxy_with_scheme(proxy, SOCKS5H_SCHEME)
}

pub fn to_local_dns_proxy(proxy: &str) -> Result<String> {
    proxy_with_scheme(proxy, SOCKS5_SCHEME)
}

fn proxy_with_scheme(proxy: &str, scheme: &str) -> Result<String> {
    let url = parse_proxy_url(proxy)?;
    if url.scheme() == scheme {
        return Ok(proxy.to_string());
    }
    let delimiter = proxy
        .find("://")
        .expect("validated proxy URL contains scheme delimiter");
    Ok(format!("{scheme}://{}", &proxy[(delimiter + 3)..]))
}

fn parse_proxy_url(proxy: &str) -> Result<Url> {
    let url = Url::parse(proxy).with_context(|| format!("invalid proxy entry: {proxy}"))?;
    if !matches!(url.scheme(), SOCKS5_SCHEME | SOCKS5H_SCHEME) {
        bail!("proxy must use socks5 or socks5h scheme: {proxy}");
    }
    if url.host_str().is_none() || url.port().is_none() {
        bail!("proxy must include host and port: {proxy}");
    }
    Ok(url)
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
            Some("socks5h://127.0.0.1:10808".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5h://127.0.0.1:10808".to_string())
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
            Some("socks5h://127.0.0.1:10808".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5h://127.0.0.1:10809".to_string())
        );
        assert_eq!(
            selector.select_proxy(&config).unwrap(),
            Some("socks5h://127.0.0.1:10808".to_string())
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

    #[test]
    fn validate_proxy_list_prefers_socks5h_for_socks5_input() {
        assert_eq!(
            validate_proxy_list("socks5://user:pass@127.0.0.1:10808").unwrap(),
            vec!["socks5h://user:pass@127.0.0.1:10808".to_string()]
        );
    }

    #[test]
    fn validate_proxy_list_accepts_socks5h_input() {
        assert_eq!(
            validate_proxy_list("socks5h://127.0.0.1:10808").unwrap(),
            vec!["socks5h://127.0.0.1:10808".to_string()]
        );
    }

    #[test]
    fn to_local_dns_proxy_uses_socks5_scheme() {
        assert_eq!(
            to_local_dns_proxy("socks5h://127.0.0.1:10808").unwrap(),
            "socks5://127.0.0.1:10808"
        );
    }

    #[test]
    fn to_remote_dns_proxy_uses_socks5h_scheme() {
        assert_eq!(
            to_remote_dns_proxy("socks5://127.0.0.1:10808").unwrap(),
            "socks5h://127.0.0.1:10808"
        );
    }
}
